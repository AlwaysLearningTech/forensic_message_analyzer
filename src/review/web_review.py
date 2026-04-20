"""
Flask-based web review interface for forensic message analysis.

Provides a browser-based UI for reviewing flagged messages with context,
screenshots, and decision tracking. All decisions maintain forensic integrity
via ManualReviewManager and ForensicRecorder.
"""

import json
import os
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import pandas as pd
import pytz

from ..config import Config
from .manual_review_manager import ManualReviewManager
from ..utils.conversation_threading import ConversationThreader

try:
    from flask import Flask, jsonify, request, send_from_directory
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

logger = logging.getLogger(__name__)


class WebReview:
    """
    Web-based review interface for flagged forensic evidence.

    Wraps a Flask application that serves a single-page review interface.
    All review decisions are persisted through ManualReviewManager and
    logged through ForensicRecorder for chain of custody.
    """

    def __init__(self, review_manager: ManualReviewManager, forensic_recorder=None, config=None):
        """
        Initialize web review.

        Args:
            review_manager: ManualReviewManager instance for persisting decisions.
            forensic_recorder: Optional ForensicRecorder for chain of custody logging.
            config: Config instance. If None, creates a new one.
        """
        if not FLASK_AVAILABLE:
            raise ImportError(
                "Flask is required for web review. Install with: pip install Flask>=3.0.0"
            )

        self.config = config if config is not None else Config()
        self.review_manager = review_manager
        self.forensic = forensic_recorder
        self.threader = ConversationThreader()
        self._tz = pytz.timezone(self.config.timezone)
        self.messages: List[Dict] = []
        self.flagged_items: List[Dict] = []
        self.screenshots: List[Dict] = []
        self.reviewed_indices: set = set()
        self._shutdown_event = threading.Event()
        # Tracks how the session ended so the pipeline runner can tell Complete from Pause. Complete marks the phase done; Pause leaves review_complete=False so --resume picks up where the reviewer stopped.
        self.was_paused = False
        self._conversation_cache = None

        # EventManager shares the review session so manual events persist alongside review decisions.
        from .event_manager import EventManager
        self.event_manager = EventManager(
            session_id=getattr(review_manager, "session_id", None),
            config=self.config,
            forensic_recorder=forensic_recorder,
        )

        # Build Flask app. Harden cookies defensively even though the server binds to localhost: Strict SameSite blocks cross-site submissions, HttpOnly prevents any cookie JS access, and a per-session secret key keeps Flask from falling back to a fixed dev value.
        self.app = Flask(__name__)
        self.app.config.update(
            SECRET_KEY=os.urandom(32),
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Strict",
        )

        # Allowed base directories for attachment serving. Files requested through /attachments/... must resolve underneath one of these, in addition to appearing in the per-request allowlist built from loaded messages.
        self._attachment_bases: List[Path] = []
        for base in (
            getattr(self.config, "whatsapp_source_dir", None),
            getattr(self.config, "screenshot_source_dir", None),
            getattr(self.config, "output_dir", None),
            Path.home() / "Library" / "Messages" / "Attachments",
        ):
            if not base:
                continue
            try:
                resolved = Path(base).expanduser().resolve()
            except (ValueError, OSError):
                continue
            if resolved.is_dir():
                self._attachment_bases.append(resolved)

        self._register_routes()

    def _register_routes(self):
        """Register all Flask routes."""

        @self.app.route("/")
        def index():
            return self._render_review_page()

        @self.app.route("/api/item/<int:idx>")
        def get_item(idx):
            return jsonify(self._get_review_item(idx))

        @self.app.route("/api/decision", methods=["POST"])
        def submit_decision():
            data = request.get_json(force=True)
            return jsonify(self._submit_decision(data))

        @self.app.route("/api/progress")
        def get_progress():
            return jsonify(self._get_progress())

        @self.app.route("/api/note_suggestions")
        def note_suggestions():
            return jsonify(self._get_note_suggestions())

        @self.app.route("/api/start_index")
        def start_index():
            return jsonify({"index": self._first_unreviewed_index()})

        @self.app.route("/screenshots/<path:filename>")
        def serve_screenshot(filename):
            screenshot_dir = self.config.screenshot_source_dir
            if screenshot_dir and Path(screenshot_dir).is_dir():
                return send_from_directory(screenshot_dir, filename)
            return ("Screenshot not found", 404)

        @self.app.route("/attachments/<path:filename>")
        def serve_attachment(filename):
            """Serve message attachment files (WhatsApp photos, iMessage images, etc.).

            Defense-in-depth:
              1. The resolved path must live under one of the configured attachment base directories (never an arbitrary filesystem location, even if something in `self.messages` points there).
              2. The resolved path must also appear in the per-request allowlist built from loaded messages.
            """
            allowed_paths = self._build_attachment_allowlist()
            candidates = self._candidate_attachment_paths(filename)

            for candidate in candidates:
                resolved = self._safe_resolve_under_bases(candidate)
                if resolved is None:
                    continue
                if str(resolved) not in allowed_paths:
                    continue
                if not resolved.is_file():
                    continue
                return send_from_directory(str(resolved.parent), resolved.name)

            return ("Attachment not found", 404)

        @self.app.route("/api/conversations")
        def get_conversations():
            return jsonify(self._get_conversations())

        @self.app.route("/api/browse")
        def browse_messages():
            page = request.args.get('page', 0, type=int)
            page_size = request.args.get('page_size', 50, type=int)
            conversation = request.args.get('conversation', '')
            return jsonify(self._get_browse_page(page, page_size, conversation))

        @self.app.route("/api/browse/flag", methods=["POST"])
        def flag_from_browse():
            data = request.get_json(force=True)
            return jsonify(self._submit_browse_flag(data))

        @self.app.route("/api/search")
        def search_messages():
            q = request.args.get('q', '').strip()
            sender = request.args.get('sender', '').strip()
            date_from = request.args.get('date_from', '').strip()
            date_to = request.args.get('date_to', '').strip()
            page = request.args.get('page', 0, type=int)
            page_size = request.args.get('page_size', 50, type=int)
            return jsonify(self._search_messages(q, sender, date_from, date_to, page, page_size))

        @self.app.route("/api/events", methods=["GET"])
        def list_events():
            return jsonify({"events": [self._serialize_event(e) for e in self.event_manager.active_events()]})

        @self.app.route("/api/events", methods=["POST"])
        def add_event():
            data = request.get_json(force=True) or {}
            try:
                record = self.event_manager.add_event(
                    title=data.get("title", ""),
                    start_message_id=data.get("start_message_id", ""),
                    end_message_id=data.get("end_message_id", ""),
                    category=data.get("category", "incident"),
                    severity=data.get("severity", "medium"),
                    description=data.get("description", ""),
                    start_timestamp=self._lookup_ts(data.get("start_message_id")),
                    end_timestamp=self._lookup_ts(data.get("end_message_id")),
                )
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            return jsonify({"status": "ok", "event": self._serialize_event(record)})

        @self.app.route("/api/events/<event_id>", methods=["PUT", "PATCH"])
        def edit_event(event_id):
            data = request.get_json(force=True) or {}
            try:
                record = self.event_manager.edit_event(
                    event_id,
                    title=data.get("title"),
                    category=data.get("category"),
                    severity=data.get("severity"),
                    description=data.get("description"),
                    start_message_id=data.get("start_message_id"),
                    end_message_id=data.get("end_message_id"),
                    start_timestamp=self._lookup_ts(data.get("start_message_id")),
                    end_timestamp=self._lookup_ts(data.get("end_message_id")),
                    reason=data.get("reason", ""),
                )
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            return jsonify({"status": "ok", "event": self._serialize_event(record)})

        @self.app.route("/api/events/<event_id>", methods=["DELETE"])
        def remove_event(event_id):
            data = request.get_json(force=True, silent=True) or {}
            try:
                self.event_manager.remove_event(event_id, reason=data.get("reason", ""))
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            return jsonify({"status": "ok"})

        @self.app.route("/api/complete", methods=["POST"])
        def complete_review():
            if self.forensic:
                self.forensic.record_action(
                    "web_review_completed",
                    f"Web review session completed with {len(self.reviewed_indices)} items reviewed",
                    {"reviewed": len(self.reviewed_indices), "total": len(self.flagged_items)}
                )
            # Signal the main thread to stop waiting; Flask runs in a daemon thread and will terminate automatically when start_review returns.
            self._shutdown_event.set()
            return jsonify({"status": "ok"})

        @self.app.route("/api/pause", methods=["POST"])
        def pause_review():
            """Exit the session without flipping review_complete.

            Functionally similar to /api/complete but stamps a different audit event and sets was_paused so the pipeline runner keeps the phase resumable via --resume.
            """
            self.was_paused = True
            if self.forensic:
                self.forensic.record_action(
                    "web_review_paused",
                    f"Web review session paused with {len(self.reviewed_indices)} items reviewed this session",
                    {"reviewed": len(self.reviewed_indices), "total": len(self.flagged_items), "resumable": True}
                )
            self._shutdown_event.set()
            return jsonify({"status": "ok"})

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start_review(
        self,
        messages: List[Dict],
        flagged_items: List[Dict],
        screenshots: Optional[List[Dict]] = None,
        port: int = 5000,
    ):
        """
        Start the web review server.

        Args:
            messages: All extracted messages (for context).
            flagged_items: Items flagged for review.
            screenshots: Optional list of screenshot metadata dicts.
            port: Port to bind to (default 5000).
        """
        self.messages = messages
        self.flagged_items = flagged_items
        self.screenshots = screenshots or []

        if self.forensic:
            self.forensic.record_action(
                "web_review_started",
                f"Web review started with {len(flagged_items)} items to review",
                {
                    "total_items": len(flagged_items),
                    "total_messages": len(messages),
                    "screenshots_available": len(self.screenshots),
                    "reviewed_via": "web_interface",
                }
            )

        print(f"\n    Opening review interface at http://127.0.0.1:{port}")
        print(f"    Click 'Complete Review' to finish, 'Pause & Quit' to stop and resume later,")
        print(f"    or press Ctrl+C in this terminal.\n")

        # Run Flask in a daemon thread so that 'Complete Review' doesn't need to SIGINT the whole process (which kills the parent pipeline).
        server_thread = threading.Thread(
            target=self.app.run,
            kwargs={"host": "127.0.0.1", "port": port, "debug": False},
            daemon=True,
        )
        server_thread.start()

        # Block until the user clicks 'Complete Review' or presses Ctrl+C
        try:
            self._shutdown_event.wait()
        except KeyboardInterrupt:
            pass

    # ------------------------------------------------------------------
    # Attachment path safety
    # ------------------------------------------------------------------

    def _build_attachment_allowlist(self) -> set:
        """Resolve every attachment path referenced by loaded messages."""
        allowed = set()
        for msg in self.messages:
            att = msg.get("attachment")
            if not att:
                continue
            try:
                allowed.add(str(Path(att).resolve()))
            except (ValueError, OSError):
                pass
        return allowed

    def _candidate_attachment_paths(self, filename: str) -> List[Path]:
        """Candidate paths to try for a requested attachment filename."""
        candidates: List[Path] = []
        # iMessage uses absolute paths (URL-encoded with leading slash).
        candidates.append(Path("/") / filename)
        # Each allowed base can host a file by that relative name.
        for base in self._attachment_bases:
            candidates.append(base / filename)
        return candidates

    def _safe_resolve_under_bases(self, candidate: Path) -> Optional[Path]:
        """Resolve ``candidate`` and confirm it lives under an allowed base.

        Returns the resolved Path or None if it escapes every base.
        """
        try:
            resolved = candidate.resolve()
        except (ValueError, OSError):
            return None
        for base in self._attachment_bases:
            try:
                resolved.relative_to(base)
                return resolved
            except ValueError:
                continue
        return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_review_item(self, index: int) -> Dict:
        """Return data for the review item at *index*."""
        if index < 0 or index >= len(self.flagged_items):
            return {"error": "Index out of range", "total": len(self.flagged_items)}

        item = self.flagged_items[index]
        item_content = item.get("content", "")

        # Find the matching message in the full message list
        target_msg = None
        target_pos = None

        # Try exact content match
        for i, msg in enumerate(self.messages):
            if msg.get("content", "") == item_content:
                target_msg = msg
                target_pos = i
                break

        # Fallback: partial match (guard against empty prefix matching everything)
        if target_msg is None and item_content:
            prefix = item_content[:50]
            if prefix:
                for i, msg in enumerate(self.messages):
                    if prefix in msg.get("content", ""):
                        target_msg = msg
                        target_pos = i
                        break

        # Build context window (15 before, flagged, 15 after) so reviewers can scroll up/down for richer context while the flagged message stays centered.
        context_before = []
        context_after = []

        if target_pos is not None:
            start = max(0, target_pos - 15)
            end = min(len(self.messages), target_pos + 16)

            context_before = [
                self._serialise_msg(self.messages[i])
                for i in range(start, target_pos)
            ]
            context_after = [
                self._serialise_msg(self.messages[i])
                for i in range(target_pos + 1, end)
            ]

        # Find associated screenshots
        associated_screenshots = self._find_associated_screenshots(item, target_msg)

        # Check if already reviewed
        existing_review = None
        for r in self.review_manager.reviews:
            if r.get("item_id") == item.get("id"):
                existing_review = {
                    "decision": r["decision"],
                    "notes": r.get("notes", ""),
                    "timestamp": r.get("timestamp", ""),
                }
                break

        return {
            "index": index,
            "total": len(self.flagged_items),
            "item": {
                "id": item.get("id", f"item_{index}"),
                "type": item.get("type", "threat"),
                "source": item.get("source", "unknown"),
                "method": item.get("method", ""),
                "content": item_content,
                "categories": item.get("categories", ""),
                "confidence": item.get("confidence", 0),
                "threat_type": item.get("threat_type", ""),
                "severity": item.get("severity", ""),
            },
            "target_message": self._serialise_msg(target_msg) if target_msg else None,
            "context_before": context_before,
            "context_after": context_after,
            "screenshots": associated_screenshots,
            "existing_review": existing_review,
            "case_info": {
                "case_number": self.config.case_number,
                "case_name": self.config.case_name,
                "examiner": self.config.examiner_name,
            },
        }

    def _submit_decision(self, data: Dict) -> Dict:
        """Save a review decision."""
        index = data.get("index")
        decision = data.get("decision")
        notes = data.get("notes", "")
        amend = bool(data.get("amend"))

        if decision not in ("relevant", "not_relevant", "uncertain"):
            return {"error": "Invalid decision value"}

        if index is None or index < 0 or index >= len(self.flagged_items):
            return {"error": "Invalid item index"}

        item = self.flagged_items[index]
        item_id = item.get("id", f"item_{index}")

        try:
            if amend:
                self.review_manager.amend_review(
                    item_id=item_id,
                    decision=decision,
                    notes=notes,
                )
            else:
                self.review_manager.add_review(
                    item_id=item_id,
                    item_type=item.get("type", "threat"),
                    decision=decision,
                    notes=notes,
                    source=item.get("source", "unknown"),
                    method=item.get("method", ""),
                )
        except ValueError as exc:
            return {"error": str(exc)}

        self.reviewed_indices.add(index)

        if self.forensic:
            self.forensic.record_action(
                "web_review_decision",
                f"Decision '{decision}' for item {item_id} via web interface",
                {
                    "item_id": item_id,
                    "decision": decision,
                    "has_notes": bool(notes),
                    "reviewed_via": "web_interface",
                }
            )

        return {
            "status": "saved",
            "item_id": item_id,
            "decision": decision,
            "progress": self._get_progress(),
        }

    def _first_unreviewed_index(self) -> int:
        """Index of the first flagged item with no active review.

        On resume, reviewers should land on where they left off — not on item 0 with a Previously-reviewed badge and a long chain of Next clicks ahead. Walks the flagged list once; returns 0 if nothing is reviewed yet or everything is reviewed.
        """
        reviewed = self.review_manager.reviewed_item_ids
        if not reviewed or not self.flagged_items:
            return 0
        for i, item in enumerate(self.flagged_items):
            item_id = item.get("id", f"item_{i}")
            if item_id not in reviewed:
                return i
        return 0

    def _get_note_suggestions(self) -> Dict:
        """Return previously used note phrases ordered by frequency, most common first.

        Surfaces prior wording so the examiner can reuse a phrase in one click — speeds up review and keeps language consistent across findings in the same case.
        """
        counts: Dict[str, int] = {}
        for record in self.review_manager.reviews:
            if record.get("superseded_by"):
                continue
            note = (record.get("notes") or "").strip()
            if not note:
                continue
            counts[note] = counts.get(note, 0) + 1
        ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))
        suggestions = [{"text": text, "count": count} for text, count in ordered[:40]]
        return {"suggestions": suggestions}

    def _get_progress(self) -> Dict:
        """Return review progress stats."""
        total = len(self.flagged_items)
        reviewed = len(self.reviewed_indices)
        summary = self.review_manager.get_review_summary()
        return {
            "total": total,
            "reviewed": reviewed,
            "remaining": total - reviewed,
            "percent": round(reviewed / total * 100) if total else 0,
            "decisions": summary.get("decisions", {}),
        }

    def _get_conversations(self) -> List[Dict]:
        """Return conversation groups for browse mode."""
        if self._conversation_cache is None:
            self._conversation_cache = self.threader.group_into_conversations(self.messages)

        result = []
        for key, msgs in self._conversation_cache.items():
            first_ts = msgs[0].get('timestamp', '') if msgs else ''
            last_ts = msgs[-1].get('timestamp', '') if msgs else ''
            result.append({
                'key': key,
                'message_count': len(msgs),
                'first_timestamp': self._format_local_ts(first_ts),
                'last_timestamp': self._format_local_ts(last_ts),
                'participants': key,
            })
        result.sort(key=lambda c: c['message_count'], reverse=True)
        return result

    def _get_browse_page(self, page: int, page_size: int, conversation: str) -> Dict:
        """Return a page of messages for browse mode."""
        page_size = min(max(page_size, 1), 200)

        if conversation:
            if self._conversation_cache is None:
                self._conversation_cache = self.threader.group_into_conversations(self.messages)
            source_msgs = self._conversation_cache.get(conversation, [])
        else:
            source_msgs = self.messages

        total = len(source_msgs)
        start = page * page_size
        end = min(start + page_size, total)
        page_msgs = source_msgs[start:end]

        serialized = []
        for msg in page_msgs:
            s = self._serialise_msg(msg)
            if s:
                s['message_id'] = msg.get('message_id', '')
                serialized.append(s)

        return {
            'messages': serialized,
            'page': page,
            'page_size': page_size,
            'total': total,
            'total_pages': (total + page_size - 1) // page_size if total else 0,
            'conversation': conversation,
        }

    def _submit_browse_flag(self, data: Dict) -> Dict:
        """Flag a message found during browse mode."""
        message_id = data.get('message_id', '')
        decision = data.get('decision', 'relevant')
        notes = data.get('notes', '')

        if decision not in ('relevant', 'not_relevant', 'uncertain'):
            return {"error": "Invalid decision value"}

        target_msg = None
        for msg in self.messages:
            if msg.get('message_id') == message_id:
                target_msg = msg
                break

        if target_msg is None:
            return {"error": "Message not found"}

        item_id = f"browse_{message_id}"

        try:
            self.review_manager.add_review(
                item_id=item_id,
                item_type='user_flagged',
                decision=decision,
                notes=notes,
            )
        except ValueError as exc:
            return {"error": str(exc)}

        if self.forensic:
            self.forensic.record_action(
                "browse_flag_decision",
                f"User flagged message {message_id} as '{decision}' from browse mode",
                {
                    "item_id": item_id,
                    "message_id": message_id,
                    "decision": decision,
                    "has_notes": bool(notes),
                    "reviewed_via": "web_browse",
                }
            )

        return {"status": "saved", "item_id": item_id, "decision": decision}

    def _search_messages(self, q: str, sender: str,
                         date_from: str, date_to: str,
                         page: int, page_size: int) -> Dict:
        """Search messages by content, sender, and date range."""
        page_size = min(max(page_size, 1), 200)

        from_dt = self.threader._parse_timestamp(date_from) if date_from else None
        to_dt = self.threader._parse_timestamp(date_to) if date_to else None

        q_lower = q.lower() if q else ''
        sender_lower = sender.lower() if sender else ''

        matching = []
        for msg in self.messages:
            if q_lower and q_lower not in msg.get('content', '').lower():
                continue
            if sender_lower:
                msg_sender = msg.get('sender', '').lower()
                msg_recipient = msg.get('recipient', '').lower()
                if sender_lower not in msg_sender and sender_lower not in msg_recipient:
                    continue
            if from_dt or to_dt:
                msg_ts = self.threader._parse_timestamp(msg.get('timestamp'))
                if msg_ts is None:
                    continue
                if from_dt and msg_ts < from_dt:
                    continue
                if to_dt and msg_ts > to_dt:
                    continue
            matching.append(msg)

        total = len(matching)
        start = page * page_size
        end = min(start + page_size, total)
        page_msgs = matching[start:end]

        serialized = []
        for msg in page_msgs:
            s = self._serialise_msg(msg)
            if s:
                s['message_id'] = msg.get('message_id', '')
                serialized.append(s)

        return {
            'messages': serialized,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size if total else 0,
            'query': {'q': q, 'sender': sender,
                      'date_from': date_from, 'date_to': date_to},
        }

    def _find_associated_screenshots(
        self, item: Dict, target_msg: Optional[Dict]
    ) -> List[Dict]:
        """
        Find screenshots associated with the flagged item by timestamp
        proximity (same day).
        """
        if not self.screenshots or not target_msg:
            return []

        msg_ts = self.threader._parse_timestamp(target_msg.get("timestamp"))
        if msg_ts is None:
            return []

        associated = []
        for ss in self.screenshots:
            ss_ts = self.threader._parse_timestamp(ss.get("timestamp") or ss.get("date_taken"))
            if ss_ts and ss_ts.date() == msg_ts.date():
                filename = ss.get("filename") or Path(ss.get("path", "")).name
                associated.append({
                    "filename": filename,
                    "url": f"/screenshots/{filename}",
                    "timestamp": self._format_local_ts(ss_ts),
                })

        return associated

    def _lookup_ts(self, message_id: Optional[str]) -> Optional[str]:
        """Look up the ISO timestamp of a message by id. Returns None when unknown."""
        if not message_id:
            return None
        for m in self.messages:
            if m.get("message_id") == message_id:
                return m.get("timestamp")
        return None

    def _serialize_event(self, event: Dict) -> Dict:
        """JSON-safe projection of a manual event, with both raw and display timestamps."""
        return {
            "event_id": event.get("event_id"),
            "title": event.get("title"),
            "category": event.get("category"),
            "severity": event.get("severity"),
            "description": event.get("description", ""),
            "start_message_id": event.get("start_message_id"),
            "end_message_id": event.get("end_message_id"),
            "start_timestamp": self._format_local_ts(event.get("start_timestamp")),
            "end_timestamp": self._format_local_ts(event.get("end_timestamp")),
            "examiner": event.get("examiner"),
            "timestamp": event.get("timestamp"),
            "amended": event.get("amended", False),
        }

    def _format_local_ts(self, ts) -> str:
        """Convert a UTC timestamp to local timezone string for display."""
        if ts is None or (isinstance(ts, str) and not ts.strip()):
            return ''
        try:
            parsed = pd.to_datetime(ts, utc=True)
            if pd.isna(parsed):
                return str(ts)
            local_dt = parsed.to_pydatetime().astimezone(self._tz)
            return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        except Exception:
            return str(ts)

    def _serialise_msg(self, msg: Optional[Dict]) -> Optional[Dict]:
        """Return a JSON-safe subset of a message dict."""
        if msg is None:
            return None
        result = {
            "message_id": msg.get("message_id"),
            "sender": msg.get("sender", "Unknown"),
            "recipient": msg.get("recipient", "Unknown"),
            "content": msg.get("content", ""),
            "timestamp": self._format_local_ts(msg.get("timestamp", "")),
            "source": msg.get("source", ""),
        }
        if msg.get("attachment_name"):
            att_name = msg["attachment_name"]
            # For iMessage: attachment field is an absolute path; use it directly
            # For WhatsApp: attachment_name is just a filename
            if msg.get("attachment", "").startswith("/"):
                result["attachment_url"] = f"/attachments{msg['attachment']}"
            else:
                result["attachment_url"] = f"/attachments/{att_name}"
            result["attachment_name"] = att_name
        return result

    # ------------------------------------------------------------------
    # HTML template
    # ------------------------------------------------------------------

    def _render_review_page(self) -> str:
        """Return the single-page review interface HTML."""
        import html as html_module
        case_number = html_module.escape(self.config.case_number or "")
        case_name = html_module.escape(self.config.case_name or "")
        examiner = html_module.escape(self.config.examiner_name or "")
        total_items = len(self.flagged_items)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Evidence Review</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         background: #f5f5f5; color: #333; }}

  /* Header */
  .header {{ background: #1a237e; color: #fff; padding: 12px 24px; display: flex;
             align-items: center; justify-content: space-between; }}
  .header h1 {{ font-size: 18px; font-weight: 600; }}
  .header .case-info {{ font-size: 13px; opacity: 0.85; }}

  /* Progress bar */
  .progress-bar {{ background: #e0e0e0; height: 6px; width: 100%; }}
  .progress-bar .fill {{ background: #43a047; height: 100%; transition: width 0.3s; }}

  /* Layout */
  .container {{ display: flex; height: calc(100vh - 108px); }}
  .context-panel {{ flex: 0 0 65%; overflow-y: auto; padding: 20px 24px; }}
  .decision-panel {{ flex: 0 0 35%; background: #fff; border-left: 1px solid #ddd;
                     padding: 20px; overflow-y: auto; display: flex; flex-direction: column; }}

  /* Messages */
  .msg {{ margin-bottom: 10px; padding: 10px 14px; border-radius: 8px; max-width: 85%;
          font-size: 14px; line-height: 1.5; }}
  .msg.sent {{ background: #d1e7dd; margin-left: auto; }}
  .msg.received {{ background: #fff; border: 1px solid #ddd; }}
  .msg.flagged {{ background: #fff3cd; border: 2px solid #e65100; position: relative; }}
  .msg .meta {{ font-size: 11px; color: #757575; margin-bottom: 4px; }}
  .msg .content {{ word-wrap: break-word; }}
  .flag-label {{ display: inline-block; background: #e65100; color: #fff; font-size: 10px;
                 padding: 2px 6px; border-radius: 4px; margin-bottom: 6px; }}

  /* Inline attachments (WhatsApp photos) */
  .msg .attachment {{ margin-top: 8px; }}
  .msg .attachment img {{ max-width: 100%; max-height: 400px; border-radius: 4px; border: 1px solid #ccc; }}

  /* Screenshots */
  .screenshots {{ margin-top: 16px; }}
  .screenshots h3 {{ font-size: 14px; margin-bottom: 8px; }}
  .screenshots img {{ max-width: 100%; border: 1px solid #ccc; border-radius: 4px; margin-bottom: 8px; }}

  /* Decision panel */
  .item-details {{ margin-bottom: 16px; }}
  .item-details h2 {{ font-size: 16px; margin-bottom: 8px; }}
  .detail-row {{ font-size: 13px; margin-bottom: 4px; }}
  .detail-row .label {{ font-weight: 600; }}
  .decision-buttons {{ display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px; }}
  .decision-buttons button {{ padding: 10px; border: 3px solid transparent; border-radius: 6px;
                              font-size: 14px; font-weight: 600; cursor: pointer;
                              transition: transform 0.12s, box-shadow 0.12s, filter 0.12s; }}
  .decision-buttons button:hover {{ filter: brightness(1.05); }}
  .btn-relevant {{ background: #43a047; color: #fff; }}
  .btn-not-relevant {{ background: #9e9e9e; color: #fff; }}
  .btn-uncertain {{ background: #ff8f00; color: #fff; }}
  /* Selected state: saturate background, add a thick dark border + outer glow ring, bump size, and drop a checkmark so the active choice is unmistakable at a glance. */
  .decision-buttons button.selected {{ transform: scale(1.04); }}
  .decision-buttons button.selected::before {{ content: "\\2713  "; font-weight: 900; }}
  .btn-relevant.selected {{ background: #1b5e20; border-color: #0b3d10;
                            box-shadow: 0 0 0 4px rgba(67,160,71,0.45), 0 4px 14px rgba(27,94,32,0.45); }}
  .btn-not-relevant.selected {{ background: #424242; border-color: #1a1a1a;
                                box-shadow: 0 0 0 4px rgba(158,158,158,0.55), 0 4px 14px rgba(66,66,66,0.45); }}
  .btn-uncertain.selected {{ background: #e65100; border-color: #8a2f00;
                             box-shadow: 0 0 0 4px rgba(255,143,0,0.45), 0 4px 14px rgba(230,81,0,0.45); }}
  .decision-buttons button:not(.selected) {{ opacity: 0.78; }}
  .decision-buttons button:not(.selected):hover {{ opacity: 1; }}

  textarea {{ width: 100%; height: 80px; padding: 8px; border: 1px solid #ccc;
              border-radius: 6px; font-size: 13px; resize: vertical; }}

  /* Quick-select note phrases — reused prior notes surfaced as clickable chips so the examiner can replay consistent language across findings. */
  .note-phrases {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0 4px; max-height: 120px; overflow-y: auto; }}
  .note-phrases .phrase-chip {{ display: inline-flex; align-items: center; gap: 4px;
                                background: #eef3ff; color: #1a237e; border: 1px solid #c5cae9;
                                border-radius: 14px; padding: 3px 10px; font-size: 12px;
                                cursor: pointer; max-width: 100%; line-height: 1.3; }}
  .note-phrases .phrase-chip:hover {{ background: #1a237e; color: #fff; border-color: #1a237e; }}
  .note-phrases .phrase-chip .chip-text {{ max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .note-phrases .phrase-chip .chip-count {{ background: rgba(26,35,126,0.12); color: inherit;
                                            font-size: 10px; padding: 0 5px; border-radius: 8px; font-weight: 600; }}
  .note-phrases .phrase-chip:hover .chip-count {{ background: rgba(255,255,255,0.22); }}
  .note-phrases .phrase-empty {{ color: #999; font-size: 11px; font-style: italic; padding: 2px 2px; }}

  .submit-btn {{ width: 100%; padding: 10px; background: #1a237e; color: #fff; border: none;
                 border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer;
                 margin-top: 8px; }}
  .submit-btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}

  /* Navigation */
  .nav {{ display: flex; justify-content: space-between; align-items: center; margin-top: auto;
          padding-top: 16px; border-top: 1px solid #eee; }}
  .nav button {{ padding: 8px 16px; border: 1px solid #ccc; border-radius: 6px; background: #fff;
                 cursor: pointer; font-size: 13px; }}
  .nav button:disabled {{ opacity: 0.4; cursor: not-allowed; }}
  .nav .counter {{ font-size: 13px; font-weight: 600; }}

  .complete-btn {{ width: 100%; padding: 10px; margin-top: 12px; background: #b71c1c; color: #fff;
                   border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }}
  .pause-btn {{ width: 100%; padding: 10px; margin-top: 8px; background: #fff; color: #424242;
                border: 1px solid #9e9e9e; border-radius: 6px; font-size: 13px; cursor: pointer; }}
  .pause-btn:hover {{ background: #f5f5f5; }}

  /* Toast */
  .toast {{ position: fixed; bottom: 24px; right: 24px; background: #333; color: #fff;
            padding: 10px 20px; border-radius: 6px; font-size: 14px; opacity: 0;
            transition: opacity 0.3s; pointer-events: none; z-index: 999; }}
  .toast.show {{ opacity: 1; }}

  /* Existing review badge */
  .existing-badge {{ background: #e8f5e9; border: 1px solid #a5d6a7; padding: 8px 12px;
                     border-radius: 6px; margin-bottom: 12px; font-size: 13px; }}

  /* Finding source badges — make the provenance of a finding visible so reviewers treat pattern-matched vs AI-screened results differently. */
  .source-badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px;
                   font-weight: 600; letter-spacing: 0.03em; margin-right: 6px; }}
  .src-pattern_matched {{ background: #e3f2fd; color: #0d47a1; border: 1px solid #bbdefb; }}
  .src-ai_screened    {{ background: #fff3e0; color: #e65100; border: 1px solid #ffcc80; }}
  .src-extracted      {{ background: #f3e5f5; color: #4a148c; border: 1px solid #e1bee7; }}
  .src-derived        {{ background: #eceff1; color: #263238; border: 1px solid #cfd8dc; }}
  .src-unknown        {{ background: #eee; color: #555; border: 1px solid #ccc; }}

  /* Tabs */
  .tabs {{ display: flex; background: #263238; }}
  .tab {{ padding: 10px 24px; border: none; background: transparent; color: #ccc;
          font-size: 14px; cursor: pointer; border-bottom: 3px solid transparent; }}
  .tab:hover {{ color: #fff; }}
  .tab.active {{ color: #fff; border-bottom-color: #43a047; }}

  /* Browse mode */
  .browse-container {{ display: flex; height: calc(100vh - 108px); }}
  .browse-sidebar {{ flex: 0 0 250px; overflow-y: auto; background: #fff;
                     border-right: 1px solid #ddd; padding: 8px; }}
  .conv-item {{ padding: 8px 12px; border-radius: 6px; cursor: pointer;
                font-size: 13px; margin-bottom: 4px; }}
  .conv-item:hover {{ background: #e3f2fd; }}
  .conv-item.active {{ background: #1a237e; color: #fff; }}
  .conv-item small {{ opacity: 0.7; }}
  .browse-main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; }}

  /* Search bar */
  .search-bar {{ display: flex; gap: 8px; padding: 10px 16px; background: #fafafa;
                 border-bottom: 1px solid #e0e0e0; align-items: center; flex-wrap: wrap; }}
  .search-bar input {{ padding: 7px 10px; border: 1px solid #ccc; border-radius: 4px;
                       font-size: 13px; }}
  .search-bar input[type="text"] {{ flex: 1; min-width: 120px; }}
  .search-bar input[type="date"] {{ width: 140px; }}
  .search-bar button {{ padding: 7px 14px; border: none; border-radius: 4px;
                        font-size: 13px; cursor: pointer; font-weight: 600; }}
  .search-bar .search-btn {{ background: #1a237e; color: #fff; }}
  .search-bar .clear-btn {{ background: #9e9e9e; color: #fff; }}

  /* Browse messages */
  .browse-messages {{ flex: 1; overflow-y: auto; padding: 16px 24px; }}
  .browse-msg {{ margin-bottom: 8px; padding: 10px 14px; border-radius: 6px;
                 font-size: 14px; line-height: 1.5; background: #fff; border: 1px solid #eee;
                 position: relative; }}
  .browse-msg.sent {{ background: #d1e7dd; }}
  .browse-msg .meta {{ font-size: 11px; color: #757575; margin-bottom: 4px; }}
  .browse-msg .content {{ word-wrap: break-word; }}
  .browse-msg .flag-btn {{ position: absolute; top: 8px; right: 8px; padding: 4px 10px;
                           border: 1px solid #43a047; border-radius: 4px; background: #fff;
                           color: #43a047; cursor: pointer; font-size: 12px; }}
  .browse-msg .flag-btn:hover {{ background: #43a047; color: #fff; }}
  .browse-msg .flag-btn.flagged {{ background: #43a047; color: #fff; border-color: #43a047; }}
  .browse-msg .attachment img {{ max-width: 100%; max-height: 300px; border-radius: 4px;
                                 border: 1px solid #ccc; margin-top: 6px; }}
  .browse-pagination {{ display: flex; justify-content: center; align-items: center; gap: 12px;
                        padding: 12px; border-top: 1px solid #eee; background: #fafafa; }}
  .browse-pagination button {{ padding: 6px 14px; border: 1px solid #ccc; border-radius: 4px;
                               background: #fff; cursor: pointer; font-size: 13px; }}
  .browse-pagination button:disabled {{ opacity: 0.4; cursor: not-allowed; }}
  .browse-pagination .page-info {{ font-size: 13px; font-weight: 600; }}
  .browse-total {{ padding: 8px 16px; font-size: 13px; color: #666; border-bottom: 1px solid #eee; }}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>Forensic Evidence Review</h1>
    <div class="case-info">
      {f'Case: {case_number}' if case_number else ''}
      {f' &mdash; {case_name}' if case_name else ''}
      {f' | Examiner: {examiner}' if examiner else ''}
    </div>
  </div>
  <div class="case-info" id="progressText">0 / {total_items} reviewed</div>
</div>
<div class="progress-bar"><div class="fill" id="progressFill" style="width:0%"></div></div>

<div class="tabs">
  <button class="tab active" id="tabFlagged" onclick="switchTab('flagged')">
    Flagged Items ({total_items})
  </button>
  <button class="tab" id="tabBrowse" onclick="switchTab('browse')">
    Browse All Messages
  </button>
  <button class="tab" id="tabEvents" onclick="switchTab('events')">
    Events Timeline
  </button>
</div>

<div class="container" id="flaggedContainer">
  <!-- Left: Message context -->
  <div class="context-panel" id="contextPanel">
    <p style="color:#999; padding-top:40px; text-align:center;">Loading...</p>
  </div>

  <!-- Right: Decision panel -->
  <div class="decision-panel">
    <div id="existingReview"></div>

    <div class="item-details" id="itemDetails">
      <h2>Item Details</h2>
      <div class="detail-row"><span class="label">Source:</span> <span id="detailSourceBadge"></span></div>
      <div class="detail-row"><span class="label">Method:</span> <span id="detailMethod">-</span></div>
      <div class="detail-row"><span class="label">Type:</span> <span id="detailType">-</span></div>
      <div class="detail-row"><span class="label">Categories:</span> <span id="detailCats">-</span></div>
      <div class="detail-row"><span class="label">Confidence:</span> <span id="detailConf">-</span></div>
      <div class="detail-row"><span class="label">Severity:</span> <span id="detailSev">-</span></div>
    </div>

    <div class="decision-buttons">
      <button class="btn-relevant" onclick="selectDecision('relevant')" id="btnRelevant">
        1 &mdash; Relevant
      </button>
      <button class="btn-not-relevant" onclick="selectDecision('not_relevant')" id="btnNotRelevant">
        2 &mdash; Not Relevant
      </button>
      <button class="btn-uncertain" onclick="selectDecision('uncertain')" id="btnUncertain">
        3 &mdash; Uncertain
      </button>
    </div>

    <label style="font-size:13px; font-weight:600; margin-bottom:4px; display:block;">Notes</label>
    <div id="notePhrases" class="note-phrases"></div>
    <textarea id="notesField" placeholder="Optional notes about your decision..."></textarea>
    <button class="submit-btn" id="submitBtn" onclick="submitDecision()" disabled>Submit Decision</button>

    <div class="nav">
      <button onclick="navigate(-1)" id="prevBtn">&larr; Previous</button>
      <span class="counter" id="navCounter">-</span>
      <button onclick="navigate(1)" id="nextBtn">Next &rarr;</button>
    </div>

    <button class="complete-btn" onclick="completeReview()">Complete Review</button>
    <button class="pause-btn" onclick="pauseReview()" title="Save decisions, close the UI, and resume later with --resume">Pause &amp; Quit (resume later)</button>
  </div>
</div>

<!-- Browse mode container (hidden by default) -->
<div class="browse-container" id="browseContainer" style="display:none;">
  <div class="browse-sidebar" id="conversationList">
    <p style="color:#999; padding:16px; text-align:center;">Loading conversations...</p>
  </div>
  <div class="browse-main">
    <div class="search-bar">
      <input type="text" id="searchQ" placeholder="Search message content...">
      <input type="text" id="searchSender" placeholder="Person..." style="flex:0 0 120px;">
      <input type="date" id="searchFrom" title="From date">
      <input type="date" id="searchTo" title="To date">
      <button class="search-btn" onclick="executeSearch()">Search</button>
      <button class="clear-btn" onclick="clearSearch()">Clear</button>
    </div>
    <div class="browse-total" id="browseTotal"></div>
    <div class="browse-messages" id="browseMessages">
      <p style="color:#999; padding:40px; text-align:center;">Select a conversation or search</p>
    </div>
    <div class="browse-pagination" id="browsePagination"></div>
  </div>
</div>

<!-- Events tab: examiner-authored named incidents spanning a message range -->
<div id="eventsContainer" style="display:none; padding: 20px 24px; max-width: 900px; margin: 0 auto;">
  <h2 style="margin:0 0 6px;">Named events</h2>
  <p style="color:#666; font-size: 13px; margin: 0 0 20px;">
    Name the incidents that span multiple messages — a fight that starts Friday night and trails into Sunday morning is one event, not twenty. Each event points at a start and end message; edits and removals append new records rather than mutating prior ones so the audit trail survives.
  </p>

  <div id="eventForm" style="background:#fff; border:1px solid #ddd; border-radius:8px; padding:16px; margin-bottom:24px;">
    <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start;">
      <div style="flex:2 1 240px;">
        <label style="font-size:12px;font-weight:600;">Title <span style="color:#c62828;">*</span></label>
        <input type="text" id="evtTitle" placeholder="e.g. September 4 custody dispute" style="width:100%; padding:7px; border:1px solid #ccc; border-radius:4px;">
      </div>
      <div style="flex:1 1 120px;">
        <label style="font-size:12px;font-weight:600;">Category</label>
        <select id="evtCategory" style="width:100%; padding:7px; border:1px solid #ccc; border-radius:4px;">
          <option value="incident">Incident</option>
          <option value="threat">Threat</option>
          <option value="escalation">Escalation</option>
          <option value="de_escalation">De-escalation</option>
          <option value="pattern">Pattern</option>
          <option value="milestone">Milestone</option>
        </select>
      </div>
      <div style="flex:1 1 100px;">
        <label style="font-size:12px;font-weight:600;">Severity</label>
        <select id="evtSeverity" style="width:100%; padding:7px; border:1px solid #ccc; border-radius:4px;">
          <option value="high">High</option>
          <option value="medium" selected>Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>
    </div>

    <div style="display:flex; gap:12px; margin-top:10px; flex-wrap:wrap;">
      <div style="flex:1 1 220px;">
        <label style="font-size:12px;font-weight:600;">Start message_id <span style="color:#c62828;">*</span></label>
        <input type="text" id="evtStart" placeholder="e.g. msg-017" style="width:100%; padding:7px; border:1px solid #ccc; border-radius:4px; font-family: Consolas, monospace;">
        <small style="color:#999; font-size:11px;">Use the Flag button in Browse to capture a message_id.</small>
      </div>
      <div style="flex:1 1 220px;">
        <label style="font-size:12px;font-weight:600;">End message_id <span style="color:#c62828;">*</span></label>
        <input type="text" id="evtEnd" placeholder="e.g. msg-020" style="width:100%; padding:7px; border:1px solid #ccc; border-radius:4px; font-family: Consolas, monospace;">
      </div>
    </div>

    <div style="margin-top:10px;">
      <label style="font-size:12px;font-weight:600;">Description (optional)</label>
      <textarea id="evtDescription" placeholder="Short context: what the examiner is asserting this range represents" style="width:100%; height:60px; padding:7px; border:1px solid #ccc; border-radius:4px; font-size:13px; resize:vertical;"></textarea>
    </div>

    <div id="evtEditReasonRow" style="display:none; margin-top:10px;">
      <label style="font-size:12px;font-weight:600;">Reason for edit <span style="color:#c62828;">*</span></label>
      <input type="text" id="evtReason" placeholder="Why is this event being changed? (required on edits + removals)" style="width:100%; padding:7px; border:1px solid #ccc; border-radius:4px;">
    </div>

    <div style="margin-top:14px; display:flex; gap:8px;">
      <button id="evtSave" onclick="saveEvent()" style="padding:8px 18px; background:#1a237e; color:#fff; border:none; border-radius:4px; font-weight:600; cursor:pointer;">Add event</button>
      <button id="evtCancel" onclick="resetEventForm()" style="padding:8px 18px; background:#9e9e9e; color:#fff; border:none; border-radius:4px; cursor:pointer; display:none;">Cancel edit</button>
    </div>
  </div>

  <h3 style="margin:0 0 10px; font-size:15px;">Active events</h3>
  <div id="eventsList">
    <p style="color:#999; padding:20px; text-align:center;">No events yet. Name the first one above.</p>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let currentIndex = 0;
let totalItems = {total_items};
let selectedDecision = null;

function loadItem(idx) {{
  fetch('/api/item/' + idx)
    .then(r => r.json())
    .then(data => {{
      if (data.error) {{
        document.getElementById('contextPanel').innerHTML =
          '<p style="color:#c62828; padding:40px; text-align:center;">' + data.error + '</p>';
        return;
      }}
      currentIndex = data.index;
      totalItems = data.total;
      renderContext(data);
      renderDetails(data);
      renderExistingReview(data.existing_review);
      updateNav();
      selectedDecision = null;
      document.querySelectorAll('.decision-buttons button').forEach(b => b.classList.remove('selected'));
      document.getElementById('submitBtn').disabled = true;
      document.getElementById('notesField').value = '';
    }});
}}

function renderContext(data) {{
  const panel = document.getElementById('contextPanel');
  let html = '';

  // Before messages
  (data.context_before || []).forEach(m => {{
    html += msgBubble(m, false);
  }});

  // Flagged message
  if (data.target_message) {{
    html += msgBubble(data.target_message, true);
  }} else {{
    html += '<div class="msg flagged"><span class="flag-label">FLAGGED</span>'
          + '<div class="content">' + escapeHtml(data.item.content || '(no content)') + '</div></div>';
  }}

  // After messages
  (data.context_after || []).forEach(m => {{
    html += msgBubble(m, false);
  }});

  // Screenshots
  if (data.screenshots && data.screenshots.length) {{
    html += '<div class="screenshots"><h3>Associated Screenshots</h3>';
    data.screenshots.forEach(s => {{
      html += '<div><img src="' + s.url + '" alt="' + escapeHtml(s.filename) + '">'
            + '<div style="font-size:11px;color:#757575;">' + escapeHtml(s.filename)
            + ' &mdash; ' + escapeHtml(s.timestamp) + '</div></div>';
    }});
    html += '</div>';
  }}

  panel.innerHTML = html;

  // Scroll to flagged message
  const flagged = panel.querySelector('.flagged');
  if (flagged) flagged.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
}}

function msgBubble(m, isFlagged) {{
  const person1 = {json.dumps(self.config.person1_name if hasattr(self.config, 'person1_name') else 'Me')};
  const cls = isFlagged ? 'msg flagged'
              : (m.sender === person1 ? 'msg sent' : 'msg received');
  let html = '<div class="' + cls + '">';
  if (isFlagged) html += '<span class="flag-label">FLAGGED</span>';
  html += '<div class="meta">' + escapeHtml(m.timestamp || '') + ' &mdash; '
        + escapeHtml(m.sender || '') + ' &rarr; ' + escapeHtml(m.recipient || '') + '</div>';
  html += '<div class="content">' + escapeHtml(m.content || '') + '</div>';
  if (m.attachment_url) {{
    html += '<div class="attachment"><img src="' + escapeHtml(m.attachment_url)
          + '" alt="' + escapeHtml(m.attachment_name || 'photo') + '"></div>';
  }}
  html += '</div>';
  return html;
}}

function renderDetails(data) {{
  const item = data.item || {{}};
  const source = item.source || 'unknown';
  const labels = {{ pattern_matched: 'PATTERN-MATCHED', ai_screened: 'AI-SCREENED', extracted: 'EXTRACTED', derived: 'DERIVED', unknown: 'UNKNOWN' }};
  const badge = document.getElementById('detailSourceBadge');
  badge.innerHTML = '<span class="source-badge src-' + escapeHtml(source) + '">'
                  + escapeHtml(labels[source] || source.toUpperCase()) + '</span>';
  document.getElementById('detailMethod').textContent = item.method || '-';
  document.getElementById('detailType').textContent = item.type || '-';
  document.getElementById('detailCats').textContent = item.categories || '-';
  document.getElementById('detailConf').textContent = item.confidence ? (item.confidence * 100).toFixed(0) + '%' : '-';
  document.getElementById('detailSev').textContent = item.severity || '-';
}}

function renderExistingReview(review) {{
  const el = document.getElementById('existingReview');
  if (review) {{
    el.innerHTML = '<div class="existing-badge">Previously reviewed: <strong>'
      + escapeHtml(review.decision) + '</strong>'
      + (review.notes ? ' &mdash; ' + escapeHtml(review.notes) : '')
      + '</div>';
  }} else {{
    el.innerHTML = '';
  }}
}}

function selectDecision(d) {{
  selectedDecision = d;
  document.querySelectorAll('.decision-buttons button').forEach(b => b.classList.remove('selected'));
  if (d === 'relevant') document.getElementById('btnRelevant').classList.add('selected');
  else if (d === 'not_relevant') document.getElementById('btnNotRelevant').classList.add('selected');
  else document.getElementById('btnUncertain').classList.add('selected');
  document.getElementById('submitBtn').disabled = false;
}}

function submitDecision() {{
  if (!selectedDecision) return;
  const notes = document.getElementById('notesField').value.trim();

  // Notes are required for rejection/uncertain — these are the decisions that keep the item OUT of the final report, so a reason must be recorded for defensibility.
  if ((selectedDecision === 'not_relevant' || selectedDecision === 'uncertain') && !notes) {{
    showToast('A brief explanation is required for this decision');
    document.getElementById('notesField').focus();
    return;
  }}

  fetch('/api/decision', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ index: currentIndex, decision: selectedDecision, notes: notes }})
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.error) {{ showToast('Error: ' + data.error); return; }}
    showToast('Decision saved');
    updateProgress(data.progress);
    loadNotePhrases();
    // Auto-advance to next item
    if (currentIndex < totalItems - 1) {{
      setTimeout(() => loadItem(currentIndex + 1), 400);
    }}
  }});
}}

function navigate(delta) {{
  const next = currentIndex + delta;
  if (next >= 0 && next < totalItems) loadItem(next);
}}

function updateNav() {{
  document.getElementById('navCounter').textContent = (currentIndex + 1) + ' / ' + totalItems;
  document.getElementById('prevBtn').disabled = (currentIndex <= 0);
  document.getElementById('nextBtn').disabled = (currentIndex >= totalItems - 1);
}}

function updateProgress(progress) {{
  if (!progress) return;
  document.getElementById('progressFill').style.width = progress.percent + '%';
  document.getElementById('progressText').textContent = progress.reviewed + ' / ' + progress.total + ' reviewed';
}}

function completeReview() {{
  if (!confirm('Complete the review session? This marks the review phase DONE; reports will be generated on the next run --finalize call. Use Pause & Quit instead if you plan to keep reviewing later.')) return;
  fetch('/api/complete', {{ method: 'POST' }}).then(() => {{
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;'
      + 'font-family:sans-serif;font-size:18px;color:#333;">Review complete. You may close this tab.</div>';
  }});
}}

function pauseReview() {{
  if (!confirm('Pause the review? Your decisions so far are already saved. Run --resume to continue from where you stopped.')) return;
  fetch('/api/pause', {{ method: 'POST' }}).then(() => {{
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;'
      + 'font-family:sans-serif;font-size:18px;color:#333; flex-direction:column;">'
      + '<div style="font-weight:600; margin-bottom:8px;">Review paused.</div>'
      + '<div style="font-size:14px; color:#666;">Resume with <code>python3 run.py --env &lt;your .env&gt; --resume</code></div>'
      + '</div>';
  }});
}}

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}}

function escapeHtml(text) {{
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}}

// Keyboard shortcuts
document.addEventListener('keydown', e => {{
  if (e.target.tagName === 'TEXTAREA') return;
  if (e.key === '1') selectDecision('relevant');
  else if (e.key === '2') selectDecision('not_relevant');
  else if (e.key === '3') selectDecision('uncertain');
  else if (e.key === 'Enter' && selectedDecision) submitDecision();
  else if (e.key === 'ArrowLeft') navigate(-1);
  else if (e.key === 'ArrowRight') navigate(1);
}});

// Quick-select note phrases
function loadNotePhrases() {{
  fetch('/api/note_suggestions')
    .then(r => r.json())
    .then(data => renderNotePhrases(data.suggestions || []));
}}

function renderNotePhrases(suggestions) {{
  const host = document.getElementById('notePhrases');
  if (!host) return;
  if (!suggestions.length) {{
    host.innerHTML = '<span class="phrase-empty">No reusable phrases yet — your notes will appear here.</span>';
    return;
  }}
  host.innerHTML = suggestions.map(s => {{
    const text = s.text || '';
    const count = s.count || 1;
    return '<span class="phrase-chip" title="' + escapeHtml(text) + '" onclick="applyPhrase(this)" data-text="' + escapeHtml(text) + '">'
         + '<span class="chip-text">' + escapeHtml(text) + '</span>'
         + (count > 1 ? '<span class="chip-count">' + count + '</span>' : '')
         + '</span>';
  }}).join('');
}}

function applyPhrase(el) {{
  const phrase = el.getAttribute('data-text') || '';
  if (!phrase) return;
  const field = document.getElementById('notesField');
  const current = field.value.trim();
  if (!current) {{
    field.value = phrase;
  }} else if (current.toLowerCase().includes(phrase.toLowerCase())) {{
    // Already present — just focus, don't duplicate
  }} else {{
    const sep = /[.!?;]$/.test(current) ? ' ' : '; ';
    field.value = current + sep + phrase;
  }}
  field.focus();
  // Put cursor at the end
  field.setSelectionRange(field.value.length, field.value.length);
}}

// Initial load — start on the first unreviewed item so resumed sessions don't dump the reviewer back at item 0.
fetch('/api/progress').then(r => r.json()).then(updateProgress);
loadNotePhrases();
fetch('/api/start_index')
  .then(r => r.json())
  .then(data => loadItem((data && typeof data.index === 'number') ? data.index : 0))
  .catch(() => loadItem(0));

// =====================================================================
// Browse mode + Search
// =====================================================================
let browseConversation = '';
let browsePage = 0;
let isSearchActive = false;
let lastSearchParams = {{}};
const BROWSE_PAGE_SIZE = 50;

function switchTab(tab) {{
  const flagged = document.getElementById('flaggedContainer');
  const browse = document.getElementById('browseContainer');
  const events = document.getElementById('eventsContainer');
  document.getElementById('tabFlagged').classList.toggle('active', tab === 'flagged');
  document.getElementById('tabBrowse').classList.toggle('active', tab === 'browse');
  document.getElementById('tabEvents').classList.toggle('active', tab === 'events');
  flagged.style.display = (tab === 'flagged') ? 'flex' : 'none';
  browse.style.display = (tab === 'browse') ? 'flex' : 'none';
  events.style.display = (tab === 'events') ? 'block' : 'none';
  if (tab === 'browse') loadConversations();
  if (tab === 'events') loadEvents();
}}

// ---- Events ----
let editingEventId = null;

function loadEvents() {{
  fetch('/api/events')
    .then(r => r.json())
    .then(data => renderEventList(data.events || []));
}}

function renderEventList(events) {{
  const panel = document.getElementById('eventsList');
  if (!events.length) {{
    panel.innerHTML = '<p style="color:#999; padding:20px; text-align:center;">No events yet. Name the first one above.</p>';
    return;
  }}
  const categoryColors = {{
    incident: '#6a1b9a', threat: '#c62828', escalation: '#ad1457',
    de_escalation: '#2e7d32', pattern: '#ef6c00', milestone: '#1565c0'
  }};
  let html = '';
  events.forEach(e => {{
    const color = categoryColors[e.category] || '#666';
    const range = (e.start_message_id && e.end_message_id && e.start_message_id !== e.end_message_id)
      ? (escapeHtml(e.start_message_id) + ' → ' + escapeHtml(e.end_message_id))
      : escapeHtml(e.start_message_id || e.end_message_id || '');
    const ts = e.start_timestamp ? (' &middot; ' + escapeHtml(e.start_timestamp)) : '';
    const amendedBadge = e.amended ? ' <span style="font-size:10px;color:#888;">(amended)</span>' : '';
    html += '<div style="background:#fff; border:1px solid #ddd; border-radius:6px; padding:14px; margin-bottom:10px;">'
          + '<div style="display:flex; justify-content:space-between; align-items:start; gap:10px;">'
          +   '<div style="flex:1;">'
          +     '<span style="display:inline-block; background:' + color + '22; color:' + color
          +       '; font-size:10px; font-weight:700; letter-spacing:0.06em; padding:2px 8px; border-radius:10px;">'
          +       escapeHtml((e.category || 'incident').toUpperCase().replace('_','-')) + '</span> '
          +     '<strong style="font-size:15px;">' + escapeHtml(e.title || '') + '</strong>' + amendedBadge
          +     '<div style="font-size:11px; color:#888; margin-top:4px; font-family: Consolas, monospace;">' + range + ts + '</div>'
          +     (e.description ? '<div style="margin-top:6px; font-size:13px; color:#333;">' + escapeHtml(e.description) + '</div>' : '')
          +     (e.examiner ? '<div style="font-size:11px; color:#888; margin-top:6px;">by ' + escapeHtml(e.examiner) + '</div>' : '')
          +   '</div>'
          +   '<div style="display:flex; flex-direction:column; gap:4px;">'
          +     '<button onclick="beginEditEvent(\\''+ escapeHtml(e.event_id) +'\\')" '
          +            'style="padding:4px 10px; background:#e3f2fd; color:#0d47a1; border:1px solid #bbdefb; border-radius:4px; cursor:pointer; font-size:11px;">Edit</button>'
          +     '<button onclick="removeEvent(\\''+ escapeHtml(e.event_id) +'\\')" '
          +            'style="padding:4px 10px; background:#ffebee; color:#c62828; border:1px solid #ffcdd2; border-radius:4px; cursor:pointer; font-size:11px;">Remove</button>'
          +   '</div>'
          + '</div></div>';
  }});
  panel.innerHTML = html;
  window._eventsCache = events;
}}

function beginEditEvent(eventId) {{
  const e = (window._eventsCache || []).find(x => x.event_id === eventId);
  if (!e) return;
  editingEventId = eventId;
  document.getElementById('evtTitle').value = e.title || '';
  document.getElementById('evtCategory').value = e.category || 'incident';
  document.getElementById('evtSeverity').value = e.severity || 'medium';
  document.getElementById('evtStart').value = e.start_message_id || '';
  document.getElementById('evtEnd').value = e.end_message_id || '';
  document.getElementById('evtDescription').value = e.description || '';
  document.getElementById('evtEditReasonRow').style.display = 'block';
  document.getElementById('evtReason').value = '';
  document.getElementById('evtSave').textContent = 'Save changes';
  document.getElementById('evtCancel').style.display = 'inline-block';
  document.getElementById('eventForm').scrollIntoView({{behavior: 'smooth', block: 'start'}});
}}

function resetEventForm() {{
  editingEventId = null;
  document.getElementById('evtTitle').value = '';
  document.getElementById('evtCategory').value = 'incident';
  document.getElementById('evtSeverity').value = 'medium';
  document.getElementById('evtStart').value = '';
  document.getElementById('evtEnd').value = '';
  document.getElementById('evtDescription').value = '';
  document.getElementById('evtReason').value = '';
  document.getElementById('evtEditReasonRow').style.display = 'none';
  document.getElementById('evtSave').textContent = 'Add event';
  document.getElementById('evtCancel').style.display = 'none';
}}

function saveEvent() {{
  const payload = {{
    title: document.getElementById('evtTitle').value.trim(),
    category: document.getElementById('evtCategory').value,
    severity: document.getElementById('evtSeverity').value,
    start_message_id: document.getElementById('evtStart').value.trim(),
    end_message_id: document.getElementById('evtEnd').value.trim(),
    description: document.getElementById('evtDescription').value.trim(),
  }};
  if (!payload.title) {{ showToast('Title is required'); return; }}
  if (!payload.start_message_id || !payload.end_message_id) {{ showToast('Start and end message_id are required'); return; }}

  const url = editingEventId ? ('/api/events/' + encodeURIComponent(editingEventId)) : '/api/events';
  const method = editingEventId ? 'PUT' : 'POST';
  if (editingEventId) {{
    payload.reason = document.getElementById('evtReason').value.trim();
    if (!payload.reason) {{ showToast('Reason is required when editing an event'); return; }}
  }}

  fetch(url, {{
    method: method,
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(payload),
  }})
  .then(r => r.json().then(d => ({{ok: r.ok, data: d}})))
  .then(({{ok, data}}) => {{
    if (!ok) {{ showToast('Error: ' + (data.error || 'could not save')); return; }}
    showToast(editingEventId ? 'Event updated' : 'Event added');
    resetEventForm();
    loadEvents();
  }});
}}

function removeEvent(eventId) {{
  const reason = prompt('Reason for removing this event (required):');
  if (!reason) return;
  fetch('/api/events/' + encodeURIComponent(eventId), {{
    method: 'DELETE',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{reason: reason}}),
  }})
  .then(r => r.json().then(d => ({{ok: r.ok, data: d}})))
  .then(({{ok, data}}) => {{
    if (!ok) {{ showToast('Error: ' + (data.error || 'could not remove')); return; }}
    showToast('Event removed');
    loadEvents();
  }});
}}

function loadConversations() {{
  fetch('/api/conversations')
    .then(r => r.json())
    .then(convos => {{
      const sidebar = document.getElementById('conversationList');
      let html = '<div class="conv-item' + (!browseConversation ? ' active' : '')
                + '" onclick="selectConversation(\\'\\')">All Messages</div>';
      convos.forEach(c => {{
        const active = (c.key === browseConversation) ? ' active' : '';
        html += '<div class="conv-item' + active + '" onclick="selectConversation(\\''
              + c.key.replace(/'/g, "\\\\'") + '\\')">'
              + escapeHtml(c.participants)
              + '<br><small>' + c.message_count + ' msgs</small></div>';
      }});
      sidebar.innerHTML = html;
      if (!isSearchActive) loadBrowsePage(0);
    }});
}}

function selectConversation(key) {{
  browseConversation = key;
  browsePage = 0;
  isSearchActive = false;
  // Re-render sidebar active state
  document.querySelectorAll('.conv-item').forEach(el => {{
    el.classList.toggle('active', el.textContent.includes(key) || (!key && el.textContent === 'All Messages'));
  }});
  loadConversations();
}}

function loadBrowsePage(page) {{
  if (isSearchActive) {{
    searchPage(page);
    return;
  }}
  browsePage = page;
  const params = new URLSearchParams({{
    page: page, page_size: BROWSE_PAGE_SIZE, conversation: browseConversation
  }});
  fetch('/api/browse?' + params)
    .then(r => r.json())
    .then(data => renderBrowseResults(data));
}}

function renderBrowseResults(data) {{
  const panel = document.getElementById('browseMessages');
  const person1 = {json.dumps(self.config.person1_name if hasattr(self.config, 'person1_name') else 'Me')};
  let html = '';

  if (!data.messages || data.messages.length === 0) {{
    html = '<p style="color:#999; padding:40px; text-align:center;">No messages found</p>';
  }} else {{
    data.messages.forEach(m => {{
      if (!m) return;
      const sentClass = (m.sender === person1) ? ' sent' : '';
      html += '<div class="browse-msg' + sentClass + '">'
            + '<button class="flag-btn" onclick="flagFromBrowse(this, \\'' + escapeHtml(m.message_id || '')
            + '\\')">Flag</button>'
            + '<div class="meta">' + escapeHtml(m.timestamp || '')
            + ' &mdash; ' + escapeHtml(m.sender || '')
            + ' &rarr; ' + escapeHtml(m.recipient || '')
            + ' <em style="color:#aaa;">(' + escapeHtml(m.source || '') + ')</em></div>'
            + '<div class="content">' + escapeHtml(m.content || '') + '</div>';
      if (m.attachment_url) {{
        html += '<div class="attachment"><img src="' + escapeHtml(m.attachment_url)
              + '" alt="' + escapeHtml(m.attachment_name || 'photo') + '"></div>';
      }}
      html += '</div>';
    }});
  }}

  panel.innerHTML = html;
  panel.scrollTop = 0;

  // Total
  const totalEl = document.getElementById('browseTotal');
  totalEl.textContent = data.total + ' messages' + (data.conversation ? ' in ' + data.conversation : '')
                       + (data.query ? ' matching search' : '');

  // Pagination
  renderBrowsePagination(data);
}}

function renderBrowsePagination(data) {{
  const pag = document.getElementById('browsePagination');
  if (!data.total_pages || data.total_pages <= 1) {{
    pag.innerHTML = '';
    return;
  }}
  let html = '<button onclick="loadBrowsePage(' + (data.page - 1) + ')"'
           + (data.page <= 0 ? ' disabled' : '') + '>&larr; Prev</button>';
  html += '<span class="page-info">Page ' + (data.page + 1) + ' of ' + data.total_pages + '</span>';
  html += '<button onclick="loadBrowsePage(' + (data.page + 1) + ')"'
        + (data.page >= data.total_pages - 1 ? ' disabled' : '') + '>Next &rarr;</button>';
  pag.innerHTML = html;
}}

function flagFromBrowse(btn, messageId) {{
  if (!messageId) {{ showToast('No message ID'); return; }}
  const notes = prompt('Notes (optional):') || '';
  fetch('/api/browse/flag', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ message_id: messageId, decision: 'relevant', notes: notes }})
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.error) {{ showToast('Error: ' + data.error); return; }}
    showToast('Message flagged as relevant');
    btn.textContent = 'Flagged';
    btn.classList.add('flagged');
    btn.disabled = true;
  }});
}}

// --- Search ---
function executeSearch() {{
  const q = document.getElementById('searchQ').value.trim();
  const sender = document.getElementById('searchSender').value.trim();
  const dateFrom = document.getElementById('searchFrom').value;
  const dateTo = document.getElementById('searchTo').value;

  if (!q && !sender && !dateFrom && !dateTo) {{
    showToast('Enter at least one search criterion');
    return;
  }}

  isSearchActive = true;
  lastSearchParams = {{ q: q, sender: sender, date_from: dateFrom, date_to: dateTo }};
  searchPage(0);
}}

function searchPage(page) {{
  const params = new URLSearchParams({{
    ...lastSearchParams, page: page, page_size: BROWSE_PAGE_SIZE
  }});
  fetch('/api/search?' + params)
    .then(r => r.json())
    .then(data => {{
      renderBrowseResults(data);
    }});
}}

function clearSearch() {{
  isSearchActive = false;
  lastSearchParams = {{}};
  document.getElementById('searchQ').value = '';
  document.getElementById('searchSender').value = '';
  document.getElementById('searchFrom').value = '';
  document.getElementById('searchTo').value = '';
  loadBrowsePage(0);
}}
</script>
</body>
</html>"""
