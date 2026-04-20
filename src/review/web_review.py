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
        self._conversation_cache = None

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

        @self.app.route("/api/complete", methods=["POST"])
        def complete_review():
            if self.forensic:
                self.forensic.record_action(
                    "web_review_completed",
                    f"Web review session completed with {len(self.reviewed_indices)} items reviewed",
                    {"reviewed": len(self.reviewed_indices), "total": len(self.flagged_items)}
                )
            # Signal the main thread to stop waiting; Flask runs in a daemon
            # thread and will terminate automatically when start_review returns.
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
        print(f"    Press Ctrl+C or click 'Complete Review' to finish.\n")

        # Run Flask in a daemon thread so that 'Complete Review' doesn't
        # need to SIGINT the whole process (which kills the parent pipeline).
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

        # Build context window (3 before, flagged, 3 after)
        context_before = []
        context_after = []

        if target_pos is not None:
            start = max(0, target_pos - 3)
            end = min(len(self.messages), target_pos + 4)

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
  .decision-buttons button {{ padding: 10px; border: none; border-radius: 6px; font-size: 14px;
                              font-weight: 600; cursor: pointer; transition: opacity 0.2s; }}
  .decision-buttons button:hover {{ opacity: 0.85; }}
  .btn-relevant {{ background: #43a047; color: #fff; }}
  .btn-not-relevant {{ background: #9e9e9e; color: #fff; }}
  .btn-uncertain {{ background: #ff8f00; color: #fff; }}
  .btn-relevant.selected {{ box-shadow: 0 0 0 3px rgba(67,160,71,0.5); }}
  .btn-not-relevant.selected {{ box-shadow: 0 0 0 3px rgba(158,158,158,0.5); }}
  .btn-uncertain.selected {{ box-shadow: 0 0 0 3px rgba(255,143,0,0.5); }}

  textarea {{ width: 100%; height: 80px; padding: 8px; border: 1px solid #ccc;
              border-radius: 6px; font-size: 13px; resize: vertical; }}

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
    <textarea id="notesField" placeholder="Optional notes about your decision..."></textarea>
    <button class="submit-btn" id="submitBtn" onclick="submitDecision()" disabled>Submit Decision</button>

    <div class="nav">
      <button onclick="navigate(-1)" id="prevBtn">&larr; Previous</button>
      <span class="counter" id="navCounter">-</span>
      <button onclick="navigate(1)" id="nextBtn">Next &rarr;</button>
    </div>

    <button class="complete-btn" onclick="completeReview()">Complete Review</button>
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
  if (!confirm('Complete the review session? The server will shut down.')) return;
  fetch('/api/complete', {{ method: 'POST' }}).then(() => {{
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;'
      + 'font-family:sans-serif;font-size:18px;color:#333;">Review complete. You may close this tab.</div>';
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

// Initial load
fetch('/api/progress').then(r => r.json()).then(updateProgress);
loadItem(0);

// =====================================================================
// Browse mode + Search
// =====================================================================
let browseConversation = '';
let browsePage = 0;
let isSearchActive = false;
let lastSearchParams = {{}};
const BROWSE_PAGE_SIZE = 50;

function switchTab(tab) {{
  const isBrowse = (tab === 'browse');
  document.getElementById('tabFlagged').classList.toggle('active', !isBrowse);
  document.getElementById('tabBrowse').classList.toggle('active', isBrowse);
  document.getElementById('flaggedContainer').style.display = isBrowse ? 'none' : 'flex';
  document.getElementById('browseContainer').style.display = isBrowse ? 'flex' : 'none';
  if (isBrowse) loadConversations();
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
