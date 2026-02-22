"""
Flask-based web review interface for forensic message analysis.

Provides a browser-based UI for reviewing flagged messages with context,
screenshots, and decision tracking. All decisions maintain forensic integrity
via ManualReviewManager and ForensicRecorder.
"""

import os
import signal
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from ..config import Config
from .manual_review_manager import ManualReviewManager
from ..utils.conversation_threading import ConversationThreader

try:
    from flask import Flask, jsonify, request, send_from_directory
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

logger = logging.getLogger(__name__)

config = Config()


class WebReview:
    """
    Web-based review interface for flagged forensic evidence.

    Wraps a Flask application that serves a single-page review interface.
    All review decisions are persisted through ManualReviewManager and
    logged through ForensicRecorder for chain of custody.
    """

    def __init__(self, review_manager: ManualReviewManager, forensic_recorder=None):
        """
        Initialize web review.

        Args:
            review_manager: ManualReviewManager instance for persisting decisions.
            forensic_recorder: Optional ForensicRecorder for chain of custody logging.
        """
        if not FLASK_AVAILABLE:
            raise ImportError(
                "Flask is required for web review. Install with: pip install Flask>=3.0.0"
            )

        self.review_manager = review_manager
        self.forensic = forensic_recorder
        self.threader = ConversationThreader()
        self.messages: List[Dict] = []
        self.flagged_items: List[Dict] = []
        self.screenshots: List[Dict] = []
        self.reviewed_indices: set = set()

        # Build Flask app
        self.app = Flask(__name__)
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
            screenshot_dir = config.screenshot_source_dir
            if screenshot_dir and Path(screenshot_dir).is_dir():
                return send_from_directory(screenshot_dir, filename)
            return ("Screenshot not found", 404)

        @self.app.route("/api/complete", methods=["POST"])
        def complete_review():
            if self.forensic:
                self.forensic.record_action(
                    "web_review_completed",
                    f"Web review session completed with {len(self.reviewed_indices)} items reviewed",
                    {"reviewed": len(self.reviewed_indices), "total": len(self.flagged_items)}
                )
            # Shut down Flask
            func = request.environ.get("werkzeug.server.shutdown")
            if func:
                func()
            else:
                os.kill(os.getpid(), signal.SIGINT)
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

        self.app.run(host="127.0.0.1", port=port, debug=False)

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

        # Fallback: partial match
        if target_msg is None and item_content:
            for i, msg in enumerate(self.messages):
                if item_content[:50] in msg.get("content", ""):
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
                "case_number": config.case_number,
                "case_name": config.case_name,
                "examiner": config.examiner_name,
            },
        }

    def _submit_decision(self, data: Dict) -> Dict:
        """Save a review decision."""
        index = data.get("index")
        decision = data.get("decision")
        notes = data.get("notes", "")

        if decision not in ("relevant", "not_relevant", "uncertain"):
            return {"error": "Invalid decision value"}

        if index is None or index < 0 or index >= len(self.flagged_items):
            return {"error": "Invalid item index"}

        item = self.flagged_items[index]
        item_id = item.get("id", f"item_{index}")

        # Add the review
        self.review_manager.add_review(
            item_id=item_id,
            item_type=item.get("type", "threat"),
            decision=decision,
            notes=notes,
        )

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
                    "timestamp": str(ss_ts),
                })

        return associated

    @staticmethod
    def _serialise_msg(msg: Optional[Dict]) -> Optional[Dict]:
        """Return a JSON-safe subset of a message dict."""
        if msg is None:
            return None
        return {
            "message_id": msg.get("message_id"),
            "sender": msg.get("sender", "Unknown"),
            "recipient": msg.get("recipient", "Unknown"),
            "content": msg.get("content", ""),
            "timestamp": str(msg.get("timestamp", "")),
            "source": msg.get("source", ""),
        }

    # ------------------------------------------------------------------
    # HTML template
    # ------------------------------------------------------------------

    def _render_review_page(self) -> str:
        """Return the single-page review interface HTML."""
        case_number = config.case_number or ""
        case_name = config.case_name or ""
        examiner = config.examiner_name or ""
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
  .container {{ display: flex; height: calc(100vh - 68px); }}
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

<div class="container">
  <!-- Left: Message context -->
  <div class="context-panel" id="contextPanel">
    <p style="color:#999; padding-top:40px; text-align:center;">Loading...</p>
  </div>

  <!-- Right: Decision panel -->
  <div class="decision-panel">
    <div id="existingReview"></div>

    <div class="item-details" id="itemDetails">
      <h2>Item Details</h2>
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
  const cls = isFlagged ? 'msg flagged'
              : (m.sender === 'Me' ? 'msg sent' : 'msg received');
  let html = '<div class="' + cls + '">';
  if (isFlagged) html += '<span class="flag-label">FLAGGED</span>';
  html += '<div class="meta">' + escapeHtml(m.timestamp || '') + ' &mdash; '
        + escapeHtml(m.sender || '') + ' &rarr; ' + escapeHtml(m.recipient || '') + '</div>';
  html += '<div class="content">' + escapeHtml(m.content || '') + '</div>';
  html += '</div>';
  return html;
}}

function renderDetails(data) {{
  const item = data.item || {{}};
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
</script>
</body>
</html>"""
