"""
Chat-bubble HTML reporter — iMessage-style conversation view.

Renders messages as chat bubbles with tapback reactions, inline images,
source badges, threat highlighting, and per-person conversation sections.
"""

import base64
import io
import logging
import pytz
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Dict, List, Optional

from PIL import Image

from ..config import Config
from ..forensic_utils import ForensicRecorder
from ..utils.legal_compliance import LegalComplianceManager

logger = logging.getLogger(__name__)

# Image handling constants (match html_reporter.py)
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.heic', '.webp', '.tiff', '.bmp'}
_HTML_IMG_MAX_DIM = 800
_HTML_IMG_JPEG_QUALITY = 70
_MIME_MAP = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.png': 'image/png', '.gif': 'image/gif',
    '.webp': 'image/webp', '.tiff': 'image/tiff',
    '.bmp': 'image/bmp', '.heic': 'image/heic',
}

# Tapback type codes from iMessage
_TAPBACK_MAP = {
    2000: '\u2764\ufe0f',   # love
    2001: '\U0001f44d',     # like
    2002: '\U0001f44e',     # dislike
    2003: '\U0001f602',     # laugh
    2004: '\u203c\ufe0f',   # emphasis
    2005: '\u2753',         # question
    3000: '',  # remove love
    3001: '',  # remove like
    3002: '',  # remove dislike
    3003: '',  # remove laugh
    3004: '',  # remove emphasis
    3005: '',  # remove question
}


def _b64_img(path_str: str) -> Optional[str]:
    """Return a resized data-URI for an image file, or None if unreadable."""
    p = Path(path_str)
    if not p.is_file():
        return None
    suffix = p.suffix.lower()
    if suffix not in IMAGE_EXTENSIONS:
        return None
    mime = _MIME_MAP.get(suffix, 'application/octet-stream')
    try:
        img = Image.open(p)
        orig_format = img.format or 'PNG'
        if max(img.size) > _HTML_IMG_MAX_DIM:
            img.thumbnail((_HTML_IMG_MAX_DIM, _HTML_IMG_MAX_DIM), Image.LANCZOS)
        buf = io.BytesIO()
        if orig_format.upper() in ('JPEG', 'JPG'):
            if img.mode not in ('RGB', 'L'):
                img = img.convert('RGB')
            img.save(buf, format='JPEG', quality=_HTML_IMG_JPEG_QUALITY, optimize=True)
        else:
            img.save(buf, format=orig_format, optimize=True)
        encoded = base64.b64encode(buf.getvalue()).decode('ascii')
        return f"data:{mime};base64,{encoded}"
    except Exception:
        try:
            data = p.read_bytes()
            encoded = base64.b64encode(data).decode('ascii')
            return f"data:{mime};base64,{encoded}"
        except Exception:
            return None


_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       margin: 0; padding: 0; background: #e5ddd5; color: #111; }
.header { background: #075e54; color: #fff; padding: 20px 24px; }
.header h1 { margin: 0 0 4px; font-size: 22px; }
.header .meta { font-size: 13px; opacity: 0.85; }
.findings-index { background: #fff; margin: 16px; padding: 16px; border-radius: 8px;
                  box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
.findings-index h2 { margin: 0 0 10px; font-size: 16px; }
.findings-index ul { margin: 0; padding-left: 20px; }
.findings-index li { margin-bottom: 4px; }
.findings-index a { color: #075e54; text-decoration: none; }
.findings-index a:hover { text-decoration: underline; }
.person-section { margin: 16px; }
.person-header { background: #075e54; color: #fff; padding: 12px 16px; border-radius: 8px 8px 0 0;
                 font-size: 17px; font-weight: 600; }
.conversation { background: #ece5dd; padding: 12px 16px; border-radius: 0 0 8px 8px; }
.date-separator { text-align: center; margin: 16px 0 8px; }
.date-separator span { background: #d4cfc6; color: #555; font-size: 12px; padding: 4px 12px;
                       border-radius: 8px; }
.msg { margin-bottom: 6px; padding: 8px 12px; border-radius: 8px; max-width: 75%;
       font-size: 14px; line-height: 1.45; position: relative; clear: both;
       box-shadow: 0 1px 1px rgba(0,0,0,0.08); }
.msg.sent { background: #dcf8c6; margin-left: auto; float: right; }
.msg.received { background: #fff; float: left; }
.msg.threat { border: 2px solid #e65100; background: #fff3cd; }
.msg::after { content: ''; display: block; clear: both; }
.msg .bubble-meta { font-size: 11px; color: #757575; margin-bottom: 3px; }
.msg .bubble-content { word-wrap: break-word; white-space: pre-wrap; }
.msg .bubble-time { font-size: 10px; color: #999; text-align: right; margin-top: 2px; }
.msg .attachment-img { max-width: 100%; max-height: 300px; border-radius: 6px; margin-top: 4px;
                       border: 1px solid #ccc; }
.msg .attachment-placeholder { color: #888; font-style: italic; margin-top: 4px; font-size: 13px; }
.source-badge { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 4px;
                margin-left: 6px; vertical-align: middle; }
.source-badge.imessage { background: #34b7f1; color: #fff; }
.source-badge.sms { background: #25d366; color: #fff; }
.source-badge.whatsapp { background: #25d366; color: #fff; }
.source-badge.email { background: #6c757d; color: #fff; }
.source-badge.teams { background: #6264a7; color: #fff; }
.source-badge.default { background: #adb5bd; color: #fff; }
.flag-badge { display: inline-block; font-size: 10px; font-weight: 600; padding: 1px 6px;
              border-radius: 4px; margin-left: 4px; vertical-align: middle; }
.flag-badge.sos { background: #dc3545; color: #fff; }
.flag-badge.edited { background: #0d6efd; color: #fff; }
.flag-badge.unsent { background: #6c757d; color: #fff; }
.flag-badge.deleted { background: #dc3545; color: #fff; }
.flag-badge.sms-fallback { background: #fd7e14; color: #fff; }
.tapbacks { margin-top: 2px; }
.tapbacks span { font-size: 16px; margin-right: 2px; }
.reply-indicator { font-size: 11px; color: #6c757d; font-style: italic; margin-bottom: 4px;
                   border-left: 2px solid #adb5bd; padding-left: 6px; }
.edit-history { margin-top: 6px; padding: 6px 8px; background: #f8f9fa;
               border-left: 3px solid #dee2e6; font-size: 12px; }
.edit-history-label { font-weight: bold; color: #6c757d; margin-bottom: 2px; }
.edit-entry { color: #495057; margin: 2px 0; }
.edit-ts { color: #adb5bd; font-size: 11px; }
.clearfix::after { content: ''; display: table; clear: both; }
.empty-section { padding: 24px; text-align: center; color: #888; font-style: italic; }
.legal-notice { background: #f8f9fa; padding: 16px 24px; font-size: 11px; color: #6c757d;
                border-top: 1px solid #dee2e6; margin-top: 24px; }
"""


class ChatReporter:
    """Generate iMessage-style chat-bubble HTML report."""

    def __init__(self, forensic_recorder: ForensicRecorder, config: Config = None):
        self.config = config if config is not None else Config()
        self.forensic = forensic_recorder
        self.person1 = getattr(self.config, 'person1_name', 'Me')
        self._tz = pytz.timezone(self.config.timezone)

    def generate_report(self, extracted_data: Dict, analysis_results: Dict,
                        review_decisions: Dict, output_path: Path) -> Dict[str, Path]:
        """Generate chat-bubble HTML report.

        Args:
            extracted_data: Extracted data dict with 'messages' key.
            analysis_results: Analysis results dict.
            review_decisions: Review decisions dict.
            output_path: Base path (without extension) for the output file.

        Returns:
            Dict mapping format name to file path, e.g. {'chat_html': Path(...)}.
        """
        try:
            html_path = Path(str(output_path) + '_chat.html')
            messages = extracted_data.get('messages', [])
            threats = analysis_results.get('threats', {}).get('details', [])
            threat_ids = self._build_threat_set(threats)
            tapback_map = self._build_tapback_map(messages)

            mapped_persons = list(self.config.contact_mappings.keys())
            persons = sorted(p for p in mapped_persons if p != self.person1)

            # Build findings index for top-of-page anchors
            flagged = self._collect_flagged(messages, threat_ids)

            compliance = LegalComplianceManager(config=self.config, forensic_recorder=self.forensic)

            html_parts = [
                '<!DOCTYPE html>',
                '<html lang="en"><head>',
                '<meta charset="UTF-8">',
                '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
                f'<title>Forensic Chat Report — {escape(self.config.case_name or "")}</title>',
                f'<style>{_CSS}</style>',
                '</head><body>',
                self._render_header(messages, compliance),
            ]

            if flagged:
                html_parts.append(self._render_findings_index(flagged))

            for person in persons:
                person_msgs = [
                    m for m in messages
                    if m.get('sender') == person or m.get('recipient') == person
                ]
                html_parts.append(self._render_person_section(
                    person, person_msgs, threat_ids, tapback_map
                ))

            html_parts.append(self._render_footer(compliance))
            html_parts.append('</body></html>')

            html_content = '\n'.join(html_parts)
            html_path.write_text(html_content, encoding='utf-8')

            file_hash = self.forensic.compute_hash(html_path)
            self.forensic.record_action(
                "chat_report_generated",
                f"Generated chat-bubble HTML report with hash {file_hash}",
                {"path": str(html_path), "hash": file_hash}
            )

            logger.info(f"Chat report generated: {html_path}")
            return {'chat_html': html_path}

        except Exception as e:
            logger.error(f"Failed to generate chat report: {e}")
            raise

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_threat_set(self, threats) -> set:
        """Build a set of message_ids that have threats detected."""
        ids = set()
        if isinstance(threats, list):
            for item in threats:
                if isinstance(item, dict) and item.get('threat_detected'):
                    mid = item.get('message_id')
                    if mid:
                        ids.add(str(mid))
        return ids

    def _build_tapback_map(self, messages: List[Dict]) -> Dict[str, List[Dict]]:
        """Build guid → [tapback messages] lookup."""
        tapbacks: Dict[str, List[Dict]] = {}
        for m in messages:
            if not m.get('is_tapback'):
                continue
            assoc = m.get('associated_message_guid', '')
            if not assoc:
                continue
            # Strip the p:N/ prefix to get the actual guid
            parts = assoc.split('/')
            guid = parts[-1] if parts else assoc
            if guid:
                tapbacks.setdefault(guid, []).append(m)
        return tapbacks

    def _collect_flagged(self, messages: List[Dict], threat_ids: set) -> List[Dict]:
        """Collect messages that are flagged (threat, SOS, etc.) for the index."""
        flagged = []
        for m in messages:
            mid = str(m.get('message_id', ''))
            is_threat = mid in threat_ids
            is_sos = m.get('is_sos', False)
            if is_threat or is_sos:
                flagged.append({
                    'message_id': mid,
                    'timestamp': m.get('timestamp', ''),
                    'sender': m.get('sender', ''),
                    'content': (m.get('content', '') or '')[:80],
                    'type': 'SOS' if is_sos else 'Threat',
                })
        return flagged

    def _format_ts(self, ts) -> str:
        """Format timestamp to local display string."""
        if not ts:
            return ''
        try:
            import pandas as pd
            parsed = pd.to_datetime(ts, utc=True)
            if pd.isna(parsed):
                return ''
            return parsed.tz_convert(self._tz).strftime('%I:%M %p')
        except Exception:
            return str(ts)

    def _format_date(self, ts) -> str:
        """Format timestamp to date string for separators."""
        if not ts:
            return ''
        try:
            import pandas as pd
            parsed = pd.to_datetime(ts, utc=True)
            if pd.isna(parsed):
                return ''
            return parsed.tz_convert(self._tz).strftime('%B %d, %Y')
        except Exception:
            return ''

    def _source_badge(self, source: str) -> str:
        """Render a source badge HTML."""
        s = (source or '').lower()
        if 'imessage' in s:
            cls, label = 'imessage', 'iMessage'
        elif 'sms' in s:
            cls, label = 'sms', 'SMS'
        elif 'whatsapp' in s:
            cls, label = 'whatsapp', 'WhatsApp'
        elif 'email' in s:
            cls, label = 'email', 'Email'
        elif 'teams' in s:
            cls, label = 'teams', 'Teams'
        else:
            cls, label = 'default', escape(source or 'Unknown')
        return f'<span class="source-badge {cls}">{label}</span>'

    def _flag_badges(self, msg: Dict) -> str:
        """Render flag badges for special message types."""
        badges = []
        if msg.get('is_sos'):
            badges.append('<span class="flag-badge sos">SOS</span>')
        if msg.get('is_recently_deleted'):
            badges.append('<span class="flag-badge deleted">Deleted</span>')
        if msg.get('date_edited'):
            badges.append('<span class="flag-badge edited">Edited</span>')
        if msg.get('date_retracted'):
            badges.append('<span class="flag-badge unsent">Unsent</span>')
        if msg.get('was_downgraded'):
            badges.append('<span class="flag-badge sms-fallback">SMS</span>')
        return ' '.join(badges)

    def _render_tapbacks(self, msg: Dict, tapback_map: Dict) -> str:
        """Render tapback emojis for a message."""
        guid = msg.get('guid', '')
        if not guid or guid not in tapback_map:
            return ''
        reactions = tapback_map[guid]
        emojis = []
        for r in reactions:
            tapback_type = r.get('tapback_type', 0)
            emoji = _TAPBACK_MAP.get(tapback_type, '')
            if emoji:
                emojis.append(emoji)
        if not emojis:
            return ''
        emoji_html = ''.join(f'<span>{e}</span>' for e in emojis)
        return f'<div class="tapbacks">{emoji_html}</div>'

    def _render_message(self, msg: Dict, threat_ids: set,
                        tapback_map: Dict) -> str:
        """Render a single message as a chat bubble."""
        mid = str(msg.get('message_id', ''))
        sender = msg.get('sender', '')
        is_sent = (sender == self.person1)
        is_threat = mid in threat_ids
        is_tapback = msg.get('is_tapback', False)

        # Skip tapback messages — they're rendered on the referenced message
        if is_tapback:
            return ''

        css_class = 'msg sent' if is_sent else 'msg received'
        if is_threat:
            css_class = 'msg threat'

        parts = [f'<div class="{css_class}" id="msg-{escape(mid)}">']

        # Reply indicator
        reply_to = msg.get('thread_originator_guid', '')
        if reply_to:
            parts.append(f'<div class="reply-indicator">Reply to message</div>')

        # Meta line: sender + source badge + flag badges
        source_html = self._source_badge(msg.get('source', ''))
        flags_html = self._flag_badges(msg)
        meta_parts = [f'<strong>{escape(sender)}</strong>', source_html]
        if flags_html:
            meta_parts.append(flags_html)
        parts.append(f'<div class="bubble-meta">{" ".join(meta_parts)}</div>')

        # Content
        content = msg.get('content', '') or ''
        if msg.get('is_unsent'):
            content = '[Message unsent]'
        parts.append(f'<div class="bubble-content">{escape(content)}</div>')

        # Edit history (show original and intermediate versions)
        edit_history = msg.get('edit_history', [])
        if edit_history and len(edit_history) > 1:
            parts.append('<div class="edit-history">')
            parts.append('<div class="edit-history-label">Edit history:</div>')
            for i, edit in enumerate(edit_history[:-1]):
                label = 'Original' if i == 0 else f'Edit {i}'
                ts_str = ''
                if edit.get('timestamp'):
                    ts_str = f' <span class="edit-ts">({edit["timestamp"]})</span>'
                content_text = escape(edit.get('content', ''))
                parts.append(f'<div class="edit-entry"><strong>{label}:</strong>{ts_str} {content_text}</div>')
            parts.append('</div>')

        # Inline image or attachment placeholder
        att_path = msg.get('attachment', '')
        if att_path:
            data_uri = _b64_img(att_path)
            if data_uri:
                parts.append(
                    f'<img class="attachment-img" src="{data_uri}" '
                    f'alt="{escape(Path(att_path).name)}">'
                )
            else:
                fname = Path(att_path).name if att_path else 'file'
                parts.append(
                    f'<div class="attachment-placeholder">'
                    f'[Attachment: {escape(fname)}]</div>'
                )

        # Shared location display
        if msg.get('is_shared_location'):
            loc_name = escape(msg.get('location_name', ''))
            loc_addr = escape(msg.get('location_address', ''))
            loc_parts = [p for p in [loc_name, loc_addr] if p]
            if loc_parts:
                parts.append(
                    f'<div style="margin-top:4px;padding:4px 6px;background:#e8f5e9;'
                    f'border-left:3px solid #4caf50;font-size:12px;">'
                    f'<strong>Shared Location:</strong> {" — ".join(loc_parts)}</div>'
                )

        # URL preview display
        elif msg.get('rich_link_title'):
            title = escape(msg.get('rich_link_title', ''))
            url = escape(msg.get('rich_link_url', ''))
            site = escape(msg.get('rich_link_site_name', ''))
            site_display = f' ({site})' if site else ''
            parts.append(
                f'<div style="margin-top:4px;padding:4px 6px;background:#e3f2fd;'
                f'border-left:3px solid #2196f3;font-size:12px;">'
                f'<strong>{title}</strong>{site_display}'
                f'{f"<br><span style=color:#666>{url}</span>" if url else ""}</div>'
            )

        # Tapbacks
        tapback_html = self._render_tapbacks(msg, tapback_map)
        if tapback_html:
            parts.append(tapback_html)

        # Timestamp
        time_str = self._format_ts(msg.get('timestamp'))
        if time_str:
            parts.append(f'<div class="bubble-time">{escape(time_str)}</div>')

        parts.append('</div>')
        parts.append('<div class="clearfix"></div>')
        return '\n'.join(parts)

    def _render_person_section(self, person: str, messages: List[Dict],
                               threat_ids: set, tapback_map: Dict) -> str:
        """Render a complete conversation section for one person."""
        parts = [
            '<div class="person-section">',
            f'<div class="person-header">{escape(person)}</div>',
            '<div class="conversation">',
        ]

        if not messages:
            parts.append('<div class="empty-section">No messages found for this contact</div>')
        else:
            # Sort messages chronologically
            sorted_msgs = sorted(messages, key=lambda m: m.get('timestamp', '') or '')
            current_date = None

            for msg in sorted_msgs:
                msg_date = self._format_date(msg.get('timestamp'))
                if msg_date and msg_date != current_date:
                    current_date = msg_date
                    parts.append(
                        f'<div class="date-separator"><span>{escape(msg_date)}</span></div>'
                    )
                bubble = self._render_message(msg, threat_ids, tapback_map)
                if bubble:
                    parts.append(bubble)

        parts.append('</div></div>')
        return '\n'.join(parts)

    def _render_header(self, messages: List[Dict], compliance: LegalComplianceManager) -> str:
        """Render the page header."""
        case_name = escape(self.config.case_name or 'Forensic Message Analysis')
        msg_count = len(messages)
        report_ts = compliance.format_timestamp()
        return (
            '<div class="header">'
            f'<h1>{case_name}</h1>'
            f'<div class="meta">Chat Conversation Report &mdash; '
            f'{msg_count:,} messages &mdash; Generated {escape(report_ts)}</div>'
            '</div>'
        )

    def _render_findings_index(self, flagged: List[Dict]) -> str:
        """Render the findings index at the top of the page."""
        items = []
        for f in flagged:
            mid = escape(f['message_id'])
            ts = escape(str(f['timestamp'])[:19])
            sender = escape(f['sender'])
            content = escape(f['content'])
            ftype = escape(f['type'])
            items.append(
                f'<li><a href="#msg-{mid}">[{ftype}] {ts} — {sender}: {content}</a></li>'
            )
        return (
            '<div class="findings-index">'
            '<h2>Flagged Messages</h2>'
            f'<ul>{"".join(items)}</ul>'
            '</div>'
        )

    def _render_footer(self, compliance: LegalComplianceManager) -> str:
        """Render the legal notice footer."""
        return (
            '<div class="legal-notice">'
            '<strong>Confidential — Attorney Work Product</strong><br>'
            'This report was generated by Forensic Message Analyzer for use in legal proceedings. '
            'Message content is presented as extracted from source databases. '
            'All timestamps have been converted to local timezone for readability. '
            f'Report generated: {escape(compliance.format_timestamp())}'
            '</div>'
        )
