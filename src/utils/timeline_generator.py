"""
Timeline generation module.
Creates visual timelines for court presentation.
Includes conversation context around flagged messages.
"""

import logging
import html as html_module
from pathlib import Path
from datetime import datetime
import pandas as pd
import pytz

from ..config import Config
from .conversation_threading import ConversationThreader


class TimelineGenerator:
    """Generate visual timelines from message data."""

    def __init__(self, forensic, config: Config = None):
        """Initialize timeline generator."""
        self.config = config if config is not None else Config()
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        self.threader = ConversationThreader()
        self._tz = pytz.timezone(self.config.timezone)

    def create_timeline(self, df: pd.DataFrame, output_path: Path,
                        raw_messages: list = None, extracted_data: dict = None):
        """
        Create HTML timeline visualization.

        Args:
            df: DataFrame with messages (may include analysis columns)
            output_path: Where to save timeline
            raw_messages: Optional flat list of message dicts used for
                conversation context lookup.  When not provided the
                DataFrame is converted to dicts automatically.
            extracted_data: Optional extraction-phase dict.  When provided,
                email messages are included on the timeline alongside
                flagged events.
        """
        if raw_messages is None:
            raw_messages = df.to_dict("records")

        # Create HTML timeline
        html_content = self.generate_html_timeline(df, raw_messages,
                                                   extracted_data=extracted_data)

        with open(output_path, 'w') as f:
            f.write(html_content)

        self.logger.info(f"Generated timeline: {output_path}")

        self.forensic.record_action(
            "TIMELINE_GENERATED",
            f"Timeline created with {len(df)} events"
        )

    def generate_html_timeline(self, df: pd.DataFrame,
                               raw_messages: list = None,
                               extracted_data: dict = None) -> str:
        """Generate HTML timeline content with conversation context.

        Args:
            df: DataFrame with messages and analysis columns.
            raw_messages: Flat list of message dicts for context lookup.
            extracted_data: Extraction-phase dict.  When provided, all email
                messages are added to the timeline alongside flagged events.
        """
        if raw_messages is None:
            raw_messages = df.to_dict("records")

        events = []

        # Pre-compute conversations once for all context lookups
        conversations = self.threader.group_into_conversations(raw_messages) if raw_messages else None

        # Build filter for significant events
        # Use index=df.index so the fallback Series aligns with a non-default index
        filter_mask = (df.get('threat_detected', pd.Series(False, index=df.index)) == True) | \
                      (df.get('patterns_detected', pd.Series('', index=df.index)) != '')

        # Add sentiment filter only if column exists
        if 'sentiment_score' in df.columns:
            filter_mask = filter_mask | (df['sentiment_score'].abs() > 0.7)

        # Focus on significant events
        significant_df = df[filter_mask]

        for _, row in significant_df.iterrows():
            # Build conversation context for this flagged message
            context_html = ""
            msg_id = row.get("message_id")
            if msg_id and raw_messages:
                context = self.threader.get_message_context(
                    raw_messages, str(msg_id), window=3,
                    conversations=conversations,
                )
                context_html = self._render_context_html(context)

            event = {
                'date': self._format_local_ts(row['timestamp']),
                'content': row.get('content', '')[:100],
                'type': self.determine_event_type(row),
                'sender': row.get('sender', 'Unknown'),
                'context_html': context_html,
                'subject': '',
            }
            events.append(event)

        # --- Email communications (case chronology context) ---
        # All emails are included because they are low-volume and each is
        # purposeful.  Third-party emails (counselors, attorneys, family)
        # provide crucial corroboration for court chronologies.
        if extracted_data:
            mapped_persons = set(self.config.contact_mappings.keys())
            for msg in extracted_data.get('messages', []):
                if msg.get('source') != 'email':
                    continue
                sender = msg.get('sender', '')
                recipient = msg.get('recipient', '')
                is_third_party = sender not in mapped_persons or recipient not in mapped_persons
                event_type = 'third-party-email' if is_third_party else 'email'
                subject = msg.get('subject', '')
                events.append({
                    'date': self._format_local_ts(msg.get('timestamp')),
                    'content': (msg.get('content', '') or '')[:100],
                    'type': event_type,
                    'sender': sender,
                    'context_html': '',
                    'subject': subject,
                })

        # Sort by date
        events.sort(key=lambda x: x['date'])

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Forensic Timeline</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .timeline {{ position: relative; padding: 20px 0; }}
                .event {{ margin: 20px 0; padding: 15px; border-left: 3px solid #007bff; }}
                .threat {{ border-color: #dc3545; background: #f8d7da; }}
                .pattern {{ border-color: #ffc107; background: #fff3cd; }}
                .sentiment {{ border-color: #17a2b8; background: #d1ecf1; }}
                .email {{ border-color: #6f42c1; background: #f3e8ff; }}
                .third-party-email {{ border-color: #e83e8c; background: #fce4ec; }}
                .date {{ font-weight: bold; color: #666; }}
                .content {{ margin-top: 5px; }}
                .sender {{ font-style: italic; color: #999; }}
                .context-block {{
                    margin-top: 10px;
                    padding: 8px 12px;
                    background: #f9f9f9;
                    border: 1px solid #e0e0e0;
                    border-radius: 4px;
                    font-size: 0.9em;
                }}
                .context-block .ctx-header {{
                    font-weight: bold;
                    margin-bottom: 6px;
                    color: #555;
                }}
                .context-block .ctx-msg {{
                    padding: 3px 0;
                    color: #444;
                }}
                .context-block .ctx-msg.target {{
                    font-weight: bold;
                    color: #000;
                    background: #fff3cd;
                    padding: 3px 6px;
                    border-radius: 3px;
                }}
                .context-block .ctx-sender {{
                    font-weight: 600;
                    color: #666;
                }}
            </style>
        </head>
        <body>
            <h1>Forensic Analysis Timeline</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total significant events: {len(events)}</p>
            <div class="timeline">
        """

        for event in events:
            context_section = event.get('context_html', '')
            safe_sender = html_module.escape(str(event['sender']))
            safe_content = html_module.escape(str(event['content']))
            subject = event.get('subject', '')
            subject_html = ''
            if subject:
                safe_subject = html_module.escape(subject)
                subject_html = f'<div class="content" style="font-weight:bold;">Subject: {safe_subject}</div>'
            html += f"""
                <div class="event {event['type']}">
                    <div class="date">{event['date']}</div>
                    <div class="sender">From: {safe_sender}</div>
                    {subject_html}
                    <div class="content">{safe_content}...</div>
                    {context_section}
                </div>
            """

        html += """
            </div>
        </body>
        </html>
        """

        return html

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _render_context_html(self, context: dict) -> str:
        """
        Render conversation context around a flagged message as an HTML
        snippet that can be embedded inside a timeline event div.

        Args:
            context: Dict returned by ConversationThreader.get_message_context

        Returns:
            HTML string (empty string when there is no useful context).
        """
        if not context or context.get("target") is None:
            return ""

        before = context.get("before", [])
        after = context.get("after", [])

        # Only render when there is at least one surrounding message
        if not before and not after:
            return ""

        lines: list = []
        lines.append('<div class="context-block">')
        conv_key = html_module.escape(context.get("conversation_key", ""))
        total = context.get("total_in_conversation", 0)
        lines.append(
            f'<div class="ctx-header">Conversation context '
            f'({conv_key} &mdash; {total} messages total):</div>'
        )

        def _msg_line(msg, is_target=False):
            sender = html_module.escape(str(msg.get("sender", "?")))
            content = html_module.escape(str(msg.get("content", ""))[:120])
            ts = html_module.escape(self._format_local_ts(msg.get("timestamp", "")))
            cls = ' target' if is_target else ''
            return (
                f'<div class="ctx-msg{cls}">'
                f'<span class="ctx-sender">[{ts}] {sender}:</span> {content}'
                f'</div>'
            )

        for m in before:
            lines.append(_msg_line(m))

        lines.append(_msg_line(context["target"], is_target=True))

        for m in after:
            lines.append(_msg_line(m))

        lines.append('</div>')
        return "\n".join(lines)

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

    def determine_event_type(self, row) -> str:
        """Determine CSS class for event type."""
        if row.get('threat_detected'):
            return 'threat'
        elif row.get('patterns_detected'):
            return 'pattern'
        score = row.get('sentiment_score')
        if score is not None and abs(score) > 0.7:
            return 'sentiment'
        return ''