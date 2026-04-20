"""
Excel report generation for forensic analysis results.
"""

import pandas as pd
import pytz
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import logging

from ..config import Config
from ..forensic_utils import ForensicRecorder
from ..utils.conversation_threading import ConversationThreader
from ..utils.legal_compliance import LegalComplianceManager
from .report_utils import match_quote_to_message

logger = logging.getLogger(__name__)


class ExcelReporter:
    """Generate Excel reports with multiple sheets for different analysis aspects."""

    def __init__(self, forensic_recorder: ForensicRecorder, config: Config = None):
        """Initialize Excel reporter."""
        self.config = config if config is not None else Config()
        self.forensic = forensic_recorder
        self.output_dir = Path(self.config.output_dir)

    def _format_local_timestamp(self, ts) -> str:
        """Convert a timestamp value to local timezone string for display."""
        if ts is None:
            return ''
        try:
            parsed = pd.to_datetime(ts, utc=True)
            if pd.isna(parsed):
                return ''
            tz = pytz.timezone(self.config.timezone)
            return parsed.tz_convert(tz).strftime('%Y-%m-%d %H:%M:%S %Z')
        except Exception:
            return str(ts)

    @staticmethod
    def _lookup_review_decision(item_id: str, review_decisions: Dict) -> str:
        """Look up the review decision for a given item ID."""
        reviews = review_decisions.get('reviews', [])
        for review in reviews:
            if isinstance(review, dict) and review.get('item_id') == item_id:
                return review.get('decision', '')
        return ''
    
    def generate_report(self, extracted_data: Dict, analysis_results: Dict,
                       review_decisions: Dict, output_path: Path) -> Path:
        """Generate comprehensive Excel report organized by person."""
        try:
            # Get mapped persons from config
            mapped_persons = list(self.config.contact_mappings.keys())
            
            # Calculate filtered message count for overview
            filtered_message_count = 0
            if 'messages' in extracted_data:
                df_messages = pd.DataFrame(extracted_data['messages'])
                if 'sender' in df_messages.columns and 'recipient' in df_messages.columns:
                    mapped_mask = (
                        df_messages['sender'].isin(mapped_persons) |
                        df_messages['recipient'].isin(mapped_persons)
                    )
                    filtered_message_count = mapped_mask.sum()
                else:
                    filtered_message_count = len(df_messages)
            
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                # Overview sheet - pass filtered count
                overview_data = extracted_data.copy()
                overview_data['total_messages'] = filtered_message_count
                self._write_overview_sheet(writer, overview_data, analysis_results, review_decisions)

                # Findings Summary — generated whenever ANY findings exist
                self._write_findings_summary_sheet(
                    writer, analysis_results, review_decisions,
                    messages=extracted_data.get('messages', [])
                )

                # Timeline of key events
                self._write_timeline_sheet(
                    writer, extracted_data, analysis_results
                )

                # Get messages DataFrame
                if 'messages' in extracted_data:
                    df_messages = pd.DataFrame(extracted_data['messages'])

                    # Create a tab for every mapped person except person1.
                    # Always create the tab even if zero messages match (documents
                    # absence of communication, which is itself evidence).
                    person1 = getattr(self.config, 'person1_name', None)
                    persons = sorted(
                        p for p in mapped_persons if p != person1
                    )

                    for person in persons:
                        self._write_person_sheet(
                            writer,
                            df_messages,
                            analysis_results,
                            person
                        )
                    
                    # NOTE: We decided NOT to publish all messages
                    # Only person-specific tabs are included for privacy

                    # Conversation Threads sheet
                    self._write_conversation_threads_sheet(
                        writer, extracted_data.get('messages', [])
                    )

                # Manual Review sheet.
                # Put source/method/reviewer up front so a reader can tell at a glance which decisions originated from deterministic pattern matching vs AI screening and who confirmed them.
                if 'reviews' in review_decisions and review_decisions['reviews']:
                    df_reviews = pd.DataFrame(review_decisions['reviews'])
                    preferred = [
                        "timestamp", "reviewer", "item_id", "item_type",
                        "source", "method", "decision", "notes",
                        "amended", "supersedes", "superseded_by", "session_id",
                    ]
                    cols = [c for c in preferred if c in df_reviews.columns]
                    cols += [c for c in df_reviews.columns if c not in cols]
                    df_reviews = df_reviews.reindex(columns=cols)
                    df_reviews.to_excel(writer, sheet_name='Manual Review', index=False)

                # Third Party Contacts sheet
                self._write_third_party_contacts_sheet(
                    writer, extracted_data.get('third_party_contacts', [])
                )
            
            # Record generation
            file_hash = self.forensic.compute_hash(output_path)
            self.forensic.record_action(
                "excel_report_generated",
                f"Generated Excel report with hash {file_hash}",
                {"path": str(output_path), "hash": file_hash}
            )
            
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate Excel report: {e}")
            raise
    
    def _write_person_sheet(self, writer, df_messages: pd.DataFrame, 
                           analysis_results: Dict, person_name: str):
        """
        Write a sheet for a specific person with their messages, threats, and sentiment.
        
        Args:
            writer: Excel writer object
            df_messages: Full messages DataFrame
            analysis_results: Analysis results dictionary
            person_name: Name of the person for this sheet
        """
        # Filter messages for this person (where they are sender OR recipient)
        person_messages = df_messages[
            (df_messages['recipient'] == person_name) |
            (df_messages['sender'] == person_name)
        ].copy()

        # Create sheet name (Excel limits to 31 characters and disallows certain characters)
        # Remove invalid characters: : \ / ? * [ ]
        sheet_name = person_name[:31]
        invalid_chars = [':', '\\', '/', '?', '*', '[', ']']
        for char in invalid_chars:
            sheet_name = sheet_name.replace(char, '_')

        if person_messages.empty:
            # Create empty sheet with header row to document absence of messages
            empty_df = pd.DataFrame(columns=['Timestamp', 'Sender', 'Recipient', 'Content', 'Source'])
            empty_df.to_excel(writer, sheet_name=sheet_name, index=False)
            logger.info(f"Created empty sheet '{sheet_name}' (no messages for this contact)")
            return
        
        # Threat columns might already be in the messages DataFrame from analysis
        # No need to merge separately
        
        # Add sentiment information if available
        if 'sentiment' in analysis_results:
            sentiment_df = pd.DataFrame(analysis_results['sentiment'])
            if not sentiment_df.empty and 'message_id' in sentiment_df.columns and 'message_id' in person_messages.columns:
                # Merge sentiment info with messages
                person_messages = person_messages.merge(
                    sentiment_df[['message_id', 'sentiment_score', 'sentiment_polarity', 'sentiment_subjectivity']], 
                    on='message_id', 
                    how='left',
                    suffixes=('', '_sentiment')
                )
        
        # Reorder columns for better readability
        # Convert timestamps to local timezone for display
        tz = pytz.timezone(self.config.timezone)
        tz_abbr = datetime.now(tz).strftime('%Z')
        if 'timestamp' in person_messages.columns:
            person_messages['timestamp'] = pd.to_datetime(
                person_messages['timestamp'], utc=True, errors='coerce'
            ).dt.tz_convert(tz).dt.strftime('%Y-%m-%d %H:%M:%S %Z')

        column_order = ['timestamp', 'sender', 'recipient', 'content', 'edit_history_text', 'source']

        # Create human-readable edit history column
        if 'edit_history' in person_messages.columns:
            def _format_edit_history(hist):
                if not hist or not isinstance(hist, list) or len(hist) <= 1:
                    return ''
                parts = []
                for i, edit in enumerate(hist[:-1]):
                    label = 'Original' if i == 0 else f'Edit {i}'
                    ts = edit.get('timestamp', '')
                    ct = edit.get('content', '')
                    parts.append(f'{label} ({ts}): {ct}' if ts else f'{label}: {ct}')
                return ' | '.join(parts)
            person_messages['edit_history_text'] = person_messages['edit_history'].apply(_format_edit_history)
        
        # Add threat columns if they exist
        threat_cols = ['threat_detected', 'threat_categories', 'threat_confidence', 'harmful_content']
        for col in threat_cols:
            if col in person_messages.columns:
                column_order.append(col)
        
        # Add sentiment columns if they exist
        sentiment_cols = ['sentiment_score', 'sentiment_polarity', 'sentiment_subjectivity']
        for col in sentiment_cols:
            if col in person_messages.columns:
                column_order.append(col)
        
        # Add any remaining columns
        remaining_cols = [col for col in person_messages.columns if col not in column_order]
        column_order.extend(remaining_cols)
        
        # Filter to only existing columns
        column_order = [col for col in column_order if col in person_messages.columns]
        
        person_messages = person_messages[column_order]

        # Label timestamp column with timezone abbreviation
        if 'timestamp' in person_messages.columns:
            person_messages = person_messages.rename(
                columns={'timestamp': f'Timestamp ({tz_abbr})'}
            )

        person_messages.to_excel(writer, sheet_name=sheet_name, index=False)
        
        logger.info(f"Created sheet '{sheet_name}' with {len(person_messages)} messages")
    
    @staticmethod
    def _compute_date_range(messages: list) -> str:
        """Return a 'YYYY-MM-DD to YYYY-MM-DD' string from a list of message dicts."""
        if not messages:
            return 'N/A'
        timestamps = []
        for msg in messages:
            ts = msg.get('timestamp')
            if ts is None:
                continue
            try:
                parsed = pd.to_datetime(ts, utc=True)
                if not pd.isna(parsed):
                    timestamps.append(parsed)
            except Exception:
                continue
        if not timestamps:
            return 'N/A'
        earliest = min(timestamps)
        latest = max(timestamps)
        return f"{earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')}"

    @staticmethod
    def _match_quote_to_message(quote: str, messages: list) -> dict:
        """Match an AI-identified quote to its source message via substring matching."""
        return match_quote_to_message(quote, messages)

    def _write_overview_sheet(self, writer, extracted_data: Dict,
                            analysis_results: Dict, review_decisions: Dict):
        """Write overview sheet with summary statistics."""
        compliance = LegalComplianceManager(config=self.config, forensic_recorder=self.forensic)
        messages = extracted_data.get('messages', [])
        date_range = self._compute_date_range(messages)
        overview = {
            'Metric': [
                'Total Messages',
                'Date Range',
                'Sources',
                'Threats Detected',
                'Items Reviewed',
                'Relevant Items',
                'Report Generated'
            ],
            'Value': [
                extracted_data.get('total_messages', len(messages)),
                date_range,
                ', '.join(set(m.get('source', '') for m in messages if m.get('source'))),
                analysis_results.get('threats', {}).get('summary', {}).get('messages_with_threats', 0),
                review_decisions.get('total_reviewed', 0),
                review_decisions.get('relevant', 0),
                compliance.format_timestamp()
            ]
        }
        
        df_overview = pd.DataFrame(overview)
        df_overview.to_excel(writer, sheet_name='Overview', index=False)

    def _write_conversation_threads_sheet(self, writer, messages: list):
        """
        Write a 'Conversation Threads' sheet summarising every detected
        conversation thread.  One row per thread with: participants,
        time_range, message_count, threat_count, avg_sentiment.

        Args:
            writer: Active pd.ExcelWriter object.
            messages: Raw list of message dicts.
        """
        if not messages:
            logger.info("No messages available for conversation threads sheet")
            return

        try:
            threader = ConversationThreader()
            summaries = threader.generate_conversation_summaries(messages)

            if not summaries:
                logger.info("No conversation threads detected")
                return

            # Build rows for the DataFrame
            rows = []
            for s in summaries:
                time_range = f"{s['start_time']}  to  {s['end_time']}"
                rows.append({
                    'Thread ID': s['thread_id'],
                    'Participants': s['participants'],
                    'Time Range': time_range,
                    'Message Count': s['message_count'],
                    'Threats Detected': s['threats_detected'],
                    'Threat Count': s['threat_count'],
                    'Avg Sentiment': s['avg_sentiment'],
                })

            df_threads = pd.DataFrame(rows)
            df_threads.to_excel(
                writer, sheet_name='Conversation Threads', index=False
            )
            logger.info(
                f"Created 'Conversation Threads' sheet with {len(rows)} threads"
            )

        except Exception as e:
            logger.error(f"Failed to write Conversation Threads sheet: {e}")

    def _write_findings_summary_sheet(self, writer, analysis_results: Dict,
                                      review_decisions: Dict,
                                      messages: list = None):
        """
        Write a 'Findings Summary' sheet with all confirmed findings,
        AI-identified threats, risk indicators, patterns, and recommendations
        — each with verifiable timestamps.

        Args:
            writer: Active pd.ExcelWriter object.
            analysis_results: Full analysis results dictionary.
            review_decisions: Review decisions dictionary.
            messages: Original messages list for cross-referencing AI quotes.
        """
        try:
            rows = []

            # --- Threats flagged for review (from pattern analyzer) ---
            threat_details = analysis_results.get('threats', {}).get('details', [])
            if isinstance(threat_details, list):
                for idx, item in enumerate(threat_details):
                    if not isinstance(item, dict):
                        continue
                    if not item.get('threat_detected'):
                        continue
                    review_id = f"threat_{idx}"
                    rows.append({
                        'Section': 'Threat',
                        'Timestamp': self._format_local_timestamp(item.get('timestamp')),
                        'Sender': item.get('sender', ''),
                        'Content': item.get('content', ''),
                        'Category': item.get('threat_categories', ''),
                        'Severity / Confidence': item.get('threat_confidence', ''),
                        'Review Decision': self._lookup_review_decision(review_id, review_decisions),
                    })

            # --- Additional threats flagged by pre-review screening ---
            # Source labelling is intentionally consistent ("Threat") — all
            # flagged items go through the same manual review process and
            # the report addresses the review findings, not the source of
            # the initial flag.
            ai_analysis = analysis_results.get('ai_analysis', {})
            threat_assessment = ai_analysis.get('threat_assessment', {})
            if threat_assessment.get('found'):
                for i, detail in enumerate(threat_assessment.get('details', [])):
                    review_id = f"ai_threat_{i}"
                    if isinstance(detail, dict):
                        quote = detail.get('quote', '')
                        match = self._match_quote_to_message(quote, messages or [])
                        rows.append({
                            'Section': 'Threat',
                            'Timestamp': self._format_local_timestamp(match['timestamp']),
                            'Sender': match['sender'],
                            'Content': quote,
                            'Category': detail.get('type', ''),
                            'Severity / Confidence': str(detail.get('severity', '')).upper(),
                            'Review Decision': self._lookup_review_decision(review_id, review_decisions),
                        })
                    else:
                        rows.append({
                            'Section': 'Threat',
                            'Timestamp': '',
                            'Sender': '',
                            'Content': str(detail),
                            'Category': '',
                            'Severity / Confidence': '',
                            'Review Decision': self._lookup_review_decision(review_id, review_decisions),
                        })

            # --- Risk indicators ---
            risk_indicators = ai_analysis.get('risk_indicators', [])
            for risk in risk_indicators:
                if isinstance(risk, dict):
                    rows.append({
                        'Section': 'Risk Indicator',
                        'Timestamp': '',
                        'Sender': '',
                        'Content': risk.get('indicator', risk.get('description', risk.get('detail', ''))),
                        'Category': '',
                        'Severity / Confidence': str(risk.get('severity', '')).upper(),
                        'Review Decision': '',
                    })
                else:
                    rows.append({
                        'Section': 'Risk Indicator',
                        'Timestamp': '',
                        'Sender': '',
                        'Content': str(risk),
                        'Category': '',
                        'Severity / Confidence': '',
                        'Review Decision': '',
                    })

            # --- Pattern detections ---
            pattern_details = analysis_results.get('patterns', [])
            if isinstance(pattern_details, list):
                for item in pattern_details:
                    if not isinstance(item, dict):
                        continue
                    patterns = item.get('patterns_detected', '')
                    if not patterns:
                        continue
                    rows.append({
                        'Section': 'Pattern Detection',
                        'Timestamp': self._format_local_timestamp(item.get('timestamp')),
                        'Sender': item.get('sender', ''),
                        'Content': item.get('content', ''),
                        'Category': patterns,
                        'Severity / Confidence': item.get('pattern_score', ''),
                        'Review Decision': '',
                    })

            # --- Executive Summary ---
            conversation_summary = ai_analysis.get('conversation_summary', '')
            if conversation_summary and 'not configured' not in conversation_summary.lower():
                rows.append({
                    'Section': 'Executive Summary',
                    'Timestamp': '',
                    'Sender': '',
                    'Content': conversation_summary,
                    'Category': '',
                    'Severity / Confidence': '',
                    'Review Decision': '',
                })

            # --- Recommendations ---
            recommendations = ai_analysis.get('recommendations', [])
            for i, rec in enumerate(recommendations, 1):
                rows.append({
                    'Section': f'Recommendation {i}',
                    'Timestamp': '',
                    'Sender': '',
                    'Content': str(rec),
                    'Category': '',
                    'Severity / Confidence': '',
                    'Review Decision': '',
                })

            if rows:
                df_summary = pd.DataFrame(rows)
                # Ensure consistent column order
                col_order = ['Section', 'Timestamp', 'Sender', 'Content',
                             'Category', 'Severity / Confidence', 'Review Decision']
                col_order = [c for c in col_order if c in df_summary.columns]
                df_summary = df_summary[col_order]
                df_summary.to_excel(writer, sheet_name='Findings Summary', index=False)
                logger.info(f"Created 'Findings Summary' sheet with {len(rows)} rows")

        except Exception as e:
            logger.error(f"Failed to write Findings Summary sheet: {e}")

    def _write_timeline_sheet(self, writer, extracted_data: Dict,
                              analysis_results: Dict):
        """
        Write a 'Timeline' sheet with key events sorted chronologically.

        Includes: threats, SOS messages, pattern detections, AI sentiment shifts.

        Args:
            writer: Active pd.ExcelWriter object.
            extracted_data: Extracted data dictionary with messages.
            analysis_results: Full analysis results dictionary.
        """
        try:
            events = []

            # --- Threat events ---
            threat_details = analysis_results.get('threats', {}).get('details', [])
            if isinstance(threat_details, list):
                for item in threat_details:
                    if not isinstance(item, dict):
                        continue
                    if not item.get('threat_detected'):
                        continue
                    # Skip email and counseling source threats; they are added
                    # in dedicated sections below to avoid duplicates.
                    if item.get('source') in ('email', 'counseling'):
                        continue
                    events.append({
                        'Timestamp': self._format_local_timestamp(item.get('timestamp')),
                        'Event Type': 'Threat',
                        'Sender': item.get('sender', ''),
                        'Content': item.get('content', ''),
                        'Source': item.get('source', ''),
                        'Details': item.get('threat_categories', ''),
                        '_sort_ts': item.get('timestamp', ''),
                    })

            # --- SOS messages ---
            messages = extracted_data.get('messages', [])
            for msg in messages:
                if msg.get('is_sos'):
                    events.append({
                        'Timestamp': self._format_local_timestamp(msg.get('timestamp')),
                        'Event Type': 'SOS',
                        'Sender': msg.get('sender', ''),
                        'Content': msg.get('content', ''),
                        'Source': msg.get('source', ''),
                        'Details': 'Emergency SOS triggered',
                        '_sort_ts': msg.get('timestamp', ''),
                    })

            # --- Pattern detections ---
            pattern_details = analysis_results.get('patterns', [])
            if isinstance(pattern_details, list):
                for item in pattern_details:
                    if not isinstance(item, dict):
                        continue
                    patterns = item.get('patterns_detected', '')
                    if not patterns:
                        continue
                    events.append({
                        'Timestamp': self._format_local_timestamp(item.get('timestamp')),
                        'Event Type': 'Pattern',
                        'Sender': item.get('sender', ''),
                        'Content': item.get('content', ''),
                        'Source': item.get('source', ''),
                        'Details': patterns,
                        '_sort_ts': item.get('timestamp', ''),
                    })

            # --- AI sentiment shifts ---
            ai_analysis = analysis_results.get('ai_analysis', {})
            sentiment = ai_analysis.get('sentiment_analysis', {})
            shifts = sentiment.get('shifts', [])
            for shift in shifts:
                if isinstance(shift, dict):
                    events.append({
                        'Timestamp': self._format_local_timestamp(shift.get('timestamp', shift.get('date', ''))),
                        'Event Type': 'Sentiment Shift',
                        'Sender': '',
                        'Content': shift.get('description', str(shift)),
                        'Source': '',
                        'Details': f"From {shift.get('from', '?')} to {shift.get('to', '?')}",
                        '_sort_ts': shift.get('timestamp', shift.get('date', '')),
                    })

            # --- Email communications (all emails provide chronological context) ---
            # Emails are low-volume and each is purposeful; third-party emails
            # (counselors, attorneys, family) provide crucial corroboration.
            messages = extracted_data.get('messages', [])
            mapped_persons = set(self.config.contact_mappings.keys())
            for msg in messages:
                if msg.get('source') != 'email':
                    continue
                sender = msg.get('sender', '')
                recipient = msg.get('recipient', '')
                is_third_party = sender not in mapped_persons or recipient not in mapped_persons
                event_type = 'Third-Party Email' if is_third_party else 'Email'
                subject = msg.get('subject', '')
                content_preview = (msg.get('content', '') or '')[:100]
                events.append({
                    'Timestamp': self._format_local_timestamp(msg.get('timestamp')),
                    'Event Type': event_type,
                    'Sender': sender,
                    'Content': content_preview,
                    'Source': 'email',
                    'Details': f'Subject: {subject}' if subject else '',
                    '_sort_ts': msg.get('timestamp', ''),
                })

            # --- Counseling session events ---
            for msg in messages:
                if msg.get('source') != 'counseling':
                    continue
                topic = msg.get('topic', '')
                provider = msg.get('provider', '') or msg.get('sender', 'Counselor')
                notes_preview = (msg.get('content', '') or '')[:200]
                events.append({
                    'Timestamp': self._format_local_timestamp(msg.get('timestamp')),
                    'Event Type': 'Counseling Session',
                    'Sender': provider,
                    'Content': notes_preview,
                    'Source': 'counseling',
                    'Details': f'Topic: {topic}' if topic else '',
                    '_sort_ts': msg.get('timestamp', ''),
                })

            if not events:
                logger.info("No timeline events to write")
                return

            # Sort chronologically by raw timestamp
            def sort_key(e):
                ts = e.get('_sort_ts', '')
                if not ts:
                    return ''
                try:
                    return str(pd.to_datetime(ts, utc=True))
                except Exception:
                    return str(ts)

            events.sort(key=sort_key)

            # Remove sort key before writing
            for e in events:
                e.pop('_sort_ts', None)

            df_timeline = pd.DataFrame(events)
            col_order = ['Timestamp', 'Event Type', 'Sender', 'Content', 'Source', 'Details']
            col_order = [c for c in col_order if c in df_timeline.columns]
            df_timeline = df_timeline[col_order]
            df_timeline.to_excel(writer, sheet_name='Timeline', index=False)
            logger.info(f"Created 'Timeline' sheet with {len(events)} events")

        except Exception as e:
            logger.error(f"Failed to write Timeline sheet: {e}")

    def _write_third_party_contacts_sheet(self, writer, contacts: list):
        """
        Write a 'Third Party Contacts' sheet listing all discovered contacts.

        Args:
            writer: Active pd.ExcelWriter object.
            contacts: List of third-party contact dicts from ThirdPartyRegistry.get_all().
        """
        if not contacts:
            return

        try:
            rows = []
            for entry in contacts:
                rows.append({
                    'Identifier': entry.get('identifier', ''),
                    'Display Name': entry.get('display_name', ''),
                    'Source': ', '.join(entry.get('sources', [])),
                    'First Seen': entry.get('first_seen', ''),
                    'Context': '; '.join(entry.get('contexts', [])),
                })

            df_contacts = pd.DataFrame(rows)
            df_contacts.to_excel(writer, sheet_name='Third Party Contacts', index=False)
            logger.info(f"Created 'Third Party Contacts' sheet with {len(rows)} contacts")

        except Exception as e:
            logger.error(f"Failed to write Third Party Contacts sheet: {e}")