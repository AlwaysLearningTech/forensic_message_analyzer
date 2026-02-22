"""
Excel report generation for forensic analysis results.
"""

import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
import logging

from ..config import Config
from ..forensic_utils import ForensicRecorder
from ..utils.conversation_threading import ConversationThreader

# Initialize config
config = Config()

logger = logging.getLogger(__name__)


class ExcelReporter:
    """Generate Excel reports with multiple sheets for different analysis aspects."""
    
    def __init__(self, forensic_recorder: ForensicRecorder):
        """Initialize Excel reporter."""
        self.forensic = forensic_recorder
        self.output_dir = Path(config.output_dir)
    
    def generate_report(self, extracted_data: Dict, analysis_results: Dict,
                       review_decisions: Dict, output_path: Path) -> Path:
        """Generate comprehensive Excel report organized by person."""
        try:
            # Get mapped persons from config
            from ..config import Config
            config = Config()
            mapped_persons = list(config.contact_mappings.keys())
            
            # Calculate filtered message count for overview
            filtered_message_count = 0
            if 'messages' in extracted_data:
                df_messages = pd.DataFrame(extracted_data['messages'])
                if 'sender' in df_messages.columns and 'recipient' in df_messages.columns:
                    mapped_mask = (
                        df_messages['sender'].isin(mapped_persons + ['Me']) |
                        df_messages['recipient'].isin(mapped_persons + ['Me'])
                    )
                    filtered_message_count = mapped_mask.sum()
                else:
                    filtered_message_count = len(df_messages)
            
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                # Overview sheet - pass filtered count
                overview_data = extracted_data.copy()
                overview_data['total_messages'] = filtered_message_count
                self._write_overview_sheet(writer, overview_data, analysis_results, review_decisions)

                # AI Analysis sheets (if AI analysis is available)
                ai_analysis = analysis_results.get('ai_analysis', {})
                if ai_analysis and ai_analysis.get('conversation_summary') and \
                   'not configured' not in ai_analysis.get('conversation_summary', '').lower():
                    self._write_findings_summary_sheet(writer, ai_analysis)
                    self._write_ai_analysis_sheet(writer, ai_analysis)

                # Get messages DataFrame
                if 'messages' in extracted_data:
                    df_messages = pd.DataFrame(extracted_data['messages'])
                    
                    # Get mapped persons from config
                    from ..config import Config
                    config = Config()
                    mapped_persons = list(config.contact_mappings.keys())
                    
                    # Get unique recipients and filter to only mapped persons
                    if 'recipient' in df_messages.columns:
                        recipients = df_messages['recipient'].unique()
                        # Only include recipients that are in the contact mappings
                        recipients = [r for r in recipients if r in mapped_persons]
                        
                        # Create a tab for each mapped person
                        for recipient in recipients:
                            self._write_person_sheet(
                                writer, 
                                df_messages, 
                                analysis_results, 
                                recipient
                            )
                    
                    # NOTE: We decided NOT to publish all messages
                    # Only person-specific tabs are included for privacy

                    # Conversation Threads sheet
                    self._write_conversation_threads_sheet(
                        writer, extracted_data.get('messages', [])
                    )

                # Manual Review sheet
                if 'reviews' in review_decisions and review_decisions['reviews']:
                    df_reviews = pd.DataFrame(review_decisions['reviews'])
                    df_reviews.to_excel(writer, sheet_name='Manual Review', index=False)
            
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
        
        if person_messages.empty:
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
        column_order = ['timestamp', 'sender', 'recipient', 'content', 'source']
        
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
        
        # Create sheet name (Excel limits to 31 characters and disallows certain characters)
        # Remove invalid characters: : \ / ? * [ ]
        sheet_name = person_name[:31]
        invalid_chars = [':', '\\', '/', '?', '*', '[', ']']
        for char in invalid_chars:
            sheet_name = sheet_name.replace(char, '_')
        
        person_messages.to_excel(writer, sheet_name=sheet_name, index=False)
        
        logger.info(f"Created sheet '{sheet_name}' with {len(person_messages)} messages")
    
    def _write_overview_sheet(self, writer, extracted_data: Dict, 
                            analysis_results: Dict, review_decisions: Dict):
        """Write overview sheet with summary statistics."""
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
                extracted_data.get('total_messages', len(extracted_data.get('messages', []))),
                'N/A',
                ', '.join(set(m.get('source', '') for m in extracted_data.get('messages', []) if m.get('source'))),
                analysis_results.get('threats', {}).get('summary', {}).get('messages_with_threats', 0),
                review_decisions.get('total_reviewed', 0),
                review_decisions.get('relevant', 0),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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

    def _write_findings_summary_sheet(self, writer, ai_analysis: Dict):
        """
        Write a 'Findings Summary' sheet with AI executive summary and recommendations.

        Args:
            writer: Active pd.ExcelWriter object.
            ai_analysis: AI analysis results dictionary.
        """
        try:
            rows = []

            # AI Executive Summary row
            conversation_summary = ai_analysis.get('conversation_summary', '')
            if conversation_summary:
                rows.append({
                    'Section': 'AI Executive Summary',
                    'Content': conversation_summary,
                })

            # Each recommendation as a row
            recommendations = ai_analysis.get('recommendations', [])
            for i, rec in enumerate(recommendations, 1):
                rows.append({
                    'Section': f'Recommendation {i}',
                    'Content': str(rec),
                })

            if rows:
                df_summary = pd.DataFrame(rows)
                df_summary.to_excel(writer, sheet_name='Findings Summary', index=False)
                logger.info(f"Created 'Findings Summary' sheet with {len(rows)} rows")

        except Exception as e:
            logger.error(f"Failed to write Findings Summary sheet: {e}")

    def _write_ai_analysis_sheet(self, writer, ai_analysis: Dict):
        """
        Write an 'AI Analysis' sheet with risk indicators and AI-detected threats.

        Args:
            writer: Active pd.ExcelWriter object.
            ai_analysis: AI analysis results dictionary.
        """
        try:
            rows = []

            # Risk indicators
            risk_indicators = ai_analysis.get('risk_indicators', [])
            for risk in risk_indicators:
                if isinstance(risk, dict):
                    rows.append({
                        'Category': 'Risk Indicator',
                        'Severity': str(risk.get('severity', 'unknown')).upper(),
                        'Description': risk.get('indicator', risk.get('description', '')),
                        'Recommended Action': risk.get('recommended_action', ''),
                    })
                else:
                    rows.append({
                        'Category': 'Risk Indicator',
                        'Severity': '',
                        'Description': str(risk),
                        'Recommended Action': '',
                    })

            # AI-detected threats
            threat_assessment = ai_analysis.get('threat_assessment', {})
            if threat_assessment.get('found'):
                for detail in threat_assessment.get('details', []):
                    if isinstance(detail, dict):
                        quote = detail.get('quote', '')
                        description = detail.get('type', 'Unknown')
                        if quote:
                            description = f"{description} - \"{quote}\""
                        rows.append({
                            'Category': 'Threat',
                            'Severity': str(detail.get('severity', 'unknown')).upper(),
                            'Description': description,
                            'Recommended Action': detail.get('recommended_action', ''),
                        })
                    else:
                        rows.append({
                            'Category': 'Threat',
                            'Severity': '',
                            'Description': str(detail),
                            'Recommended Action': '',
                        })

            if rows:
                df_ai = pd.DataFrame(rows)
                df_ai.to_excel(writer, sheet_name='AI Analysis', index=False)
                logger.info(f"Created 'AI Analysis' sheet with {len(rows)} rows")

        except Exception as e:
            logger.error(f"Failed to write AI Analysis sheet: {e}")