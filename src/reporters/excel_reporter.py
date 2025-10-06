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
                    
                    # All Messages tab - only messages involving mapped persons
                    # Filter to messages where sender OR recipient is a mapped person
                    if 'sender' in df_messages.columns and 'recipient' in df_messages.columns:
                        mapped_mask = (
                            df_messages['sender'].isin(mapped_persons + ['Me']) |
                            df_messages['recipient'].isin(mapped_persons + ['Me'])
                        )
                        df_filtered = df_messages[mapped_mask]
                        df_filtered.to_excel(writer, sheet_name='All Messages', index=False)
                    else:
                        df_messages.to_excel(writer, sheet_name='All Messages', index=False)
                
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
        # Filter messages for this person (where they are the recipient)
        person_messages = df_messages[df_messages['recipient'] == person_name].copy()
        
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
                extracted_data.get('total_messages', 0),
                extracted_data.get('date_range', 'N/A'),
                ', '.join(extracted_data.get('sources', [])),
                analysis_results.get('threats', {}).get('count', 0),
                review_decisions.get('total_reviewed', 0),
                review_decisions.get('relevant', 0),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ]
        }
        
        df_overview = pd.DataFrame(overview)
        df_overview.to_excel(writer, sheet_name='Overview', index=False)