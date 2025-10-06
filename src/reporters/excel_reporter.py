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
        """Generate comprehensive Excel report."""
        try:
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                # Overview sheet
                self._write_overview_sheet(writer, extracted_data, analysis_results, review_decisions)
                
                # Messages sheet
                if 'messages' in extracted_data:
                    df_messages = pd.DataFrame(extracted_data['messages'])
                    df_messages.to_excel(writer, sheet_name='Messages', index=False)
                
                # Threats sheet
                if 'threats' in analysis_results:
                    df_threats = pd.DataFrame(analysis_results['threats'].get('details', []))
                    df_threats.to_excel(writer, sheet_name='Threats', index=False)
                
                # Sentiment sheet
                if 'sentiment' in analysis_results:
                    df_sentiment = pd.DataFrame(analysis_results['sentiment'])
                    df_sentiment.to_excel(writer, sheet_name='Sentiment', index=False)
                
                # Review sheet
                if 'reviews' in review_decisions:
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