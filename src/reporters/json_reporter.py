"""
JSON report generation for forensic analysis.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
import logging

from ..config import Config
from ..forensic_utils import ForensicRecorder

# Initialize config
config = Config()

logger = logging.getLogger(__name__)


class JSONReporter:
    """Generate JSON reports for forensic analysis results."""
    
    def __init__(self, forensic_recorder: ForensicRecorder):
        """Initialize JSON reporter."""
        self.forensic = forensic_recorder
        self.output_dir = Path(config.output_dir)
    
    def generate_report(self, extracted_data: Dict, analysis_results: Dict,
                       review_decisions: Dict, output_path: Path) -> Path:
        """Generate comprehensive JSON report."""
        report = {
            "metadata": {
                "type": "Forensic Message Analysis Report",
                "generated": datetime.now().isoformat(),
                "version": "1.0"
            },
            "extraction": extracted_data,
            "analysis": analysis_results,
            "review": review_decisions,
            "summary": {
                "total_messages": extracted_data.get('total_messages', 0),
                "threats_detected": analysis_results.get('threats', {}).get('count', 0),
                "items_reviewed": review_decisions.get('total_reviewed', 0),
                "relevant_items": review_decisions.get('relevant', 0)
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Record generation
        file_hash = self.forensic.compute_hash(output_path)
        self.forensic.record_action(
            "json_report_generated",
            f"Generated JSON report with hash {file_hash}",
            {"path": str(output_path), "hash": file_hash}
        )
        
        return output_path