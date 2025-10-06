#!/usr/bin/env python3
"""
Main forensic analyzer module 
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Core imports - FIXED
from src.config import Config
from src.forensic_utils import ForensicIntegrity  # Corrected from ForensicUtils

# Extractor imports - ensure correct class names
from src.extractors.imessage_extractor import iMessageExtractor
from src.extractors.whatsapp_extractor import WhatsAppExtractor
from src.extractors.data_extractor import DataExtractor

# Analyzer imports
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.analyzers.sentiment_analyzer import SentimentAnalyzer
from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
from src.analyzers.screenshot_analyzer import ScreenshotAnalyzer
from src.analyzers.yaml_pattern_analyzer import YamlPatternAnalyzer
from src.analyzers.attachment_processor import AttachmentProcessor
from src.analyzers.communication_metrics import CommunicationMetricsGenerator

# Check for optional components
HAS_FORENSIC_REPORTER = False
try:
    from src.reporters.forensic_reporter import ForensicReporter
    HAS_FORENSIC_REPORTER = True
except ImportError:
    pass


class ForensicAnalyzer:
    """Main forensic analyzer class"""
    
    def __init__(self):
        """Initialize the forensic analyzer"""
        self.config = Config()
        self.forensic = ForensicIntegrity()  # Fixed class name
        self.logger = self._setup_logging()
        self.results = {}
        
    def _setup_logging(self):
        """Setup logging configuration"""
        log_file = self.config.LOGS_DIR / f"forensic_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=getattr(logging, self.config.LOG_LEVEL),
            format=self.config.LOG_FORMAT,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        return logging.getLogger(__name__)
    
    def run_analysis(self):
        """Run the complete forensic analysis"""
        self.logger.info("Starting forensic analysis...")
        
        # Initialize data extractor
        data_extractor = DataExtractor(self.forensic)
        
        # Extract all messages
        self.logger.info("Extracting messages from all sources...")
        all_messages = data_extractor.extract_all()
        
        if not all_messages:
            self.logger.warning("No messages extracted")
            return self.results
            
        self.logger.info(f"Extracted {len(all_messages)} messages")
        
        # Convert to DataFrame
        import pandas as pd
        df = pd.DataFrame(all_messages)
        
        # Run analyzers
        analyzers = {
            'threat': ThreatAnalyzer(self.forensic),
            'sentiment': SentimentAnalyzer(self.forensic),
            'behavioral': BehavioralAnalyzer(self.forensic),
            'yaml_patterns': YamlPatternAnalyzer(self.forensic),
            'metrics': CommunicationMetricsGenerator(self.forensic)
        }
        
        for name, analyzer in analyzers.items():
            try:
                self.logger.info(f"Running {name} analysis...")
                if name == 'threat':
                    self.results[name] = analyzer.analyze_threats(df)
                elif name == 'sentiment':
                    self.results[name] = analyzer.analyze_sentiment(df)
                elif name == 'behavioral':
                    self.results[name] = analyzer.analyze_patterns(df)
                elif name == 'yaml_patterns':
                    self.results[name] = analyzer.analyze_patterns(df)
                elif name == 'metrics':
                    self.results[name] = analyzer.generate_metrics(df)
            except Exception as e:
                self.logger.error(f"Error in {name} analysis: {e}")
                self.results[name] = {'error': str(e)}
        
        # Generate reports if reporter available
        if HAS_FORENSIC_REPORTER:
            try:
                self.logger.info("Generating reports...")
                reporter = ForensicReporter(self.forensic)
                reporter.generate_comprehensive_report(
                    df,
                    self.results.get('behavioral', {}),
                    self.results.get('metrics', {}),
                    self.config.OUTPUT_DIR
                )
            except Exception as e:
                self.logger.error(f"Error generating reports: {e}")
        
        # Save results
        self._save_results()
        
        return self.results
    
    def _save_results(self):
        """Save analysis results to file"""
        output_file = self.config.OUTPUT_DIR / f"analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        self.logger.info(f"Results saved to {output_file}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of analysis results"""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'components_analyzed': list(self.results.keys()),
            'total_items': sum(
                len(data.get('messages', [])) if isinstance(data, dict) else 0 
                for data in self.results.values()
            )
        }
        return summary


def main():
    """Main entry point"""
    try:
        analyzer = ForensicAnalyzer()
        analyzer.run_analysis()
        summary = analyzer.get_summary()
        print(f"\nAnalysis complete: {summary}")
        return True
    except Exception as e:
        print(f"\nAnalysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)