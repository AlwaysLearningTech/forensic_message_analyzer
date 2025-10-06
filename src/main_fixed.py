#!/usr/bin/env python3
"""
Main forensic analyzer module - FIXED VERSION
This version only imports classes that actually exist.
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

# Core imports - using actual existing classes
from src.config import Config
from src.forensic_utils import ForensicIntegrity  # Fixed class name

# Extractor imports - only those that exist
from src.extractors.imessage_extractor import iMessageExtractor
from src.extractors.whatsapp_extractor import WhatsAppExtractor
from src.extractors.data_extractor import DataExtractor

# Analyzer imports - only those that exist
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.analyzers.sentiment_analyzer import SentimentAnalyzer
from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
from src.analyzers.screenshot_analyzer import ScreenshotAnalyzer
from src.analyzers.yaml_pattern_analyzer import YamlPatternAnalyzer
from src.analyzers.attachment_processor import AttachmentProcessor
from src.analyzers.communication_metrics import CommunicationMetricsGenerator

# Reporter imports - check which actually exist
try:
    from src.reporters.forensic_reporter import ForensicReporter
    HAS_FORENSIC_REPORTER = True
except ImportError:
    HAS_FORENSIC_REPORTER = False
    print("Warning: ForensicReporter not available")


class ForensicAnalyzer:
    """Main forensic analyzer class"""
    
    def __init__(self):
        """Initialize the forensic analyzer"""
        self.config = Config()
        self.forensic = ForensicIntegrity()  # Fixed class name
        self.logger = self._setup_logging()
        self.results = {}
        
        # Initialize components
        self.data_extractor = DataExtractor(self.forensic)
        
        # Analyzers
        self.threat_analyzer = ThreatAnalyzer(self.forensic)
        self.sentiment_analyzer = SentimentAnalyzer(self.forensic)
        self.behavioral_analyzer = BehavioralAnalyzer(self.forensic)
        self.screenshot_analyzer = ScreenshotAnalyzer(self.forensic)
        self.yaml_pattern_analyzer = YamlPatternAnalyzer(self.forensic)
        self.attachment_processor = AttachmentProcessor(self.forensic)
        self.metrics_generator = CommunicationMetricsGenerator(self.forensic)
        
        # Reporter
        if HAS_FORENSIC_REPORTER:
            self.reporter = ForensicReporter(self.forensic)
        else:
            self.reporter = None
            
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
        self.logger.info("=" * 60)
        self.logger.info("Starting Forensic Analysis System v4.0")
        self.logger.info("=" * 60)
        
        try:
            # Step 1: Extract all messages
            self.logger.info("Step 1: Extracting messages from all sources...")
            all_messages = self.data_extractor.extract_all()
            self.logger.info(f"Extracted {len(all_messages)} total messages")
            
            if not all_messages:
                self.logger.warning("No messages extracted. Check source files.")
                return self.results
            
            # Convert to DataFrame for analysis
            import pandas as pd
            df = pd.DataFrame(all_messages)
            
            # Step 2: Run threat analysis
            self.logger.info("Step 2: Running threat analysis...")
            threat_results = self.threat_analyzer.analyze_threats(df)
            self.results['threats'] = threat_results
            
            # Step 3: Run sentiment analysis
            self.logger.info("Step 3: Running sentiment analysis...")
            sentiment_results = self.sentiment_analyzer.analyze_sentiment(df)
            self.results['sentiment'] = sentiment_results
            
            # Step 4: Run behavioral analysis
            self.logger.info("Step 4: Running behavioral analysis...")
            behavioral_results = self.behavioral_analyzer.analyze_patterns(df)
            self.results['behavioral'] = behavioral_results
            
            # Step 5: Process screenshots if available
            screenshot_dir = self.config.SOURCE_DIR / "screenshots"
            if screenshot_dir.exists():
                self.logger.info("Step 5: Processing screenshots...")
                screenshot_results = self.screenshot_analyzer.analyze_screenshots(screenshot_dir)
                self.results['screenshots'] = screenshot_results
            
            # Step 6: Generate metrics
            self.logger.info("Step 6: Generating communication metrics...")
            metrics = self.metrics_generator.generate_metrics(df)
            self.results['metrics'] = metrics
            
            # Step 7: Generate reports
            if self.reporter:
                self.logger.info("Step 7: Generating reports...")
                self.reporter.generate_comprehensive_report(
                    df, 
                    behavioral_results,
                    metrics,
                    self.config.OUTPUT_DIR
                )
            
            # Save results
            self._save_results()
            
            self.logger.info("=" * 60)
            self.logger.info("Analysis complete!")
            self.logger.info(f"Results saved to: {self.config.OUTPUT_DIR}")
            
        except Exception as e:
            self.logger.error(f"Critical error during analysis: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            raise
        
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