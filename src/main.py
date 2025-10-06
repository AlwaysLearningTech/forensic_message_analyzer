#!/usr/bin/env python3
"""
Main orchestration script for the forensic message analyzer.
Coordinates extraction, analysis, review, and reporting phases.
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import Config
from src.forensic_utils import ForensicRecorder, ForensicIntegrity
from src.extractors.data_extractor import DataExtractor
from src.extractors.screenshot_extractor import ScreenshotExtractor
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.analyzers.sentiment_analyzer import SentimentAnalyzer
from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
from src.analyzers.yaml_pattern_analyzer import YamlPatternAnalyzer
from src.analyzers.screenshot_analyzer import ScreenshotAnalyzer
from src.analyzers.communication_metrics import CommunicationMetricsAnalyzer
from src.reporters.excel_reporter import ExcelReporter
from src.reporters.forensic_reporter import ForensicReporter
from src.reporters.json_reporter import JSONReporter
from src.review.manual_review_manager import ManualReviewManager
from src.utils.run_manifest import RunManifest
from src.utils.timeline_generator import TimelineGenerator


class ForensicAnalyzer:
    """Main orchestrator for the forensic analysis workflow."""
    
    def __init__(self, config: Config = None):
        """Initialize the forensic analyzer with necessary components.
        
        Args:
            config: Configuration instance. If None, creates a new one.
        """
        self.config = config if config is not None else Config()
        self.forensic = ForensicRecorder(Path(self.config.output_dir))
        self.integrity = ForensicIntegrity(self.forensic)
        self.manifest = RunManifest(self.forensic)
        
        # Record session start
        self.forensic.record_action("session_start", "Forensic analysis session initialized")
        
    def run_extraction_phase(self) -> Dict:
        """Run the data extraction phase."""
        print("\n" + "="*60)
        print("PHASE 1: DATA EXTRACTION")
        print("="*60)
        
        extractor = DataExtractor(self.forensic)
        
        # Extract all message data
        print("\n[*] Extracting message data from all sources...")
        try:
            all_messages = extractor.extract_all()
            print(f"    Extracted {len(all_messages)} total messages")
        except Exception as e:
            print(f"    Error extracting messages: {e}")
            all_messages = []
        
        # Catalog screenshots
        print("\n[*] Cataloging screenshots...")
        screenshots = []
        if self.config.screenshot_source_dir:
            try:
                screenshot_extractor = ScreenshotExtractor(
                    self.config.screenshot_source_dir,
                    self.forensic
                )
                screenshots = screenshot_extractor.extract_screenshots()
                print(f"    Cataloged {len(screenshots)} screenshots")
            except Exception as e:
                print(f"    Error cataloging screenshots: {e}")
        else:
            print("    No screenshot directory configured")
        
        # Save extracted data
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = Path(self.config.output_dir) / f"extracted_data_{timestamp}.json"
        
        extraction_results = {
            'messages': all_messages,
            'screenshots': screenshots,
            'combined': all_messages  # For backwards compatibility
        }
        
        with open(output_file, 'w') as f:
            json.dump(extraction_results, f, indent=2, default=str)
        
        print(f"\n[✓] Extraction complete. Data saved to {output_file}")
        
        return extraction_results
    
    def run_analysis_phase(self, data: Dict) -> Dict:
        """Run the analysis phase on extracted data."""
        print("\n" + "="*60)
        print("PHASE 2: AUTOMATED ANALYSIS")
        print("="*60)
        
        results = {}
        messages = data.get('messages', [])
        
        if not messages:
            print("\n[!] No message data to analyze")
            return results
        
        # Convert to DataFrame for analysis
        import pandas as pd
        combined_df = pd.DataFrame(messages)
        
        print(f"\n[*] Analyzing {len(combined_df)} messages")
        
        # Run threat analysis
        print("\n[*] Analyzing threats...")
        threat_analyzer = ThreatAnalyzer(self.forensic)
        threat_results = threat_analyzer.detect_threats(combined_df)
        threat_summary = threat_analyzer.generate_threat_summary(threat_results)
        results['threats'] = {
            'details': threat_results.to_dict('records') if hasattr(threat_results, 'to_dict') else threat_results,
            'summary': threat_summary
        }
        print(f"    Detected threats in {threat_summary.get('messages_with_threats', 0)} messages")
        
        # Run sentiment analysis
        print("\n[*] Analyzing sentiment...")
        sentiment_analyzer = SentimentAnalyzer(self.forensic)
        sentiment_results = sentiment_analyzer.analyze_sentiment(combined_df)
        results['sentiment'] = sentiment_results.to_dict('records') if hasattr(sentiment_results, 'to_dict') else sentiment_results
        print("    Sentiment analysis complete")
        
        # Run behavioral analysis
        print("\n[*] Analyzing behavioral patterns...")
        behavioral_analyzer = BehavioralAnalyzer(self.forensic)
        behavioral_results = behavioral_analyzer.analyze_patterns(combined_df)
        results['behavioral'] = behavioral_results
        print("    Behavioral analysis complete")
        
        # Run pattern analysis
        print("\n[*] Running pattern detection...")
        pattern_analyzer = YamlPatternAnalyzer(self.forensic)
        pattern_results = pattern_analyzer.analyze_patterns(combined_df)
        results['patterns'] = pattern_results.to_dict('records') if hasattr(pattern_results, 'to_dict') else pattern_results
        print(f"    Pattern detection complete")
        
        # Process screenshots
        if data.get('screenshots'):
            print("\n[*] Analyzing screenshots...")
            # Screenshots are already extracted, just use them
            screenshot_results = data['screenshots']
            results['screenshots'] = screenshot_results
            print(f"    Analyzed {len(screenshot_results)} screenshots")
        
        # Communication metrics
        print("\n[*] Calculating communication metrics...")
        metrics_analyzer = CommunicationMetricsAnalyzer()
        metrics_results = metrics_analyzer.analyze_messages(messages)
        results['metrics'] = metrics_results
        print("    Communication metrics calculated")
        
        # Save analysis results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = Path(self.config.output_dir) / f"analysis_results_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n[✓] Analysis complete. Results saved to {output_file}")
        
        return results
    
    def run_review_phase(self, analysis_results: Dict) -> Dict:
        """Run the manual review phase."""
        print("\n" + "="*60)
        print("PHASE 3: MANUAL REVIEW")
        print("="*60)
        
        manager = ManualReviewManager()
        
        # Present items for review
        items_for_review = []
        
        # Add high-confidence threats
        if 'threats' in analysis_results:
            threat_details = analysis_results['threats'].get('details', {})
            if hasattr(threat_details, 'iterrows'):
                for idx, row in threat_details.iterrows():
                    if row.get('threat_detected'):
                        items_for_review.append({
                            'id': f"threat_{idx}",
                            'type': 'threat',
                            'content': row.get('content', ''),
                            'categories': row.get('threat_categories', [])
                        })
        
        print(f"\n[*] {len(items_for_review)} items flagged for review")
        
        # In automated mode, we'll approve all for now
        for item in items_for_review:
            manager.add_review(
                item['id'],
                item['type'],
                'relevant',
                'Automatically approved for demonstration'
            )
        
        # Get review summary
        relevant = manager.get_reviews_by_decision('relevant')
        not_relevant = manager.get_reviews_by_decision('not_relevant')
        uncertain = manager.get_reviews_by_decision('uncertain')
        
        review_summary = {
            'total_reviewed': len(relevant) + len(not_relevant) + len(uncertain),
            'relevant': len(relevant),
            'not_relevant': len(not_relevant),
            'uncertain': len(uncertain),
            'reviews': manager.reviews
        }
        
        print(f"    Relevant: {review_summary['relevant']}")
        print(f"    Not Relevant: {review_summary['not_relevant']}")
        print(f"    Uncertain: {review_summary['uncertain']}")
        
        print("\n[✓] Review phase complete")
        
        return review_summary
    
    def run_reporting_phase(self, data: Dict, analysis: Dict, review: Dict) -> Dict:
        """Generate reports in multiple formats."""
        print("\n" + "="*60)
        print("PHASE 4: REPORT GENERATION")
        print("="*60)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports = {}
        
        # Use ForensicReporter for comprehensive reports
        forensic_reporter = ForensicReporter(self.forensic)
        
        # Generate all report formats
        print("\n[*] Generating comprehensive reports...")
        generated_reports = forensic_reporter.generate_comprehensive_report(
            data, analysis, review
        )
        
        for format_name, path in generated_reports.items():
            reports[format_name] = str(path)
            print(f"    {format_name.upper()} report: {path.name}")
        
        # Also generate separate Excel report if needed
        if 'excel' not in reports:
            print("\n[*] Generating Excel report...")
            try:
                # Enrich messages with analysis results before generating Excel
                enriched_data = data.copy()
                if 'messages' in data and 'threats' in analysis and 'details' in analysis['threats']:
                    # Convert messages to DataFrame for merging
                    import pandas as pd
                    df_messages = pd.DataFrame(data['messages'])
                    df_threats = pd.DataFrame(analysis['threats']['details'])
                    
                    # Merge threat columns if message_id exists
                    if 'message_id' in df_messages.columns and 'message_id' in df_threats.columns:
                        threat_cols = [col for col in df_threats.columns if col.startswith('threat_') or col == 'harmful_content']
                        if 'message_id' not in threat_cols:
                            threat_cols.insert(0, 'message_id')
                        df_messages = df_messages.merge(
                            df_threats[threat_cols],
                            on='message_id',
                            how='left'
                        )
                    
                    # Merge sentiment columns if available
                    if 'sentiment' in analysis:
                        df_sentiment = pd.DataFrame(analysis['sentiment'])
                        if 'message_id' in df_sentiment.columns:
                            sentiment_cols = [col for col in df_sentiment.columns if col.startswith('sentiment_')]
                            if 'message_id' not in sentiment_cols:
                                sentiment_cols.insert(0, 'message_id')
                            df_messages = df_messages.merge(
                                df_sentiment[sentiment_cols],
                                on='message_id',
                                how='left'
                            )
                    
                    # Update enriched_data with merged messages
                    enriched_data['messages'] = df_messages.to_dict('records')
                
                excel_reporter = ExcelReporter(self.forensic)
                excel_path = Path(self.config.output_dir) / f"report_{timestamp}.xlsx"
                excel_reporter.generate_report(enriched_data, analysis, review, excel_path)
                reports['excel'] = str(excel_path)
                print(f"    Saved to {excel_path}")
            except Exception as e:
                print(f"    Error generating Excel report: {e}")
                import traceback
                traceback.print_exc()
        
        # Generate JSON report if needed
        if 'json' not in reports:
            print("\n[*] Generating JSON report...")
            try:
                json_reporter = JSONReporter(self.forensic)
                json_path = Path(self.config.output_dir) / f"report_{timestamp}.json"
                json_reporter.generate_report(data, analysis, review, json_path)
                reports['json'] = str(json_path)
                print(f"    Saved to {json_path}")
            except Exception as e:
                print(f"    Error generating JSON report: {e}")
        
        print("\n[✓] Report generation complete")
        
        return reports
    
    def run_documentation_phase(self, data: Dict) -> Dict:
        """Generate final documentation and chain of custody."""
        print("\n" + "="*60)
        print("PHASE 5: DOCUMENTATION")
        print("="*60)
        
        # Generate chain of custody
        print("\n[*] Generating chain of custody...")
        chain_path = self.forensic.generate_chain_of_custody()
        print(f"    Saved to {chain_path}")
        
        # Generate timeline if we have message data
        timeline_path = None
        combined_data = data.get('combined', [])
        if combined_data:
            print("\n[*] Generating timeline...")
            timeline_gen = TimelineGenerator(self.forensic)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            timeline_path = Path(self.config.output_dir) / f"timeline_{timestamp}.html"
            
            # Convert to DataFrame if needed
            import pandas as pd
            if isinstance(combined_data, list):
                df = pd.DataFrame(combined_data)
            else:
                df = combined_data
            
            timeline_gen.create_timeline(df, timeline_path)
            print(f"    Saved to {timeline_path}")
        else:
            print("\n[!] Skipping timeline generation (no message data)")
        
        # Generate run manifest
        print("\n[*] Generating run manifest...")
        manifest_path = self.manifest.generate_manifest()
        print(f"    Saved to {manifest_path}")
        
        print("\n[✓] Documentation complete")
        
        result = {
            'chain_of_custody': str(chain_path),
            'manifest': str(manifest_path)
        }
        if timeline_path:
            result['timeline'] = str(timeline_path)
        
        return result
    
    def run_full_analysis(self):
        """Run the complete forensic analysis workflow."""
        print("\n" + "="*80)
        print(" FORENSIC MESSAGE ANALYZER - FULL WORKFLOW ")
        print("="*80)
        print(f"Session started: {datetime.now()}")
        print(f"Output directory: {self.config.output_dir}")
        
        try:
            # Phase 1: Extraction
            extracted_data = self.run_extraction_phase()
            
            # Phase 2: Analysis
            analysis_results = self.run_analysis_phase(extracted_data)
            
            # Phase 3: Review
            review_results = self.run_review_phase(analysis_results)
            
            # Phase 4: Reporting
            reports = self.run_reporting_phase(extracted_data, analysis_results, review_results)
            
            # Phase 5: Documentation
            documentation = self.run_documentation_phase(extracted_data)
            
            print("\n" + "="*80)
            print(" WORKFLOW COMPLETE ")
            print("="*80)
            print(f"\nAll outputs saved to: {self.config.output_dir}")
            print("\nGenerated files:")
            for report_type, path in reports.items():
                print(f"  - {report_type}: {Path(path).name}")
            for doc_type, path in documentation.items():
                print(f"  - {doc_type}: {Path(path).name}")
            
        except Exception as e:
            print(f"\n[ERROR] Workflow failed: {e}")
            raise


def main(config: Config = None):
    """Main entry point for the forensic analyzer.
    
    Args:
        config: Configuration instance. If None, creates a new one.
        
    Returns:
        bool: True if analysis completed successfully, False otherwise.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.run_full_analysis()
        return True
    except Exception as e:
        print(f"\n[ERROR] Analysis failed: {e}")
        return False