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
from src.third_party_registry import ThirdPartyRegistry
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
        self.third_party_registry = ThirdPartyRegistry(self.forensic, self.config)
        
        # Record session start
        self.forensic.record_action("session_start", "Forensic analysis session initialized")
        
    def run_extraction_phase(self) -> Dict:
        """Run the data extraction phase."""
        print("\n" + "="*60)
        print("PHASE 1: DATA EXTRACTION")
        print("="*60)
        
        extractor = DataExtractor(self.forensic, third_party_registry=self.third_party_registry)
        
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
            'combined': all_messages,  # For backwards compatibility
            'third_party_contacts': self.third_party_registry.get_all(),
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
        
        # NOTE: Behavioral analysis moved to Phase 4 (after manual review)
        # This ensures trends are based on reviewed/confirmed data, not raw detections
        
        # Run pattern analysis
        print("\n[*] Running pattern detection...")
        pattern_analyzer = YamlPatternAnalyzer(self.forensic)
        pattern_results = pattern_analyzer.analyze_patterns(combined_df)
        results['patterns'] = pattern_results.to_dict('records') if hasattr(pattern_results, 'to_dict') else pattern_results
        print(f"    Pattern detection complete")
        
        # Process screenshots
        if data.get('screenshots'):
            print("\n[*] Analyzing screenshots...")
            screenshot_analyzer = ScreenshotAnalyzer(
                self.forensic, third_party_registry=self.third_party_registry
            )
            # Run contact extraction on already-extracted screenshots
            for screenshot in data['screenshots']:
                text = screenshot.get('extracted_text', '')
                if text:
                    contacts = screenshot_analyzer._extract_contact_info(
                        text, screenshot.get('filename', '')
                    )
                    screenshot['contacts_found'] = contacts
            screenshot_results = data['screenshots']
            results['screenshots'] = screenshot_results
            print(f"    Analyzed {len(screenshot_results)} screenshots")
        
        # Communication metrics
        print("\n[*] Calculating communication metrics...")
        metrics_analyzer = CommunicationMetricsAnalyzer()
        metrics_results = metrics_analyzer.analyze_messages(messages)
        results['metrics'] = metrics_results
        print("    Communication metrics calculated")

        # AI analysis (Anthropic Claude)
        print("\n[*] Running AI analysis...")
        try:
            from src.analyzers.ai_analyzer import AIAnalyzer
            ai_analyzer = AIAnalyzer(forensic_recorder=self.forensic)
            if ai_analyzer.client:
                ai_results = ai_analyzer.analyze_messages(messages, batch_size=self.config.batch_size)
                results['ai_analysis'] = ai_results
                risk_count = len(ai_results.get('risk_indicators', []))
                print(f"    AI analysis complete - {risk_count} risk indicators found")
            else:
                results['ai_analysis'] = ai_analyzer._empty_analysis()
                print("    AI analysis skipped - Anthropic Claude not configured")
        except Exception as e:
            print(f"    AI analysis error: {e}")
            results['ai_analysis'] = {}

        # Save analysis results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = Path(self.config.output_dir) / f"analysis_results_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n[✓] Analysis complete. Results saved to {output_file}")
        
        return results
    
    def run_review_phase(self, analysis_results: Dict, extracted_data: Dict) -> Dict:
        """Run the interactive manual review phase on flagged items."""
        print("\n" + "="*60)
        print("PHASE 3: INTERACTIVE MANUAL REVIEW")
        print("="*60)

        manager = ManualReviewManager()

        # Present items for review
        items_for_review = []

        # Add ALL threats for review (not just high-confidence)
        if 'threats' in analysis_results:
            threat_details = analysis_results['threats'].get('details', [])
            # threat_details is a list of dicts, not a DataFrame
            if isinstance(threat_details, list):
                for idx, item in enumerate(threat_details):
                    if item.get('threat_detected'):
                        # Flag ALL threats for legal review, regardless of confidence
                        items_for_review.append({
                            'id': f"threat_{idx}",
                            'type': 'threat',
                            'content': item.get('content', ''),
                            'categories': item.get('threat_categories', ''),
                            'confidence': item.get('threat_confidence', 0),
                            'message_id': item.get('message_id', ''),
                        })

        # Add AI-detected threats to review queue
        ai_analysis = analysis_results.get('ai_analysis', {})
        if ai_analysis.get('threat_assessment', {}).get('found'):
            for i, detail in enumerate(ai_analysis['threat_assessment'].get('details', [])):
                if isinstance(detail, dict):
                    items_for_review.append({
                        'id': f"ai_threat_{i}",
                        'type': 'ai_threat',
                        'content': detail.get('quote', detail.get('type', '')),
                        'categories': detail.get('type', ''),
                        'confidence': 0.0,
                        'severity': detail.get('severity', ''),
                        'threat_type': detail.get('type', ''),
                    })

        print(f"\n[*] {len(items_for_review)} items flagged for review")

        # Choose review mode (web or terminal)
        messages = extracted_data.get('messages', [])
        screenshots = extracted_data.get('screenshots', [])

        review_mode = 'terminal'
        if items_for_review:
            try:
                choice = input("\n    Review mode: (W)eb interface or (T)erminal? [W]: ").strip().upper()
                if choice != 'T':
                    review_mode = 'web'
            except (EOFError, KeyboardInterrupt):
                review_mode = 'terminal'

        if review_mode == 'web' and items_for_review:
            try:
                from src.review.web_review import WebReview
                web = WebReview(manager, forensic_recorder=self.forensic)
                web.start_review(messages, items_for_review, screenshots=screenshots)
            except ImportError:
                print("    Flask not installed. Falling back to terminal review.")
                from src.review.interactive_review import InteractiveReview
                interactive = InteractiveReview(manager)
                interactive.review_flagged_items(messages, items_for_review)
        else:
            from src.review.interactive_review import InteractiveReview
            interactive = InteractiveReview(manager)
            interactive.review_flagged_items(messages, items_for_review)

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
    
    def run_behavioral_phase(self, extracted_data: Dict, analysis_results: Dict, review_results: Dict) -> Dict:
        """Run behavioral analysis on reviewed data (Phase 4)."""
        print("\n" + "="*60)
        print("PHASE 4: BEHAVIORAL ANALYSIS (POST-REVIEW)")
        print("="*60)
        
        import pandas as pd
        
        messages = extracted_data.get('messages', [])
        if not messages:
            print("\n[!] No message data to analyze")
            return {}
        
        # Get confirmed threats from review
        relevant_ids = [r.get('item_id', '') for r in review_results.get('reviews', [])
                       if r.get('decision') == 'relevant']
        
        print(f"\n[*] Analyzing behavioral patterns on {len(relevant_ids)} reviewed threats")
        
        # Convert to DataFrame
        combined_df = pd.DataFrame(messages)
        
        # Run behavioral analysis
        behavioral_analyzer = BehavioralAnalyzer(self.forensic)
        behavioral_results = behavioral_analyzer.analyze_patterns(combined_df)
        
        print("    Behavioral analysis complete")
        print(f"    Analyzed communication patterns across {len(combined_df)} messages")
        
        return behavioral_results
    
    def run_reporting_phase(self, data: Dict, analysis: Dict, review: Dict) -> Dict:
        """Generate reports in multiple formats."""
        print("\n" + "="*60)
        print("PHASE 5: REPORT GENERATION")
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
                # DON'T enrich - just pass the original data
                # The Excel reporter will handle filtering and won't need all analysis columns
                enriched_data = data.copy()
                
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
    
    def run_documentation_phase(self, data: Dict, analysis_results: Dict = None) -> Dict:
        """Generate final documentation and chain of custody."""
        print("\n" + "="*60)
        print("PHASE 6: DOCUMENTATION")
        print("="*60)
        
        # Generate chain of custody
        print("\n[*] Generating chain of custody...")
        chain_path = self.forensic.generate_chain_of_custody()
        print(f"    Saved to {chain_path}")
        
        # Generate timeline if we have message data
        timeline_path = None
        combined_data = data.get('messages', data.get('combined', []))
        if combined_data:
            print("\n[*] Generating timeline...")
            timeline_gen = TimelineGenerator(self.forensic)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            timeline_path = Path(self.config.output_dir) / f"timeline_{timestamp}.html"

            # Convert to DataFrame
            import pandas as pd
            if isinstance(combined_data, list):
                df = pd.DataFrame(combined_data)
            else:
                df = combined_data

            # Merge analysis columns if available
            if analysis_results:
                # Threats have details as list of dicts with analysis columns
                threat_details = analysis_results.get('threats', {}).get('details', [])
                if threat_details and isinstance(threat_details, list):
                    analysis_df = pd.DataFrame(threat_details)
                    # Only merge columns that aren't already in df
                    analysis_cols = ['threat_detected', 'threat_categories', 'threat_confidence',
                                   'harmful_content', 'sentiment_score', 'sentiment_polarity',
                                   'sentiment_subjectivity', 'patterns_detected', 'pattern_score']
                    for col in analysis_cols:
                        if col in analysis_df.columns and col not in df.columns:
                            df[col] = analysis_df[col].values[:len(df)] if len(analysis_df) >= len(df) else None

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
            review_results = self.run_review_phase(analysis_results, extracted_data)

            # Phase 4: Behavioral Analysis (post-review)
            behavioral_results = self.run_behavioral_phase(extracted_data, analysis_results, review_results)
            analysis_results['behavioral'] = behavioral_results

            # Update third-party contact data (screenshots may have added more during analysis)
            extracted_data['third_party_contacts'] = self.third_party_registry.get_all()
            tp_summary = self.third_party_registry.get_summary()
            if tp_summary['total'] > 0:
                print(f"\n[*] Discovered {tp_summary['total']} third-party contacts")
                for src, count in tp_summary['by_source'].items():
                    print(f"    {src}: {count}")

            # Phase 5: Reporting
            reports = self.run_reporting_phase(extracted_data, analysis_results, review_results)

            # Phase 6: Documentation (pass analysis_results for enriched timeline)
            documentation = self.run_documentation_phase(extracted_data, analysis_results)

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
            import traceback
            traceback.print_exc()
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