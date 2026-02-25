"""
Integration tests for the forensic message analyzer.
"""

import pytest
import copy
import pandas as pd
from pathlib import Path
import tempfile
import json
from datetime import datetime

from src.config import Config
from src.forensic_utils import ForensicRecorder, ForensicIntegrity
from src.extractors.data_extractor import DataExtractor
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.analyzers.sentiment_analyzer import SentimentAnalyzer
from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
from src.analyzers.yaml_pattern_analyzer import YamlPatternAnalyzer
from src.analyzers.communication_metrics import CommunicationMetricsAnalyzer
from src.review.manual_review_manager import ManualReviewManager
from src.reporters.forensic_reporter import ForensicReporter
from src.reporters.excel_reporter import ExcelReporter
from src.reporters.html_reporter import HtmlReporter
from src.reporters.json_reporter import JSONReporter
from src.main import ForensicAnalyzer


class TestSystemIntegration:
    """Test system integration and workflow."""
    
    def test_extraction_to_analysis_pipeline(self):
        """Test data flow from extraction to analysis."""
        recorder = ForensicRecorder()

        # Create test message data with clear threat and non-threat content
        test_messages = pd.DataFrame({
            'content': [
                'Hello, how are you?',
                'I will hurt you',
                'Normal conversation',
                'I am going to kill you'
            ],
            'sender': ['user1', 'user2', 'user1', 'user2'],
            'timestamp': pd.date_range(start='2024-01-01', periods=4, freq='h'),
            'source': ['iMessage'] * 4
        })

        # Run threat analysis
        threat_analyzer = ThreatAnalyzer(recorder)
        threat_results = threat_analyzer.detect_threats(test_messages)

        assert isinstance(threat_results, pd.DataFrame)
        assert len(threat_results) == len(test_messages)
        assert 'threat_detected' in threat_results.columns

        # Verify specific threat detection
        assert threat_results.loc[1, 'threat_detected'] == True, \
            "'I will hurt you' should be detected as a threat"
        assert threat_results.loc[3, 'threat_detected'] == True, \
            "'I am going to kill you' should be detected as a threat"
        assert threat_results.loc[0, 'threat_detected'] == False, \
            "'Hello, how are you?' should not be a threat"

        # Run sentiment analysis
        sentiment_analyzer = SentimentAnalyzer(recorder)
        sentiment_results = sentiment_analyzer.analyze_sentiment(test_messages)

        assert isinstance(sentiment_results, pd.DataFrame)
        assert 'sentiment_polarity' in sentiment_results.columns
    
    def test_analysis_to_review_pipeline(self):
        """Test data flow from analysis to manual review."""
        recorder = ForensicRecorder()

        # Create test data with clear threats
        test_messages = pd.DataFrame({
            'message_id': ['msg_001', 'msg_002', 'msg_003'],
            'content': [
                'I will hurt you',
                'Normal message',
                'I am going to kill you'
            ],
            'sender': ['user1', 'user2', 'user1'],
            'timestamp': pd.date_range(start='2024-01-01', periods=3, freq='h')
        })

        # Analyze threats
        threat_analyzer = ThreatAnalyzer(recorder)
        threat_results = threat_analyzer.detect_threats(test_messages)

        # Verify threats are detected before testing review pipeline
        assert threat_results['threat_detected'].any(), \
            "At least one threat should be detected for this test to be meaningful"

        # Create review manager
        review_manager = ManualReviewManager()

        # Add reviews for threats
        for idx, row in threat_results.iterrows():
            if row.get('threat_detected', False):
                review_manager.add_review(
                    test_messages.loc[idx, 'message_id'],
                    'threat',
                    'relevant',
                    f"Threat detected in message"
                )

        # Verify reviews were created for threat messages
        reviews = review_manager.get_reviews_by_decision('relevant')
        assert len(reviews) >= 2, \
            "Both 'I will hurt you' and 'I am going to kill you' should produce reviews"
        reviewed_ids = {r['item_id'] for r in reviews}
        assert 'msg_001' in reviewed_ids, "'I will hurt you' (msg_001) should be reviewed"
        assert 'msg_003' in reviewed_ids, "'I am going to kill you' (msg_003) should be reviewed"
        
    def test_review_manager(self):
        """Test manual review manager functionality."""
        manager = ManualReviewManager()
        
        # Add multiple reviews
        manager.add_review('item1', 'threat', 'relevant', 'Contains threat')
        manager.add_review('item2', 'pattern', 'not_relevant', 'False positive')
        manager.add_review('item3', 'behavioral', 'uncertain', 'Needs more context')
        
        # Test retrieval by decision
        relevant = manager.get_reviews_by_decision('relevant')
        assert len(relevant) == 1
        assert relevant[0]['item_id'] == 'item1'
        
        not_relevant = manager.get_reviews_by_decision('not_relevant')
        assert len(not_relevant) == 1
        assert not_relevant[0]['item_id'] == 'item2'
        
        uncertain = manager.get_reviews_by_decision('uncertain')
        assert len(uncertain) == 1
        assert uncertain[0]['item_id'] == 'item3'
        
        # Test retrieval by type
        threat_reviews = manager.get_reviews_by_type('threat')
        assert len(threat_reviews) == 1
        assert threat_reviews[0]['decision'] == 'relevant'
        
        # Test summary
        summary = manager.get_review_summary()
        assert summary['total_reviews'] == 3
        assert summary['decisions']['relevant'] == 1
        assert summary['decisions']['not_relevant'] == 1
        assert summary['decisions']['uncertain'] == 1
        
    def test_full_workflow_integration(self, tmp_path):
        """
        Full end-to-end test: synthetic iMessage-style messages through
        extraction → analysis → review (with random mixed decisions) →
        filtering → report generation.

        Verifies that all report formats are produced with realistic data
        and that review filtering actually removes rejected findings.
        """
        # ---------------------------------------------------------------
        # 1. Build synthetic iMessage-style messages with a mix of
        #    threats, normal conversation, and emotional content.
        # ---------------------------------------------------------------
        messages = [
            {
                'message_id': 'imsg_001',
                'content': 'Hey, can you pick up the kids from school today?',
                'sender': 'Person A',
                'recipient': 'Person B',
                'timestamp': '2024-06-15T08:30:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_002',
                'content': 'I told you I will hurt you if you keep ignoring my calls',
                'sender': 'Person B',
                'recipient': 'Person A',
                'timestamp': '2024-06-15T09:15:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_003',
                'content': 'Please stop threatening me. I am documenting everything.',
                'sender': 'Person A',
                'recipient': 'Person B',
                'timestamp': '2024-06-15T09:20:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_004',
                'content': 'You are worthless and nobody will believe you',
                'sender': 'Person B',
                'recipient': 'Person A',
                'timestamp': '2024-06-15T09:45:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_005',
                'content': 'I will take the kids and you will never see them again',
                'sender': 'Person B',
                'recipient': 'Person A',
                'timestamp': '2024-06-15T10:00:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_006',
                'content': 'Can we please talk about this calmly?',
                'sender': 'Person A',
                'recipient': 'Person B',
                'timestamp': '2024-06-15T10:30:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_007',
                'content': 'I am going to destroy your car if you leave',
                'sender': 'Person B',
                'recipient': 'Person A',
                'timestamp': '2024-06-15T11:00:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_008',
                'content': 'Sure, I will pick them up at 3pm',
                'sender': 'Person A',
                'recipient': 'Person B',
                'timestamp': '2024-06-15T14:00:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_009',
                'content': 'You are crazy and insane for thinking that',
                'sender': 'Person B',
                'recipient': 'Person A',
                'timestamp': '2024-06-15T15:30:00+00:00',
                'source': 'iMessage',
            },
            {
                'message_id': 'imsg_010',
                'content': 'I hope we can work something out for the kids sake',
                'sender': 'Person A',
                'recipient': 'Person B',
                'timestamp': '2024-06-15T16:00:00+00:00',
                'source': 'iMessage',
            },
        ]

        # JSON round-trip to match real pipeline behaviour
        extracted_data = json.loads(json.dumps({
            'messages': messages,
            'screenshots': [],
            'combined': messages,
            'third_party_contacts': [],
        }, default=str))

        # ---------------------------------------------------------------
        # 2. Run all analysis phases
        # ---------------------------------------------------------------
        temp_dir = tmp_path / "output"
        temp_dir.mkdir()
        forensic = ForensicRecorder(temp_dir)

        df = pd.DataFrame(messages)

        ta = ThreatAnalyzer(forensic)
        threat_df = ta.detect_threats(df)
        threat_summary = ta.generate_threat_summary(threat_df)

        sa = SentimentAnalyzer(forensic)
        sentiment_df = sa.analyze_sentiment(df)

        pa = YamlPatternAnalyzer(forensic)
        pattern_df = pa.analyze_patterns(df)

        ba = BehavioralAnalyzer(forensic)
        behavioral = ba.analyze_patterns(df)

        cm = CommunicationMetricsAnalyzer()
        metrics = cm.analyze_messages(messages)

        # Verify threat detection found the right messages
        threat_count = int(threat_df['threat_detected'].sum())
        assert threat_count >= 4, (
            f"Expected at least 4 threats from synthetic data, got {threat_count}"
        )

        # Stub AI analysis with realistic structure including
        # threat details that the review filter can act on
        ai_analysis = {
            'generated_at': datetime.now().isoformat(),
            'total_messages': len(messages),
            'ai_model': 'test-stub',
            'conversation_summary': (
                'Conversation between Person A and Person B shows escalating '
                'conflict with multiple threats of physical harm and custody '
                'interference by Person B.'
            ),
            'sentiment_analysis': {
                'scores': [{'batch': 1, 'avg_polarity': -0.35}],
                'overall': 'negative',
                'shifts': [{'from': 'neutral', 'to': 'hostile',
                            'at': '2024-06-15T09:15:00'}],
            },
            'threat_assessment': {
                'found': True,
                'details': [
                    {
                        'type': 'physical_threat',
                        'severity': 'high',
                        'quote': 'I will hurt you if you keep ignoring my calls',
                        'context': 'Direct threat of physical harm',
                    },
                    {
                        'type': 'custody_interference',
                        'severity': 'high',
                        'quote': 'I will take the kids and you will never see them',
                        'context': 'Threat to remove children',
                    },
                    {
                        'type': 'property_destruction',
                        'severity': 'medium',
                        'quote': 'I am going to destroy your car',
                        'context': 'Threat to damage property',
                    },
                ],
            },
            'behavioral_patterns': {
                'intimidation': {'detected': True, 'frequency': 'repeated'},
                'emotional_abuse': {'detected': True, 'frequency': 'repeated'},
            },
            'key_topics': ['custody', 'threats', 'emotional abuse'],
            'risk_indicators': [
                {'type': 'threat', 'severity': 'high',
                 'detail': 'Multiple explicit threats of harm'},
                {'type': 'behavioral', 'severity': 'medium',
                 'detail': 'Pattern of emotional abuse and name-calling'},
            ],
            'notable_quotes': [
                {
                    'quote': 'I will hurt you if you keep ignoring my calls',
                    'context': 'Escalation after perceived rejection',
                    'significance': 'Direct threat',
                },
                {
                    'quote': 'You are worthless and nobody will believe you',
                    'context': 'Emotional manipulation',
                    'significance': 'Gaslighting attempt',
                },
            ],
            'recommendations': [
                'Document all threatening communications',
                'Consider protective order based on repeated threats',
            ],
            'processing_stats': {
                'batches_processed': 1,
                'tokens_used': 500,
                'input_tokens': 300,
                'output_tokens': 200,
                'api_calls': 1,
                'errors': [],
            },
        }

        analysis_results = {
            'threats': {
                'details': threat_df.to_dict('records'),
                'summary': threat_summary,
            },
            'sentiment': sentiment_df.to_dict('records'),
            'patterns': pattern_df.to_dict('records'),
            'metrics': metrics,
            'ai_analysis': ai_analysis,
        }

        # ---------------------------------------------------------------
        # 3. Build review items and apply mixed decisions
        # ---------------------------------------------------------------
        items_for_review = []
        threat_details = analysis_results['threats']['details']
        for idx, item in enumerate(threat_details):
            if item.get('threat_detected'):
                items_for_review.append({
                    'id': f"threat_{idx}",
                    'type': 'threat',
                    'content': item.get('content', ''),
                })

        ai_threats = ai_analysis['threat_assessment']['details']
        for i, detail in enumerate(ai_threats):
            items_for_review.append({
                'id': f"ai_threat_{i}",
                'type': 'ai_threat',
                'content': detail.get('quote', ''),
            })

        for i, nq in enumerate(ai_analysis.get('notable_quotes', [])):
            items_for_review.append({
                'id': f"ai_notable_{i}",
                'type': 'ai_notable',
                'content': nq.get('quote', ''),
            })

        assert len(items_for_review) >= 4, (
            f"Expected at least 4 review items, got {len(items_for_review)}"
        )

        # Cycle through relevant / not_relevant / uncertain to simulate
        # a realistic human review with mixed decisions
        review_dir = tmp_path / "reviews"
        manager = ManualReviewManager(review_dir=review_dir)
        decision_cycle = ['relevant', 'not_relevant', 'uncertain']
        for i, item in enumerate(items_for_review):
            decision = decision_cycle[i % 3]
            notes = {
                'relevant': 'Confirmed — include in report',
                'not_relevant': 'False positive — exclude',
                'uncertain': 'Needs attorney review',
            }[decision]
            manager.add_review(item['id'], item['type'], decision, notes=notes)

        review_results = {
            'total_reviewed': len(manager.reviews),
            'relevant': len(manager.get_reviews_by_decision('relevant')),
            'not_relevant': len(manager.get_reviews_by_decision('not_relevant')),
            'uncertain': len(manager.get_reviews_by_decision('uncertain')),
            'reviews': manager.reviews,
        }

        # Must have at least one of each decision type
        assert review_results['relevant'] >= 1
        assert review_results['not_relevant'] >= 1
        assert review_results['uncertain'] >= 1

        # ---------------------------------------------------------------
        # 4. Filter analysis by review decisions
        # ---------------------------------------------------------------
        config = Config()
        config.output_dir = str(temp_dir)
        analyzer = ForensicAnalyzer(config)
        filtered_analysis = analyzer._filter_analysis_by_review(
            analysis_results, review_results
        )

        # Verify filtering actually removed rejected threats
        rejected_ids = {
            r['item_id'] for r in manager.get_reviews_by_decision('not_relevant')
        }
        for idx, item in enumerate(filtered_analysis['threats']['details']):
            if f"threat_{idx}" in rejected_ids:
                assert not item.get('threat_detected'), (
                    f"threat_{idx} was rejected in review but still shows "
                    f"threat_detected=True after filtering"
                )

        # ---------------------------------------------------------------
        # 5. Generate all report formats
        # ---------------------------------------------------------------
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Excel report
        excel_reporter = ExcelReporter(forensic, config=config)
        excel_path = temp_dir / f"report_{timestamp}.xlsx"
        excel_reporter.generate_report(
            extracted_data, filtered_analysis, review_results, excel_path
        )
        assert excel_path.exists(), "Excel report was not created"
        assert excel_path.stat().st_size > 0, "Excel report is empty"

        # HTML report (skip PDF to avoid WeasyPrint dependency in CI)
        html_reporter = HtmlReporter(forensic, config=config)
        html_base = temp_dir / f"report_{timestamp}"
        html_paths = html_reporter.generate_report(
            extracted_data, filtered_analysis, review_results,
            html_base, pdf=False
        )
        assert len(html_paths) >= 1, "HTML reporter produced no files"
        for fmt, path in html_paths.items():
            assert Path(path).exists(), f"HTML report file missing: {path}"

        # JSON report
        json_reporter = JSONReporter(forensic, config=config)
        json_path = temp_dir / f"report_{timestamp}.json"
        json_reporter.generate_report(
            extracted_data, filtered_analysis, review_results, json_path
        )
        assert json_path.exists(), "JSON report was not created"
        # Verify JSON is valid and contains expected keys
        with open(json_path) as f:
            json_data = json.load(f)
        assert 'threats' in json_data or 'analysis' in json_data or 'messages' in json_data, \
            "JSON report missing expected top-level keys"

        # ForensicReporter (Word + legal team summary)
        forensic_reporter = ForensicReporter(forensic, config=config)
        fr_reports = forensic_reporter.generate_comprehensive_report(
            extracted_data, filtered_analysis, review_results
        )
        assert len(fr_reports) >= 1, "ForensicReporter produced no files"
        for fmt, path in fr_reports.items():
            assert Path(path).exists(), f"Forensic report missing: {fmt} -> {path}"
            assert Path(path).stat().st_size > 0, f"Forensic report is empty: {fmt}"

        # Chain of custody
        chain_path = forensic.generate_chain_of_custody()
        assert Path(chain_path).exists(), "Chain of custody file not created"

        # ---------------------------------------------------------------
        # 6. Verify output directory has the expected files
        # ---------------------------------------------------------------
        output_files = [f for f in temp_dir.rglob("*") if f.is_file()]
        assert len(output_files) >= 5, (
            f"Expected at least 5 output files (Excel, HTML, JSON, Word, "
            f"chain of custody), got {len(output_files)}: "
            f"{[f.name for f in output_files]}"
        )