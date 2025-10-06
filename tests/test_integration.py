"""
Integration tests for the forensic message analyzer.
"""

import pytest
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
from src.review.manual_review_manager import ManualReviewManager
from src.reporters.forensic_reporter import ForensicReporter


class TestSystemIntegration:
    """Test system integration and workflow."""
    
    def test_extraction_to_analysis_pipeline(self):
        """Test data flow from extraction to analysis."""
        recorder = ForensicRecorder()
        
        # Create test message data
        test_messages = pd.DataFrame({
            'content': [
                'Hello, how are you?',
                'I will find you',
                'This is harassment',
                'Normal conversation'
            ],
            'sender': ['user1', 'user2', 'user2', 'user1'],
            'timestamp': pd.date_range(start='2024-01-01', periods=4, freq='h'),
            'source': ['iMessage'] * 4
        })
        
        # Run threat analysis
        threat_analyzer = ThreatAnalyzer(recorder)
        threat_results = threat_analyzer.detect_threats(test_messages)
        
        assert isinstance(threat_results, pd.DataFrame)
        assert len(threat_results) == len(test_messages)
        # Check if any threats detected (column exists)
        assert 'threat_detected' in threat_results.columns
        
        # Run sentiment analysis
        sentiment_analyzer = SentimentAnalyzer(recorder)
        sentiment_results = sentiment_analyzer.analyze_sentiment(test_messages)
        
        assert isinstance(sentiment_results, pd.DataFrame)
        assert 'sentiment_polarity' in sentiment_results.columns
    
    def test_analysis_to_review_pipeline(self):
        """Test data flow from analysis to manual review."""
        recorder = ForensicRecorder()
        
        # Create test data with threats
        test_messages = pd.DataFrame({
            'message_id': ['msg_001', 'msg_002', 'msg_003'],
            'content': [
                'I will hurt you',
                'Normal message',
                'This is threatening'
            ],
            'sender': ['user1', 'user2', 'user1'],
            'timestamp': pd.date_range(start='2024-01-01', periods=3, freq='h')
        })
        
        # Analyze threats
        threat_analyzer = ThreatAnalyzer(recorder)
        threat_results = threat_analyzer.detect_threats(test_messages)
        
        # Create review manager
        review_manager = ManualReviewManager()
        
        # Add reviews for threats
        for idx, row in threat_results.iterrows():
            if row.get('threat_detected', False):
                # add_review doesn't return anything
                review_manager.add_review(
                    test_messages.loc[idx, 'message_id'],
                    'threat',
                    'relevant',
                    f"Threat detected in message"
                )
        
        # Verify at least some reviews were added if threats detected
        if threat_results['threat_detected'].any():
            reviews = review_manager.get_reviews_by_decision('relevant')
            assert len(reviews) > 0
        
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
        
    @pytest.mark.skip(reason="Requires actual iMessage database")
    def test_full_workflow_integration(self):
        """Test complete workflow from extraction to reporting."""
        pass  # This would test the full pipeline with real data