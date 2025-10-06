"""
Integration tests to ensure the system works correctly.
Run with: pytest tests/test_integration.py -v
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime
import pandas as pd

from src.forensic_utils import ForensicIntegrity
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.extractors.data_extractor import DataExtractor
from src.review.manual_review_manager import ManualReviewManager

class TestSystemIntegration:
    """Test complete system integration."""
    
    def test_forensic_integrity_initialization(self):
        """Test that forensic integrity system initializes correctly."""
        forensic = ForensicIntegrity()
        assert forensic is not None
        assert hasattr(forensic, 'record_action')
        assert hasattr(forensic, 'export_chain_of_custody')
    
    def test_threat_analyzer(self):
        """Test threat analyzer functionality."""
        forensic = ForensicIntegrity()
        analyzer = ThreatAnalyzer(forensic)
        
        # Create test DataFrame
        test_data = pd.DataFrame([
            {'content': 'Hello, how are you?', 'message_id': '1'},
            {'content': 'I will hurt you if you do that', 'message_id': '2'},
            {'content': 'You are worthless and nobody cares', 'message_id': '3'},
        ])
        
        # Analyze threats
        result = analyzer.detect_threats(test_data)
        
        # Verify results
        assert result is not None
        assert 'threat_detected' in result.columns
        assert result.iloc[0]['threat_detected'] == False  # Normal message
        assert result.iloc[1]['threat_detected'] == True   # Physical threat
        assert result.iloc[2]['threat_detected'] == True   # Emotional abuse
    
    def test_review_manager(self):
        """Test manual review manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            forensic = ForensicIntegrity()
            
            # Create review manager with temp directory
            manager = ManualReviewManager(forensic)
            manager.review_file = Path(tmpdir) / "test_reviews.json"
            
            # Record a review decision
            manager.record_review_decision("msg_123", "include", "Important evidence")
            
            # Verify it was recorded
            assert "msg_123" in manager.reviews
            assert manager.reviews["msg_123"]["decision"] == "include"
            
            # Save and reload
            manager.save_reviews()
            assert manager.review_file.exists()
            
            # Create new manager and verify persistence
            manager2 = ManualReviewManager(forensic)
            manager2.review_file = manager.review_file
            manager2.load_reviews()
            assert "msg_123" in manager2.reviews
    
    def test_data_extraction_validation(self):
        """Test data extraction validation."""
        forensic = ForensicIntegrity()
        extractor = DataExtractor(forensic)
        
        # Create test messages
        test_messages = [
            {'message_id': '1', 'content': 'Test 1', 'timestamp': datetime.now(), 'source': 'test'},
            {'message_id': '2', 'content': 'Test 2', 'timestamp': datetime.now(), 'source': 'test'},
            {'message_id': '1', 'content': 'Duplicate', 'timestamp': datetime.now(), 'source': 'test'},  # Duplicate
        ]
        
        # Validate
        validation = extractor.validate_extraction(test_messages)
        
        assert validation['total_messages'] == 3
        assert validation['duplicate_count'] == 1
        assert 'test' in validation['sources']
        assert validation['sources']['test'] == 3

if __name__ == "__main__":
    pytest.main([__file__, "-v"])