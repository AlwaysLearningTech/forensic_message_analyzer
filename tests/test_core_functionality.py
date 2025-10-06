"""
Core functionality tests for the forensic message analyzer.
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
from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
from src.analyzers.yaml_pattern_analyzer import YamlPatternAnalyzer
from src.analyzers.screenshot_analyzer import ScreenshotAnalyzer
from src.analyzers.attachment_processor import AttachmentProcessor
from src.analyzers.communication_metrics import CommunicationMetricsAnalyzer
from src.review.manual_review_manager import ManualReviewManager
from src.utils.timeline_generator import TimelineGenerator
from src.utils.run_manifest import RunManifest


class TestCoreComponents:
    """Test core system components."""
    
    def test_config_initialization(self):
        """Test configuration initialization."""
        config = Config()
        assert config is not None
        assert hasattr(config, 'output_dir')
        assert hasattr(config, 'review_dir')
    
    def test_forensic_recorder(self):
        """Test forensic recorder functionality."""
        recorder = ForensicRecorder()
        
        # Test action recording
        recorder.record_action("test_action", "Test description", {"key": "value"})
        assert len(recorder.actions) >= 1
        
        # Test hash computation
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test content")
            temp_path = Path(f.name)
        
        try:
            hash_value = recorder.compute_hash(temp_path)
            assert hash_value is not None
            assert len(hash_value) == 64  # SHA-256 hash
        finally:
            temp_path.unlink()
    
    def test_forensic_integrity(self):
        """Test forensic integrity checker."""
        recorder = ForensicRecorder()
        integrity = ForensicIntegrity(recorder)
        
        # Test working copy creation
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Original content")
            source_path = Path(f.name)
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                dest_dir = Path(temp_dir)
                working_copy = integrity.create_working_copy(source_path, dest_dir)
                assert working_copy.exists()
                assert working_copy.read_text() == "Original content"
        finally:
            source_path.unlink()
    
    def test_data_extractor(self):
        """Test data extraction orchestration."""
        recorder = ForensicRecorder()
        extractor = DataExtractor(recorder)
        
        # Test that the extractor initializes properly
        assert extractor.forensic is not None
        assert extractor.integrity is not None
        # Extractors might be None if config paths aren't set, which is OK for testing
        assert hasattr(extractor, 'imessage')
        assert hasattr(extractor, 'whatsapp')
    
    def test_threat_analyzer(self):
        """Test threat analysis."""
        recorder = ForensicRecorder()
        analyzer = ThreatAnalyzer(recorder)
        
        # Create test data
        test_data = pd.DataFrame({
            'content': [
                'Hello there',
                'I will hurt you',
                'This is harassment',
                'Normal message'
            ],
            'sender': ['user1', 'user2', 'user2', 'user1'],
            'timestamp': pd.date_range(start='2024-01-01', periods=4, freq='h')
        })
        
        # Analyze threats - returns DataFrame with threat_detected column
        results = analyzer.detect_threats(test_data)
        assert isinstance(results, pd.DataFrame)
        assert 'threat_detected' in results.columns
        # Note: may not have threat_score if no threats detected
        
        # Generate summary
        summary = analyzer.generate_threat_summary(results)
        assert isinstance(summary, dict)
    
    def test_sentiment_analyzer(self):
        """Test sentiment analysis."""
        recorder = ForensicRecorder()
        analyzer = SentimentAnalyzer(recorder)
        
        # Create test data
        test_data = pd.DataFrame({
            'content': [
                'I love this!',
                'This is terrible',
                'It is okay',
                'Amazing work!'
            ],
            'sender': ['user1', 'user2', 'user1', 'user2'],
            'timestamp': pd.date_range(start='2024-01-01', periods=4, freq='h')
        })
        
        # Analyze sentiment - returns DataFrame with sentiment columns
        results = analyzer.analyze_sentiment(test_data)
        assert isinstance(results, pd.DataFrame)
        assert 'sentiment_polarity' in results.columns
        assert 'sentiment_subjectivity' in results.columns
    
    def test_behavioral_analyzer(self):
        """Test behavioral analysis."""
        recorder = ForensicRecorder()
        analyzer = BehavioralAnalyzer(recorder)
        
        # Create test data
        test_data = pd.DataFrame({
            'content': ['msg1', 'msg2', 'msg3', 'msg4'],
            'sender': ['user1', 'user1', 'user2', 'user1'],
            'timestamp': pd.date_range(start='2024-01-01', periods=4, freq='h')
        })
        
        # Analyze behavior - check actual method name
        results = analyzer.analyze_patterns(test_data)
        assert isinstance(results, dict)
    
    def test_pattern_analyzer(self):
        """Test YAML pattern analysis."""
        recorder = ForensicRecorder()
        
        # Use a non-existent patterns file to force default patterns
        # This avoids issues with the existing YAML having a different structure
        with tempfile.TemporaryDirectory() as temp_dir:
            patterns_path = Path(temp_dir) / "test_patterns.yaml"
            analyzer = YamlPatternAnalyzer(recorder, patterns_file=patterns_path)
            
            # Create test data
            test_data = pd.DataFrame({
                'content': [
                    'Send money to account 12345',
                    'Normal message',
                    'Click this link http://suspicious.com',
                    'Hello there'
                ],
                'sender': ['user1', 'user2', 'user1', 'user2'],
                'timestamp': pd.date_range(start='2024-01-01', periods=4, freq='h')
            })
            
            # Analyze patterns - returns DataFrame with pattern columns
            results = analyzer.analyze_patterns(test_data)
            assert isinstance(results, pd.DataFrame)
            assert 'patterns_detected' in results.columns
            assert 'pattern_score' in results.columns
    
    def test_manual_review_manager(self):
        """Test manual review functionality."""
        manager = ManualReviewManager()
        
        # Test adding a review - add_review doesn't return anything
        manager.add_review(
            'msg_001',
            'message', 
            'relevant',
            'This message contains threats'
        )
        
        # Verify the review was added
        assert len(manager.reviews) > 0
        
        # Test retrieving reviews by decision
        relevant_reviews = manager.get_reviews_by_decision('relevant')
        assert len(relevant_reviews) == 1
        assert relevant_reviews[0]['item_id'] == 'msg_001'
        
        # Test review summary
        summary = manager.get_review_summary()
        assert summary['total_reviews'] == 1
        assert summary['decisions']['relevant'] == 1
    
    def test_timeline_generator(self):
        """Test timeline generation."""
        recorder = ForensicRecorder()
        generator = TimelineGenerator(recorder)
        
        # Create test data
        test_data = pd.DataFrame({
            'content': ['Message 1', 'Message 2'],
            'sender': ['user1', 'user2'],
            'timestamp': pd.date_range(start='2024-01-01', periods=2, freq='h'),
            'threat_detected': [False, True]
        })
        
        # Create timeline with output path
        with tempfile.TemporaryDirectory() as temp_dir:
            timeline_path = Path(temp_dir) / "timeline.html"
            generator.create_timeline(test_data, timeline_path)
            
            # Should create the file
            assert timeline_path.exists()
    
    def test_run_manifest(self):
        """Test run manifest generation."""
        recorder = ForensicRecorder()
        manifest = RunManifest(recorder)
        
        # Create temporary files to add
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Input file")
            input_path = Path(f.name)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Output file")
            output_path = Path(f.name)
        
        try:
            # Add files to manifest
            manifest.add_input_file(input_path)
            manifest.add_output_file(output_path)
            
            # Generate manifest - returns Path
            manifest_path = manifest.generate_manifest()
            assert isinstance(manifest_path, Path)
            assert manifest_path.exists()
            
            # Clean up
            manifest_path.unlink()
        finally:
            input_path.unlink()
            output_path.unlink()
    
    def test_communication_metrics(self):
        """Test communication metrics analysis."""
        analyzer = CommunicationMetricsAnalyzer()
        
        # Create test messages list (not DataFrame)
        test_messages = [
            {'content': 'Hello', 'sender': 'user1', 'recipient': 'user2', 'timestamp': '2024-01-01 00:00:00'},
            {'content': 'Hi there', 'sender': 'user2', 'recipient': 'user1', 'timestamp': '2024-01-01 01:00:00'},
            {'content': 'How are you?', 'sender': 'user1', 'recipient': 'user2', 'timestamp': '2024-01-01 02:00:00'},
            {'content': 'Good thanks', 'sender': 'user2', 'recipient': 'user1', 'timestamp': '2024-01-01 03:00:00'}
        ]
        
        # Analyze metrics - correct method name is analyze_messages() and takes list, not DataFrame
        results = analyzer.analyze_messages(test_messages)
        assert isinstance(results, dict)