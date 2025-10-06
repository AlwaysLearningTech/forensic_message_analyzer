import pytest
import pandas as pd
from pathlib import Path
from datetime import datetime
import tempfile
import sqlite3

from src.forensic_utils import ForensicIntegrity
from src.extractors.imessage_extractor import iMessageExtractor
from src.extractors.whatsapp_extractor import WhatsAppExtractor

class TestiMessageExtractor:
    """Test iMessage extraction functionality."""
    
    def test_message_id_generation(self):
        """Test unique ID generation for messages."""
        forensic = ForensicIntegrity()
        extractor = iMessageExtractor(forensic)
        
        # Test with GUID
        row = pd.Series({'guid': 'test-guid-123', 'message_id': 1})
        result = extractor._generate_message_id(row)
        assert result == 'imessage_test-guid-123'
        
        # Test without GUID
        row = pd.Series({'message_id': 1, 'date': '2024-01-01', 'handle_id': 'test@example.com', 'text': 'Hello'})
        result = extractor._generate_message_id(row)
        assert result.startswith('imessage_composite_')
    
    def test_validation(self):
        """Test extraction validation."""
        forensic = ForensicIntegrity()
        extractor = iMessageExtractor(forensic)
        
        # Create test DataFrame
        df = pd.DataFrame({
            'unique_id': ['id1', 'id2', 'id1'],  # Duplicate
            'content': ['Hello', None, 'World'],  # One null
            'timestamp': [datetime(2024, 1, 1), datetime(2024, 1, 2), datetime(2024, 1, 3)]
        })
        
        validation = extractor.validate_extraction(df)
        
        assert validation['total_messages'] == 3
        assert validation['duplicates_found'] == 1
        assert validation['null_content'] == 1

class TestWhatsAppExtractor:
    """Test WhatsApp extraction functionality."""
    
    def test_unicode_cleaning(self):
        """Test Unicode character cleaning."""
        forensic = ForensicIntegrity()
        extractor = WhatsAppExtractor(forensic)
        
        # Test string with problematic Unicode
        text = "Hello\u200bWorld\ufeff!"
        cleaned = extractor._clean_unicode(text)
        assert cleaned == "HelloWorld!"
    
    def test_timestamp_parsing(self):
        """Test various timestamp formats."""
        forensic = ForensicIntegrity()
        extractor = WhatsAppExtractor(forensic)
        
        # US format
        ts1 = extractor._parse_timestamp("1/15/24, 2:30:45 PM")
        assert ts1.hour == 14
        assert ts1.minute == 30
        
        # EU format
        ts2 = extractor._parse_timestamp("15/1/24, 14:30")
        assert ts2.hour == 14
        assert ts2.minute == 30
    
    def test_pattern_detection(self):
        """Test WhatsApp format pattern detection."""
        forensic = ForensicIntegrity()
        extractor = WhatsAppExtractor(forensic)
        
        sample_lines = [
            "[1/15/24, 2:30:45 PM] John: Hello world",
            "[1/15/24, 2:31:00 PM] Jane: Hi there"
        ]
        
        pattern = extractor._auto_detect_pattern(sample_lines)
        assert pattern is not None
