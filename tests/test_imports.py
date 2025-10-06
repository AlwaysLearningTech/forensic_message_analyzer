#!/usr/bin/env python3
"""
Test module imports and dependencies.
"""

import pytest


def test_imports():
    """Test that all required modules can be imported."""
    try:
        # Core modules
        import src.config
        import src.forensic_utils
        import src.main
        
        # Extractors
        import src.extractors.data_extractor
        import src.extractors.imessage_extractor
        import src.extractors.whatsapp_extractor
        import src.extractors.screenshot_extractor
        
        # Analyzers
        import src.analyzers.threat_analyzer
        import src.analyzers.sentiment_analyzer
        import src.analyzers.behavioral_analyzer
        import src.analyzers.yaml_pattern_analyzer
        import src.analyzers.screenshot_analyzer
        import src.analyzers.attachment_processor
        import src.analyzers.communication_metrics
        import src.analyzers.ai_analyzer
        
        # Review
        import src.review.manual_review_manager
        
        # Reporters
        import src.reporters.forensic_reporter
        import src.reporters.json_reporter
        import src.reporters.excel_reporter
        
        # Utils
        import src.utils.timeline_generator
        import src.utils.run_manifest
        
        # Required external dependencies
        import pandas
        import numpy
        import yaml
        import pytesseract
        from PIL import Image
        import openpyxl
        from docx import Document
        from reportlab.lib.pagesizes import letter
        
        # Optional but included
        try:
            import plotly
        except ImportError:
            print("Note: plotly not installed - visualization features will be limited")
        
        # All core imports successful
        assert True, "All required imports successful"
        
    except ImportError as e:
        pytest.fail(f"Import failed: {str(e)}")


def test_config_loads():
    """Test that configuration loads properly."""
    from src.config import Config
    
    config = Config()
    assert config is not None
    assert hasattr(config, 'output_dir')


def test_forensic_utils_available():
    """Test forensic utilities are available."""
    from src.forensic_utils import ForensicRecorder, ForensicIntegrity
    
    recorder = ForensicRecorder()
    assert recorder is not None