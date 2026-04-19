"""Shared pytest fixtures for forensic message analyzer tests."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Provide a temporary output directory for tests."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def mock_config(tmp_output_dir):
    """Create a Config-like object with test-safe defaults (no real API keys)."""
    config = MagicMock()
    config.output_dir = str(tmp_output_dir)
    config.ai_api_key = None
    config.ai_endpoint = None
    config.ai_batch_model = "claude-haiku-4-5"
    config.ai_summary_model = "claude-sonnet-4-5"
    config.batch_size = 50
    config.use_batch_api = True
    config.max_tokens_per_request = 4096
    config.tokens_per_minute = 25000
    config.max_requests_per_minute = 40
    config.person1_name = "Person1"
    config.contact_mappings = {"Person1": [], "Person2": []}
    config.case_name = "Test Case"
    config.case_number = "TEST-001"
    config.examiner_name = "Test Examiner"
    config.organization = "Test Org"
    config.timezone = "America/Los_Angeles"
    config.enable_sentiment = True
    config.enable_image_analysis = True
    config.enable_ocr = True
    config.messages_db_path = None
    config.whatsapp_source_dir = None
    config.email_source_dir = None
    config.teams_source_dir = None
    config.screenshot_source_dir = None
    config.counseling_source_dir = None
    config.counseling_correlation_window_hours = 48
    config.start_date = None
    config.end_date = None
    config.review_dir = str(tmp_output_dir / "review")
    return config


@pytest.fixture
def sample_messages():
    """Provide a list of synthetic message dicts for testing."""
    return [
        {
            "timestamp": "2024-01-15T10:00:00",
            "sender": "Person1",
            "recipient": "Person2",
            "content": "Hello, how are you doing today?",
            "source": "imessage",
        },
        {
            "timestamp": "2024-01-15T10:05:00",
            "sender": "Person2",
            "recipient": "Person1",
            "content": "I'm doing well, thanks for asking.",
            "source": "imessage",
        },
        {
            "timestamp": "2024-01-15T10:10:00",
            "sender": "Person1",
            "recipient": "Person2",
            "content": "We need to discuss the schedule for this week.",
            "source": "imessage",
        },
        {
            "timestamp": "2024-01-15T10:15:00",
            "sender": "Person2",
            "recipient": "Person1",
            "content": "Sure, let me check my calendar and get back to you.",
            "source": "imessage",
        },
        {
            "timestamp": "2024-01-15T10:20:00",
            "sender": "Person1",
            "recipient": "Person2",
            "content": "That sounds good. Please let me know today.",
            "source": "imessage",
        },
    ]
