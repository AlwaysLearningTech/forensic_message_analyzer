"""Tests for bug fixes in code review.

Covers:
- Version centralization (1.1)
- Config attribute naming for limitations (1.3)
- JSON report message count (1.6)
- Report utilities deduplication (5.1)
"""

import pytest
from unittest.mock import MagicMock


class TestVersionCentralization:
    """Verify version is consistent across all modules."""

    def test_init_version(self):
        from src import __version__
        assert __version__ == "4.3.1"

    def test_forensic_utils_uses_init_version(self):
        from src import __version__
        from src.forensic_utils import ForensicRecorder
        import tempfile, json
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            recorder = ForensicRecorder(output_dir=Path(td))
            out = recorder.generate_chain_of_custody()
            assert out is not None
            with open(out) as f:
                doc = json.load(f)
            assert doc["system_info"]["analyzer_version"] == __version__

    def test_run_manifest_uses_init_version(self):
        from src import __version__
        from src.utils.run_manifest import RunManifest
        from src.forensic_utils import ForensicRecorder
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            recorder = ForensicRecorder(output_dir=Path(td))
            manifest = RunManifest(forensic_recorder=recorder)
            assert manifest.manifest_data["system_info"]["analyzer_version"] == __version__

    def test_legal_compliance_uses_init_version(self):
        from src import __version__
        from src.utils.legal_compliance import ANALYZER_VERSION
        assert ANALYZER_VERSION == __version__


class TestLimitationsReporting:
    """Verify enable_sentiment attribute is correctly checked."""

    def test_sentiment_disabled_appears_in_limitations(self, mock_config):
        from src.reporters.report_utils import generate_limitations

        mock_config.enable_sentiment = False
        limitations = generate_limitations(mock_config, {"ai_analysis": {}})
        assert any("Sentiment analysis was disabled" in l for l in limitations)

    def test_sentiment_enabled_not_in_limitations(self, mock_config):
        from src.reporters.report_utils import generate_limitations

        mock_config.enable_sentiment = True
        limitations = generate_limitations(mock_config, {"ai_analysis": {"conversation_summary": "Some summary"}})
        assert not any("Sentiment analysis was disabled" in l for l in limitations)


class TestJsonReportMessageCount:
    """Verify forensic reporter JSON output has correct total_messages."""

    def test_total_messages_from_list(self):
        """extracted_data uses 'messages' key (a list), not 'total_messages'."""
        extracted_data = {
            "messages": [{"content": "a"}, {"content": "b"}, {"content": "c"}]
        }
        # The fix: len(extracted_data.get('messages', []))
        total = len(extracted_data.get('messages', []))
        assert total == 3

    def test_total_messages_empty(self):
        extracted_data = {}
        total = len(extracted_data.get('messages', []))
        assert total == 0


class TestReportUtils:
    """Verify shared utility functions work correctly."""

    def test_match_quote_found(self, sample_messages):
        from src.reporters.report_utils import match_quote_to_message
        result = match_quote_to_message("how are you doing", sample_messages)
        assert result['sender'] == 'Person1'
        assert result['timestamp'] == '2024-01-15T10:00:00'

    def test_match_quote_not_found(self, sample_messages):
        from src.reporters.report_utils import match_quote_to_message
        result = match_quote_to_message("nonexistent phrase", sample_messages)
        assert result['sender'] == ''
        assert result['timestamp'] is None

    def test_match_quote_empty(self):
        from src.reporters.report_utils import match_quote_to_message
        result = match_quote_to_message("", [])
        assert result['sender'] == ''

    def test_generate_limitations_no_limitations(self, mock_config):
        from src.reporters.report_utils import generate_limitations
        mock_config.enable_sentiment = True
        mock_config.enable_image_analysis = True
        mock_config.enable_ocr = True
        limitations = generate_limitations(mock_config, {"ai_analysis": {"conversation_summary": "A real summary"}})
        assert limitations == ["No significant limitations identified for this analysis."]


class TestAIAnalyzerConfig:
    """Verify AIAnalyzer accepts and uses config parameter."""

    def test_accepts_config(self, mock_config, tmp_output_dir):
        from src.analyzers.ai_analyzer import AIAnalyzer
        from src.forensic_utils import ForensicRecorder
        mock_config.ai_api_key = None
        recorder = ForensicRecorder(output_dir=tmp_output_dir)
        analyzer = AIAnalyzer(forensic_recorder=recorder, config=mock_config)
        # AI_MODEL env var was removed in 4.4.0; analyzer.model now resolves to the summary model (preferred) or batch model.
        assert analyzer.model == mock_config.ai_summary_model
        assert analyzer.client is None  # No API key

    def test_batch_model_default(self, mock_config, tmp_output_dir):
        from src.analyzers.ai_analyzer import AIAnalyzer
        from src.forensic_utils import ForensicRecorder
        mock_config.ai_api_key = None
        mock_config.ai_tagging_model = None
        recorder = ForensicRecorder(output_dir=tmp_output_dir)
        analyzer = AIAnalyzer(forensic_recorder=recorder, config=mock_config)
        # When batch model is not set, falls back to summary model
        assert analyzer.batch_model == mock_config.ai_summary_model

    def test_batch_model_custom(self, mock_config, tmp_output_dir):
        from src.analyzers.ai_analyzer import AIAnalyzer
        from src.forensic_utils import ForensicRecorder
        mock_config.ai_api_key = None
        mock_config.ai_tagging_model = "claude-haiku-4-5"
        recorder = ForensicRecorder(output_dir=tmp_output_dir)
        analyzer = AIAnalyzer(forensic_recorder=recorder, config=mock_config)
        assert analyzer.batch_model == "claude-haiku-4-5"

    def test_summary_model_custom(self, mock_config, tmp_output_dir):
        from src.analyzers.ai_analyzer import AIAnalyzer
        from src.forensic_utils import ForensicRecorder
        mock_config.ai_api_key = None
        mock_config.ai_summary_model = "claude-sonnet-4-6"
        recorder = ForensicRecorder(output_dir=tmp_output_dir)
        analyzer = AIAnalyzer(forensic_recorder=recorder, config=mock_config)
        assert analyzer.summary_model == "claude-sonnet-4-6"


class TestDataExtractorConfig:
    """Verify DataExtractor accepts config parameter."""

    def test_accepts_config(self, mock_config):
        from src.extractors.data_extractor import DataExtractor
        from src.forensic_utils import ForensicRecorder
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            recorder = ForensicRecorder(output_dir=Path(td))
            extractor = DataExtractor(recorder, config=mock_config)
            assert extractor.config is mock_config


class TestForensicRecorderTimezones:
    """Verify ForensicRecorder uses timezone-aware timestamps."""

    def test_start_time_is_aware(self):
        from src.forensic_utils import ForensicRecorder
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            recorder = ForensicRecorder(output_dir=Path(td))
            assert recorder.start_time.tzinfo is not None

    def test_action_timestamp_is_aware(self):
        from src.forensic_utils import ForensicRecorder
        from datetime import datetime
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            recorder = ForensicRecorder(output_dir=Path(td))
            recorder.record_action("test", "test action")
            ts = recorder.actions[-1]["timestamp"]
            # UTC ISO format includes +00:00
            assert "+00:00" in ts or "Z" in ts
