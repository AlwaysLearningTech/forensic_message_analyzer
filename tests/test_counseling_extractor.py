"""
Tests for CounselingExtractor.
"""

import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, call

from src.extractors.counseling_extractor import CounselingExtractor


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _write_yaml(directory, content):
    """Write a counseling_sessions.yaml file to directory."""
    yaml_path = directory / "counseling_sessions.yaml"
    yaml_path.write_text(content, encoding="utf-8")
    return yaml_path


def _make_dummy_pdf(directory, filename="test.pdf"):
    """Create a minimal PDF file (not valid for pdfplumber but sufficient for hashing tests)."""
    pdf_path = directory / filename
    pdf_path.write_bytes(b"%PDF-1.4 dummy content")
    return pdf_path


def _make_extractor(source_dir, config=None):
    """Create a CounselingExtractor with mock forensic objects."""
    forensic = MagicMock()
    forensic.compute_hash = MagicMock(return_value="abc123hash")
    forensic.record_action = MagicMock()

    integrity = MagicMock()
    integrity.compute_and_record_hash = MagicMock()

    if config is None:
        config = MagicMock()
        config.person1_name = "Person1"
        config.counseling_correlation_window_hours = 48

    extractor = CounselingExtractor(
        source_dir=str(source_dir),
        forensic_recorder=forensic,
        forensic_integrity=integrity,
        config=config,
    )
    return extractor, forensic, integrity


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestCounselingExtractor:

    def test_extract_basic_sessions(self, tmp_path):
        """YAML with 2 sessions returns 2 correctly shaped dicts."""
        _write_yaml(tmp_path, """
sessions:
  - date: "2024-03-15"
    topic: "Anxiety management"
    notes: "Discussed coping strategies for anxiety."
    provider: "Dr. Smith"
  - date: "2024-03-22"
    topic: "Co-parenting communication"
    notes: "Reviewed text messages from the week."
""")
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()

        assert len(results) == 2

        # Check required fields on first session
        session = results[0]
        assert session['source'] == 'counseling'
        assert session['content'] == "Discussed coping strategies for anxiety."
        assert session['topic'] == "Anxiety management"
        assert session['sender'] == "Dr. Smith"
        assert session['recipient'] == "Person1"
        assert session['is_counseling_event'] is True
        assert session['message_id'].startswith("counseling_2024-03-15_")
        assert session['timestamp'] is not None

    def test_extract_minimal_fields(self, tmp_path):
        """Session with only required fields (date, topic, notes) works."""
        _write_yaml(tmp_path, """
sessions:
  - date: "2024-06-01"
    topic: "Initial assessment"
    notes: "First session intake."
""")
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()

        assert len(results) == 1
        assert results[0]['sender'] == 'Counselor'  # default when no provider
        assert results[0]['provider'] == ''
        assert results[0]['pdf_file'] == ''
        assert results[0]['pdf_text'] == ''

    def test_no_yaml_returns_empty(self, tmp_path):
        """Source directory with no YAML file returns empty list."""
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()
        assert results == []

    def test_empty_sessions_returns_empty(self, tmp_path):
        """YAML with empty sessions list returns empty list."""
        _write_yaml(tmp_path, """
sessions: []
""")
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()
        assert results == []

    def test_missing_date_skipped(self, tmp_path):
        """Session entry without a date field is skipped."""
        _write_yaml(tmp_path, """
sessions:
  - topic: "No date session"
    notes: "This has no date."
  - date: "2024-01-01"
    topic: "Valid session"
    notes: "This is valid."
""")
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()
        assert len(results) == 1
        assert results[0]['topic'] == "Valid session"

    def test_forensic_hashing(self, tmp_path):
        """Verify integrity hash is called for YAML and PDF files."""
        _write_yaml(tmp_path, """
sessions:
  - date: "2024-01-01"
    topic: "Test"
    notes: "Test notes."
""")
        _make_dummy_pdf(tmp_path, "extra.pdf")

        extractor, _, integrity = _make_extractor(tmp_path)
        extractor.extract_all()

        # Should hash the YAML file and the PDF file
        hash_calls = integrity.compute_and_record_hash.call_args_list
        hashed_files = [str(c[0][0]) for c in hash_calls]
        assert any("counseling_sessions.yaml" in f for f in hashed_files)
        assert any("extra.pdf" in f for f in hashed_files)

    def test_forensic_action_recorded(self, tmp_path):
        """Verify forensic action is recorded after extraction."""
        _write_yaml(tmp_path, """
sessions:
  - date: "2024-01-01"
    topic: "Test"
    notes: "Notes."
""")
        extractor, forensic, _ = _make_extractor(tmp_path)
        extractor.extract_all()

        forensic.record_action.assert_called_with(
            "counseling_extraction",
            "Extracted 1 counseling sessions from counseling_sessions.yaml"
        )

    def test_sorted_by_date(self, tmp_path):
        """Sessions are returned in chronological order regardless of YAML order."""
        _write_yaml(tmp_path, """
sessions:
  - date: "2024-06-15"
    topic: "Later session"
    notes: "Second."
  - date: "2024-01-10"
    topic: "Earlier session"
    notes: "First."
""")
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()

        assert len(results) == 2
        assert results[0]['topic'] == "Earlier session"
        assert results[1]['topic'] == "Later session"

    def test_deterministic_message_id(self, tmp_path):
        """Same session data produces the same message_id across runs."""
        yaml_content = """
sessions:
  - date: "2024-05-01"
    topic: "Consistency test"
    notes: "Same data."
"""
        _write_yaml(tmp_path, yaml_content)
        ext1, _, _ = _make_extractor(tmp_path)
        result1 = ext1.extract_all()

        ext2, _, _ = _make_extractor(tmp_path)
        result2 = ext2.extract_all()

        assert result1[0]['message_id'] == result2[0]['message_id']

    def test_pdf_file_missing_graceful(self, tmp_path):
        """Referencing a non-existent PDF logs a warning but still extracts."""
        _write_yaml(tmp_path, """
sessions:
  - date: "2024-01-01"
    topic: "Test"
    notes: "Notes."
    pdf_file: "nonexistent.pdf"
""")
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()

        assert len(results) == 1
        assert results[0]['pdf_file'] == "nonexistent.pdf"
        assert results[0]['pdf_text'] == ''

    def test_yml_extension_supported(self, tmp_path):
        """Also accept .yml extension."""
        yml_path = tmp_path / "counseling_sessions.yml"
        yml_path.write_text("""
sessions:
  - date: "2024-01-01"
    topic: "YML test"
    notes: "Notes."
""", encoding="utf-8")
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()
        assert len(results) == 1
        assert results[0]['topic'] == "YML test"

    def test_source_dir_not_found(self):
        """Non-existent source directory raises FileNotFoundError."""
        forensic = MagicMock()
        integrity = MagicMock()
        config = MagicMock()

        with pytest.raises(FileNotFoundError):
            CounselingExtractor(
                source_dir="/nonexistent/path",
                forensic_recorder=forensic,
                forensic_integrity=integrity,
                config=config,
            )

    def test_timestamps_are_utc(self, tmp_path):
        """Extracted timestamps are UTC-aware."""
        _write_yaml(tmp_path, """
sessions:
  - date: "2024-07-04"
    topic: "Independence"
    notes: "Notes."
""")
        extractor, _, _ = _make_extractor(tmp_path)
        results = extractor.extract_all()

        ts = results[0]['timestamp']
        assert ts.tzinfo is not None
        assert str(ts.tzinfo) == 'UTC'
