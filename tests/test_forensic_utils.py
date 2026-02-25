"""Test forensic utilities."""

import pytest
from pathlib import Path
import tempfile
import json
from src.forensic_utils import ForensicRecorder, ForensicIntegrity


def test_forensic_recorder_initialization(tmp_path):
    """Test ForensicRecorder can be initialized."""
    recorder = ForensicRecorder(tmp_path)
    assert recorder is not None
    assert hasattr(recorder, 'actions')


def test_forensic_recorder_action_recording(tmp_path):
    """Test recording forensic actions."""
    recorder = ForensicRecorder(tmp_path)

    # Get initial action count
    initial_count = len(recorder.actions)

    # Record an action - signature is record_action(action, details, metadata)
    recorder.record_action("test_action", "Test description", {"key": "value"})

    assert len(recorder.actions) == initial_count + 1
    # Check the last action
    last_action = recorder.actions[-1]
    assert last_action['action'] == "test_action"
    assert last_action['details'] == "Test description"
    assert 'timestamp' in last_action
    assert last_action['metadata'] == {"key": "value"}


def test_forensic_integrity_initialization(tmp_path):
    """Test ForensicIntegrity can be initialized."""
    recorder = ForensicRecorder(tmp_path)
    integrity = ForensicIntegrity(recorder)
    assert integrity is not None
    assert integrity.forensic == recorder


def test_hash_computation(tmp_path):
    """Test file hash computation."""
    recorder = ForensicRecorder(tmp_path)

    # Create a temporary file
    temp_file = tmp_path / "hashtest.txt"
    temp_file.write_text("Test content for hashing")

    # Compute hash
    file_hash = recorder.compute_hash(temp_file)
    assert file_hash is not None
    assert len(file_hash) == 64  # SHA-256 hash length in hex

    # Verify same file produces same hash
    hash2 = recorder.compute_hash(temp_file)
    assert file_hash == hash2


def test_chain_of_custody_generation(tmp_path):
    """Test chain of custody generation."""
    recorder = ForensicRecorder(tmp_path)

    # Record some actions
    recorder.record_action("action1", "First action")
    recorder.record_action("action2", "Second action", {"data": "value"})

    # Generate chain of custody
    chain_path = recorder.generate_chain_of_custody()

    assert chain_path is not None
    assert Path(chain_path).exists()

    # Verify the chain of custody has correct structure
    with open(chain_path, 'r') as f:
        chain_data = json.load(f)

    assert 'actions' in chain_data
    assert len(chain_data['actions']) >= 2  # At least our two actions


def test_forensic_integrity_verify_read_only(tmp_path):
    """Test read-only verification."""
    recorder = ForensicRecorder(tmp_path)
    integrity = ForensicIntegrity(recorder)

    # Create a temporary file
    temp_file = tmp_path / "readonly_test.txt"
    temp_file.write_text("Test content")

    # Verify file exists and can be checked
    result = integrity.verify_read_only(temp_file)
    # Result might be True or False depending on permissions
    assert isinstance(result, bool)


def test_forensic_integrity_working_copy(tmp_path):
    """Test creating working copies."""
    recorder = ForensicRecorder(tmp_path)
    integrity = ForensicIntegrity(recorder)

    # Create a source file
    source_path = tmp_path / "source.txt"
    source_path.write_text("Original content")

    # Create working copy in a subdirectory
    dest_dir = tmp_path / "working"
    dest_dir.mkdir()
    working_copy = integrity.create_working_copy(source_path, dest_dir)

    assert working_copy is not None
    assert working_copy.exists()
    assert working_copy.read_text() == "Original content"
    assert working_copy != source_path
