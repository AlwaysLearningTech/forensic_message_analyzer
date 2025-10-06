"""Test forensic utilities."""

import pytest
from pathlib import Path
import tempfile
import json
from src.forensic_utils import ForensicRecorder, ForensicIntegrity


def test_forensic_recorder_initialization():
    """Test ForensicRecorder can be initialized."""
    recorder = ForensicRecorder()
    assert recorder is not None
    assert hasattr(recorder, 'actions')


def test_forensic_recorder_action_recording():
    """Test recording forensic actions."""
    recorder = ForensicRecorder()
    
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


def test_forensic_integrity_initialization():
    """Test ForensicIntegrity can be initialized."""
    recorder = ForensicRecorder()
    integrity = ForensicIntegrity(recorder)
    assert integrity is not None
    assert integrity.forensic == recorder


def test_hash_computation():
    """Test file hash computation."""
    recorder = ForensicRecorder()
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Test content for hashing")
        temp_path = Path(f.name)
    
    try:
        # Compute hash
        file_hash = recorder.compute_hash(temp_path)
        assert file_hash is not None
        assert len(file_hash) == 64  # SHA-256 hash length in hex
        
        # Verify same file produces same hash
        hash2 = recorder.compute_hash(temp_path)
        assert file_hash == hash2
    finally:
        temp_path.unlink()


def test_chain_of_custody_generation():
    """Test chain of custody generation."""
    recorder = ForensicRecorder()
    
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
    
    # Clean up
    Path(chain_path).unlink()


def test_forensic_integrity_verify_read_only():
    """Test read-only verification."""
    recorder = ForensicRecorder()
    integrity = ForensicIntegrity(recorder)
    
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Test content")
        temp_path = Path(f.name)
    
    try:
        # Verify file exists and can be checked
        result = integrity.verify_read_only(temp_path)
        # Result might be True or False depending on permissions
        assert isinstance(result, bool)
    finally:
        temp_path.unlink()


def test_forensic_integrity_working_copy():
    """Test creating working copies."""
    recorder = ForensicRecorder()
    integrity = ForensicIntegrity(recorder)
    
    # Create a temporary source file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Original content")
        source_path = Path(f.name)
    
    try:
        # Create working copy
        with tempfile.TemporaryDirectory() as temp_dir:
            dest_dir = Path(temp_dir)
            working_copy = integrity.create_working_copy(source_path, dest_dir)
            
            assert working_copy is not None
            assert working_copy.exists()
            assert working_copy.read_text() == "Original content"
            assert working_copy != source_path
    finally:
        source_path.unlink()
