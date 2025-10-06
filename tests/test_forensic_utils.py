import pytest
import tempfile
from pathlib import Path
import json

from src.forensic_utils import ForensicIntegrity, DaubertCompliance

class TestForensicIntegrity:
    """Test forensic integrity functionality."""
    
    def test_file_hashing(self):
        """Test SHA-256 file hashing."""
        forensic = ForensicIntegrity()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Test content for hashing")
            temp_path = Path(f.name)
        
        try:
            # Generate hash
            hash1 = forensic.hash_file(temp_path)
            assert len(hash1) == 64  # SHA-256 produces 64 character hex string
            
            # Verify consistency
            hash2 = forensic.hash_file(temp_path)
            assert hash1 == hash2
            
        finally:
            temp_path.unlink()
    
    def test_chain_of_custody(self):
        """Test chain of custody recording."""
        forensic = ForensicIntegrity("TEST_CASE_001")
        
        # Create test file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Evidence content")
            temp_path = Path(f.name)
        
        try:
            # Record source
            record = forensic.record_source(temp_path, "Test Evidence")
            
            assert record['source_type'] == "Test Evidence"
            assert 'hash' in record
            assert 'timestamp' in record
            assert len(forensic.chain_of_custody) == 1
            
            # Verify integrity
            assert forensic.verify_integrity(temp_path) == True
            
            # Modify file and check integrity fails
            with open(temp_path, 'a') as f:
                f.write("Modified")
            
            assert forensic.verify_integrity(temp_path) == False
            
        finally:
            temp_path.unlink()
    
    def test_operation_logging(self):
        """Test operation logging."""
        forensic = ForensicIntegrity()
        
        # Log operations
        forensic.log_operation("Test Operation", {"detail": "test value"})
        forensic.log_operation("Another Operation", {"count": 42})
        
        assert len(forensic.operation_log) == 2
        assert forensic.operation_log[0]['operation'] == "Test Operation"
        assert forensic.operation_log[1]['details']['count'] == 42

class TestDaubertCompliance:
    """Test Daubert compliance documentation."""
    
    def test_methodology_documentation(self):
        """Test that methodology is properly documented."""
        methodology = DaubertCompliance.document_methodology()
        
        # Check all five Daubert factors are addressed
        required_factors = ['testing', 'peer_review', 'error_rate', 'standards', 'acceptance']
        for factor in required_factors:
            assert factor in methodology
            assert len(methodology[factor]) > 50  # Ensure substantial documentation
    
    def test_limitations_documentation(self):
        """Test that limitations are documented."""
        limitations = DaubertCompliance.document_limitations()
        
        # Check key limitation categories
        required_categories = ['temporal', 'linguistic', 'technical', 'contextual', 'completeness']
        for category in required_categories:
            assert category in limitations
            assert len(limitations[category]) > 30  # Ensure meaningful description
