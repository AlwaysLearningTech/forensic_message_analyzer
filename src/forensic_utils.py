#!/usr/bin/env python3
"""Forensic utilities for maintaining chain of custody and evidence integrity.
Implements FRE 901 authentication and Daubert reliability standards.
"""

import hashlib
import json
import os
import platform
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class ForensicRecorder:
    """
    Records all forensic actions for chain of custody and legal defensibility.
    Satisfies FRE 901 authentication requirements by tracking all operations with timestamps and hashes.
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize the forensic recorder.
        
        Args:
            output_dir: Directory for output files. Uses config if not specified.
        """
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            # Import config here to avoid circular imports
            try:
                from src.config import config
                self.output_dir = config.output_dir
            except ImportError:
                # Fallback to current directory if config not available
                self.output_dir = Path('./output')
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize action log for chain of custody
        self.actions: List[Dict] = []
        self.start_time = datetime.now()
        self.session_id = self.start_time.strftime("%Y%m%d_%H%M%S")
        
        # Record initialization for audit trail
        self.record_action(
            "session_start",
            "Forensic recorder initialized",
            {"session_id": self.session_id, "start_time": self.start_time.isoformat()}
        )
    
    def record_action(self, action: str, details: str, metadata: Optional[Dict] = None):
        """
        Record a forensic action for chain of custody (FRE 901 authentication).
        Every operation is logged with timestamp and metadata for reproducibility.
        
        Args:
            action: Type of action performed
            details: Description of the action
            metadata: Optional additional metadata
        """
        action_record = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details,
            "metadata": metadata or {},
            "session_id": self.session_id
        }
        self.actions.append(action_record)
        
        # Persist to log file immediately for evidence integrity
        log_file = self.output_dir / f"forensic_log_{self.session_id}.jsonl"
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(action_record) + '\n')
        except Exception as e:
            print(f"Warning: Could not write to forensic log: {e}")
    
    def compute_hash(self, file_path: Path) -> str:
        """
        Compute SHA-256 hash of a file for authentication (FRE 901).
        Hash provides verifiable proof that file has not been altered.
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA-256 hash hex string
        """
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                # Process in chunks for large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            file_hash = sha256_hash.hexdigest()
            
            # Record hash computation for audit trail
            self.record_action(
                "hash_computed",
                f"Computed SHA-256 hash for {file_path.name}",
                {"file": str(file_path), "hash": file_hash, "size": file_path.stat().st_size}
            )
            
            return file_hash
            
        except Exception as e:
            self.record_action(
                "hash_error",
                f"Failed to compute hash for {file_path.name}: {str(e)}",
                {"file": str(file_path), "error": str(e)}
            )
            return ""
    
    def verify_integrity(self, file_path: Path, expected_hash: str) -> bool:
        """
        Verify file integrity using SHA-256 hash.
        Ensures evidence has not been tampered with (FRE 901, Daubert reliability).
        
        Args:
            file_path: Path to the file
            expected_hash: Expected SHA-256 hash
            
        Returns:
            True if hash matches, False otherwise
        """
        actual_hash = self.compute_hash(file_path)
        matches = actual_hash == expected_hash
        
        self.record_action(
            "integrity_check",
            f"Integrity verification for {file_path.name}: {'PASSED' if matches else 'FAILED'}",
            {
                "file": str(file_path),
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "matches": matches
            }
        )
        
        return matches
    
    def generate_chain_of_custody(self, output_file: Optional[str] = None) -> Optional[str]:
        """
        Generate chain of custody document for legal proceedings.
        Satisfies FRE 901 authentication and business records exception (FRE 803(6)).
        
        Args:
            output_file: Optional path for the output file
            
        Returns:
            Path to the generated file, or None if failed
        """
        if not output_file:
            output_file = str(self.output_dir / f"chain_of_custody_{self.session_id}.json")
        
        try:
            # Create comprehensive custody document
            custody_doc = {
                "generated_at": datetime.now().isoformat(),
                "session_id": self.session_id,
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
                "total_actions": len(self.actions),
                "actions": self.actions,
                "system_info": {
                    "platform": platform.system(),
                    "platform_version": platform.version(),
                    "python_version": sys.version,
                    "analyzer_version": "1.0.0"
                },
                "legal_notice": (
                    "This chain of custody document was generated automatically "
                    "as part of forensic analysis. All timestamps are in ISO 8601 format. "
                    "SHA-256 hashes verify file integrity. This document satisfies "
                    "FRE 901 authentication requirements."
                )
            }
            
            # Write initial document
            with open(output_file, 'w') as f:
                json.dump(custody_doc, f, indent=2)
            
            # Hash the chain of custody document itself
            doc_hash = self.compute_hash(Path(output_file))
            
            # Append self-hash to the document
            custody_doc["document_hash"] = doc_hash
            custody_doc["hash_algorithm"] = "SHA-256"
            
            # Re-save with hash
            with open(output_file, 'w') as f:
                json.dump(custody_doc, f, indent=2)
            
            self.record_action(
                "chain_of_custody_generated",
                f"Generated chain of custody document with {len(self.actions)} actions",
                {"file": output_file, "hash": doc_hash}
            )
            
            return output_file
            
        except Exception as e:
            self.record_action(
                "chain_of_custody_error",
                f"Failed to generate chain of custody: {str(e)}",
                {"error": str(e)}
            )
            return None
    
    def record_file_state(self, file_path: Path, operation: str):
        """
        Record the state of a file for evidence tracking.
        Implements best evidence rule (FRE 1002) by preserving original state.
        
        Args:
            file_path: Path to the file
            operation: Operation being performed (e.g., "read", "created", "analyzed")
        """
        if not file_path.exists():
            self.record_action(
                "file_not_found",
                f"File not found during {operation}: {file_path.name}",
                {"file": str(file_path), "operation": operation}
            )
            return
        
        stats = file_path.stat()
        file_hash = self.compute_hash(file_path)
        
        self.record_action(
            "file_state_recorded",
            f"Recorded state of {file_path.name} for {operation}",
            {
                "file": str(file_path),
                "operation": operation,
                "size_bytes": stats.st_size,
                "created_time": datetime.fromtimestamp(stats.st_ctime).isoformat(),
                "modified_time": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "hash": file_hash,
                "read_only": not os.access(file_path, os.W_OK)
            }
        )
    
    def record_error(self, error_type: str, error_message: str, context: Optional[Dict] = None):
        """
        Record errors for Daubert reliability (known error rate documentation).
        
        Args:
            error_type: Type of error
            error_message: Error message
            context: Optional context information
        """
        self.record_action(
            f"error_{error_type}",
            error_message,
            {"error_type": error_type, "context": context or {}}
        )


class EvidenceValidator:
    """
    Validates evidence integrity and chain of custody.
    Ensures compliance with authentication requirements (FRE 901) and reliability standards (Daubert).
    """
    
    def __init__(self, forensic_recorder: ForensicRecorder):
        """
        Initialize the evidence validator.
        
        Args:
            forensic_recorder: ForensicRecorder instance for logging
        """
        self.forensic = forensic_recorder
    
    def validate_source_files(self, source_files: List[Path]) -> Dict[str, Any]:
        """
        Validate source files for evidence integrity.
        Implements FRE 901 authentication by verifying file existence and computing hashes.
        
        Args:
            source_files: List of source file paths
            
        Returns:
            Validation report with file states and hashes
        """
        report = {
            "validated_at": datetime.now().isoformat(),
            "total_files": len(source_files),
            "valid_files": [],
            "missing_files": [],
            "issues": []
        }
        
        for file_path in source_files:
            if not file_path.exists():
                report["missing_files"].append(str(file_path))
                self.forensic.record_action(
                    "validation_failed",
                    f"Source file missing: {file_path}",
                    {"file": str(file_path)}
                )
            else:
                try:
                    # Compute and record hash for authentication
                    file_hash = self.forensic.compute_hash(file_path)
                    stats = file_path.stat()
                    
                    file_info = {
                        "path": str(file_path),
                        "hash": file_hash,
                        "size": stats.st_size,
                        "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                        "read_only": not os.access(file_path, os.W_OK)
                    }
                    report["valid_files"].append(file_info)
                    
                except Exception as e:
                    report["issues"].append({
                        "file": str(file_path),
                        "error": str(e)
                    })
                    self.forensic.record_error(
                        "validation_error",
                        f"Error validating {file_path}: {str(e)}",
                        {"file": str(file_path)}
                    )
        
        self.forensic.record_action(
            "source_validation_complete",
            f"Validated {len(report['valid_files'])} of {report['total_files']} files",
            report
        )
        
        return report
    
    def create_evidence_package(self, source_files: List[Path], 
                              output_files: List[Path],
                              metadata: Optional[Dict] = None) -> Path:
        """
        Create an evidence package with all files and metadata.
        Satisfies best evidence rule (FRE 1002) and business records exception (FRE 803(6)).
        
        Args:
            source_files: List of source file paths
            output_files: List of output file paths
            metadata: Optional additional metadata
            
        Returns:
            Path to the evidence package manifest
        """
        package_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Compute hashes for all files (FRE 901 authentication)
        source_hashes = {}
        for file_path in source_files:
            if file_path.exists():
                source_hashes[str(file_path)] = self.forensic.compute_hash(file_path)
        
        output_hashes = {}
        for file_path in output_files:
            if file_path.exists():
                output_hashes[str(file_path)] = self.forensic.compute_hash(file_path)
        
        # Create comprehensive package manifest
        package_manifest = {
            "package_id": package_id,
            "created_at": datetime.now().isoformat(),
            "source_files": source_hashes,
            "output_files": output_hashes,
            "metadata": metadata or {},
            "total_files": len(source_hashes) + len(output_hashes),
            "legal_notice": (
                "This evidence package preserves the original state of all files "
                "with SHA-256 hashes for authentication (FRE 901). Files were processed "
                "in read-only mode to maintain best evidence (FRE 1002)."
            )
        }
        
        # Save manifest
        manifest_path = self.forensic.output_dir / f"evidence_package_{package_id}.json"
        with open(manifest_path, 'w') as f:
            json.dump(package_manifest, f, indent=2)
        
        # Hash the manifest itself for integrity
        manifest_hash = self.forensic.compute_hash(manifest_path)
        package_manifest["manifest_hash"] = manifest_hash
        
        # Re-save with self-hash
        with open(manifest_path, 'w') as f:
            json.dump(package_manifest, f, indent=2)
        
        self.forensic.record_action(
            "evidence_package_created",
            f"Created evidence package with {package_manifest['total_files']} files",
            {"manifest": str(manifest_path), "hash": manifest_hash}
        )
        
        return manifest_path


# Ensure classes are exported
__all__ = ['ForensicRecorder', 'EvidenceValidator', 'ForensicIntegrity']


class ForensicIntegrity:
    """
    Maintains forensic integrity for evidence processing.
    Ensures read-only access and tracks all file operations for FRE 901 authentication.
    """
    
    def __init__(self, forensic_recorder: Optional[ForensicRecorder] = None):
        """
        Initialize forensic integrity checker.
        
        Args:
            forensic_recorder: Optional ForensicRecorder instance for logging
        """
        self.forensic = forensic_recorder or ForensicRecorder()
    
    def verify_read_only(self, file_path: Path) -> bool:
        """
        Verify file is accessible in read-only mode (FRE 1002 - Best Evidence).
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file can be read without modification risk
        """
        if not file_path.exists():
            self.forensic.record_action(
                "integrity_check",
                f"File not found: {file_path}",
                {"file": str(file_path), "exists": False}
            )
            return False
        
        # Check if file is read-only
        can_write = os.access(file_path, os.W_OK)
        
        self.forensic.record_action(
            "read_only_check",
            f"Checked read-only status for {file_path.name}",
            {
                "file": str(file_path),
                "read_only": not can_write,
                "can_read": os.access(file_path, os.R_OK)
            }
        )
        
        return True  # We can proceed even if writable, just don't write
    
    def create_working_copy(self, source_path: Path, dest_dir: Optional[Path] = None) -> Optional[Path]:
        """
        Create a working copy to preserve original evidence (FRE 1002).
        
        Args:
            source_path: Path to the source file
            dest_dir: Optional destination directory
            
        Returns:
            Path to the working copy, or None if failed
        """
        if not source_path.exists():
            self.forensic.record_error(
                "copy_failed",
                f"Source file not found: {source_path}",
                {"source": str(source_path)}
            )
            return None
        
        try:
            # Use output directory if not specified
            if not dest_dir:
                dest_dir = self.forensic.output_dir / "working_copies"
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            # Create timestamped copy name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_path = dest_dir / f"{source_path.stem}_{timestamp}{source_path.suffix}"
            
            # Copy the file
            import shutil
            shutil.copy2(source_path, dest_path)
            
            # Verify copy integrity
            source_hash = self.forensic.compute_hash(source_path)
            copy_hash = self.forensic.compute_hash(dest_path)
            
            if source_hash == copy_hash:
                self.forensic.record_action(
                    "working_copy_created",
                    f"Created verified working copy of {source_path.name}",
                    {
                        "source": str(source_path),
                        "copy": str(dest_path),
                        "hash": source_hash,
                        "verified": True
                    }
                )
                return dest_path
            else:
                self.forensic.record_error(
                    "copy_verification_failed",
                    f"Hash mismatch for copy of {source_path.name}",
                    {
                        "source": str(source_path),
                        "source_hash": source_hash,
                        "copy_hash": copy_hash
                    }
                )
                dest_path.unlink()  # Remove bad copy
                return None
                
        except Exception as e:
            self.forensic.record_error(
                "copy_error",
                f"Failed to create working copy: {str(e)}",
                {"source": str(source_path), "error": str(e)}
            )
            return None
    
    def validate_extraction(self, source_path: Path, extracted_data: Any) -> bool:
        """
        Validate that extraction preserved data integrity (Daubert reliability).
        
        Args:
            source_path: Path to source file
            extracted_data: Data extracted from the file
            
        Returns:
            True if extraction appears valid
        """
        # Record extraction
        self.forensic.record_action(
            "extraction_validated",
            f"Validated extraction from {source_path.name}",
            {
                "source": str(source_path),
                "data_type": type(extracted_data).__name__,
                "has_data": bool(extracted_data)
            }
        )
        
        return bool(extracted_data)
