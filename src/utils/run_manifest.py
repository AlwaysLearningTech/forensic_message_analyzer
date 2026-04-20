"""
Run manifest generator for forensic analysis documentation.
Creates comprehensive manifest of all analysis operations for legal proceedings.
Satisfies FRE 901 authentication and Daubert reliability standards.
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import platform
import sys

from .. import __version__
from ..forensic_utils import ForensicRecorder


def _sign_if_possible(file_path: Path, forensic: ForensicRecorder):
    """Best-effort signing hook used by the manifest and final reports.

    Skips silently (logging an info-level note) if cryptography is not installed or the examiner key cannot be loaded. That way signing is opt-in in practice — it improves defensibility when available and never breaks the run when not.
    """
    try:
        from ..config import Config
        from .signing import Signer
        cfg = Config()
        key_path = getattr(cfg, "examiner_signing_key", None)
        run_dir = file_path.parent
        signer = Signer(key_path=Path(key_path) if key_path else None, run_dir=run_dir)
        sig_path, pub_path = signer.sign_file(file_path)
        forensic.record_action(
            "artifact_signed",
            f"Signed {file_path.name} with {'ephemeral run key' if signer.is_ephemeral else 'configured examiner key'}",
            {
                "file": str(file_path),
                "sig": str(sig_path),
                "public_key": str(pub_path),
                "ephemeral_key": signer.is_ephemeral,
            },
        )
        return sig_path
    except Exception as exc:
        forensic.record_action(
            "artifact_sign_skipped",
            f"Could not sign {file_path.name}: {exc}",
            {"file": str(file_path), "error": str(exc)},
        )
        return None


class RunManifest:
    """
    Generates run manifest documenting all forensic analysis operations.
    Provides complete audit trail for legal proceedings (FRE 803(6) business records).
    """
    
    def __init__(self, forensic_recorder: Optional[ForensicRecorder] = None, config=None):
        """
        Initialize the run manifest generator.

        Args:
            forensic_recorder: Optional ForensicRecorder for chain of custody
            config: Optional Config instance; when provided, its snapshot() is embedded in the manifest so the exact run configuration can be reproduced.
        """
        self.forensic = forensic_recorder or ForensicRecorder()
        self.manifest_data = {
            "created_at": datetime.now().isoformat(),
            "system_info": self._get_system_info(),
            "config_snapshot": config.snapshot() if config is not None and hasattr(config, "snapshot") else None,
            "pattern_files": {},
            "input_files": {},
            "output_files": {},
            "operations": [],
            "validation": {}
        }

        self.forensic.record_action(
            "manifest_initialized",
            "Run manifest generator initialized"
        )

        # Hash the bundled pattern YAML so opposing experts can verify that the same rule set was in effect during the run.
        self._hash_pattern_files()

    def _hash_pattern_files(self):
        """Hash every pattern YAML in patterns/ and attach to the manifest."""
        try:
            project_root = Path(__file__).resolve().parents[2]
        except IndexError:
            return
        patterns_dir = project_root / "patterns"
        if not patterns_dir.is_dir():
            return
        for yaml_path in sorted(patterns_dir.glob("*.yaml")):
            try:
                file_hash = self.forensic.compute_hash(yaml_path)
                stats = yaml_path.stat()
                self.manifest_data["pattern_files"][yaml_path.name] = {
                    "path": str(yaml_path),
                    "hash": file_hash,
                    "size_bytes": stats.st_size,
                    "modified": datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat(),
                }
            except Exception as e:
                self.forensic.record_error(
                    "pattern_hash_error",
                    f"Failed to hash pattern file {yaml_path.name}: {e}",
                    {"file": str(yaml_path)},
                )
    
    def _get_system_info(self) -> Dict[str, str]:
        """
        Collect system information for reproducibility (Daubert reliability).
        
        Returns:
            Dictionary containing system information
        """
        return {
            "platform": platform.platform(),
            "platform_version": platform.version(),
            "processor": platform.processor(),
            "python_version": sys.version,
            "python_implementation": platform.python_implementation(),
            "hostname": platform.node(),
            "analyzer_version": __version__
        }
    
    def add_input_file(self, file_path: Path, file_type: str = "unknown"):
        """
        Add input file to manifest with hash for authentication (FRE 901).
        
        Args:
            file_path: Path to the input file
            file_type: Type of file (e.g., "imessage", "whatsapp", "screenshot")
        """
        if not file_path.exists():
            self.forensic.record_error(
                "manifest_input_missing",
                f"Input file not found: {file_path}",
                {"file": str(file_path)}
            )
            return
        
        # Compute hash for authentication
        file_hash = self.forensic.compute_hash(file_path)
        stats = file_path.stat()
        
        self.manifest_data["input_files"][str(file_path)] = {
            "path": str(file_path),
            "type": file_type,
            "hash": file_hash,
            "size_bytes": stats.st_size,
            "modified": datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat(),
            "added_to_manifest": datetime.now().isoformat()
        }
        
        self.forensic.record_action(
            "manifest_input_added",
            f"Added input file to manifest: {file_path.name}",
            {"file": str(file_path), "hash": file_hash}
        )
    
    def add_output_file(self, file_path: Path, file_type: str = "unknown", 
                       description: Optional[str] = None):
        """
        Add output file to manifest with hash for verification.
        
        Args:
            file_path: Path to the output file
            file_type: Type of file (e.g., "excel_report", "word_report", "pdf_report")
            description: Optional description of the file
        """
        if not file_path.exists():
            self.forensic.record_error(
                "manifest_output_missing",
                f"Output file not found: {file_path}",
                {"file": str(file_path)}
            )
            return
        
        # Compute hash for verification
        file_hash = self.forensic.compute_hash(file_path)
        stats = file_path.stat()
        
        self.manifest_data["output_files"][str(file_path)] = {
            "path": str(file_path),
            "type": file_type,
            "description": description or f"Generated {file_type}",
            "hash": file_hash,
            "size_bytes": stats.st_size,
            "created": datetime.fromtimestamp(stats.st_ctime, tz=timezone.utc).isoformat(),
            "added_to_manifest": datetime.now().isoformat()
        }
        
        self.forensic.record_action(
            "manifest_output_added",
            f"Added output file to manifest: {file_path.name}",
            {"file": str(file_path), "hash": file_hash}
        )
    
    def add_operation(self, operation: str, status: str, details: Optional[Dict] = None):
        """
        Record an operation in the manifest for audit trail.
        
        Args:
            operation: Name of the operation (e.g., "extraction", "analysis", "reporting")
            status: Status of the operation (e.g., "success", "partial", "failed")
            details: Optional details about the operation
        """
        operation_record = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "status": status,
            "details": details or {}
        }
        
        self.manifest_data["operations"].append(operation_record)
        
        self.forensic.record_action(
            "manifest_operation_added",
            f"Recorded operation: {operation} - {status}",
            operation_record
        )
    
    def validate_manifest(self) -> bool:
        """
        Validate the manifest for completeness and integrity.
        Ensures all referenced files exist and hashes match (Daubert reliability).
        
        Returns:
            True if validation passes, False otherwise
        """
        validation_results = {
            "validated_at": datetime.now().isoformat(),
            "input_files_valid": True,
            "output_files_valid": True,
            "issues": []
        }
        
        # Validate input files
        for file_info in self.manifest_data["input_files"].values():
            file_path = Path(file_info["path"])
            if not file_path.exists():
                validation_results["input_files_valid"] = False
                validation_results["issues"].append(f"Missing input: {file_path}")
            else:
                # Re-compute hash to verify integrity
                current_hash = self.forensic.compute_hash(file_path)
                if current_hash != file_info["hash"]:
                    validation_results["input_files_valid"] = False
                    validation_results["issues"].append(
                        f"Hash mismatch for input: {file_path}"
                    )
        
        # Validate output files
        for file_info in self.manifest_data["output_files"].values():
            file_path = Path(file_info["path"])
            if not file_path.exists():
                validation_results["output_files_valid"] = False
                validation_results["issues"].append(f"Missing output: {file_path}")
            else:
                # Re-compute hash to verify integrity
                current_hash = self.forensic.compute_hash(file_path)
                if current_hash != file_info["hash"]:
                    validation_results["output_files_valid"] = False
                    validation_results["issues"].append(
                        f"Hash mismatch for output: {file_path}"
                    )
        
        self.manifest_data["validation"] = validation_results
        
        is_valid = (validation_results["input_files_valid"] and 
                   validation_results["output_files_valid"])
        
        self.forensic.record_action(
            "manifest_validated",
            f"Manifest validation: {'PASSED' if is_valid else 'FAILED'}",
            validation_results
        )
        
        return is_valid
    
    def generate_manifest(self, output_path: Optional[Path] = None) -> Path:
        """
        Generate the complete run manifest file.
        Creates comprehensive documentation for legal proceedings (FRE 803(6)).
        
        Args:
            output_path: Optional path for the manifest file
            
        Returns:
            Path to the generated manifest file
        """
        # Validate before generating
        self.validate_manifest()
        
        # Set output path if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.forensic.output_dir / f"run_manifest_{timestamp}.json"
        
        # Add generation metadata
        self.manifest_data["generated_at"] = datetime.now().isoformat()
        self.manifest_data["manifest_version"] = "1.0"
        self.manifest_data["legal_notice"] = (
            "This run manifest documents all forensic analysis operations performed. "
            "File hashes provide authentication per FRE 901. "
            "This manifest was generated automatically as part of the analysis workflow "
            "and constitutes a business record under FRE 803(6). "
            "All timestamps are in ISO 8601 format."
        )
        
        # Calculate statistics
        self.manifest_data["statistics"] = {
            "total_input_files": len(self.manifest_data["input_files"]),
            "total_output_files": len(self.manifest_data["output_files"]),
            "total_operations": len(self.manifest_data["operations"]),
            "successful_operations": sum(
                1 for op in self.manifest_data["operations"] 
                if op["status"] == "success"
            ),
            "failed_operations": sum(
                1 for op in self.manifest_data["operations"] 
                if op["status"] == "failed"
            )
        }
        
        # Write manifest to file
        with open(output_path, 'w') as f:
            json.dump(self.manifest_data, f, indent=2, default=str)

        # Compute hash of the final manifest file for chain-of-custody logging. The hash is recorded in the forensic log only — NOT written back into the manifest file itself, which would invalidate the hash.
        manifest_hash = self.forensic.compute_hash(output_path)

        # Detached signature: a sibling .sig (raw Ed25519) + .sig.pub (PEM). Hashing alone does not resist an attacker with write access to the output directory; a signature tied to an examiner key does.
        sig_path = _sign_if_possible(output_path, self.forensic)

        self.forensic.record_action(
            "manifest_generated",
            f"Generated run manifest with {len(self.manifest_data['operations'])} operations",
            {
                "output_path": str(output_path),
                "hash": manifest_hash,
                "signature": str(sig_path) if sig_path else None,
                "input_files": len(self.manifest_data["input_files"]),
                "output_files": len(self.manifest_data["output_files"])
            }
        )

        return output_path
    
    def add_extraction_summary(self, source: str, message_count: int, 
                              extraction_time: float, issues: Optional[List] = None):
        """
        Add extraction summary to manifest.
        
        Args:
            source: Source of extraction (e.g., "imessage", "whatsapp")
            message_count: Number of messages extracted
            extraction_time: Time taken for extraction in seconds
            issues: Optional list of issues encountered
        """
        self.add_operation(
            f"extraction_{source}",
            "success" if message_count > 0 else "failed",
            {
                "source": source,
                "message_count": message_count,
                "extraction_time_seconds": extraction_time,
                "issues": issues or []
            }
        )
    
    def add_analysis_summary(self, analyzer: str, results_count: int, 
                            analysis_time: float, findings: Optional[Dict] = None):
        """
        Add analysis summary to manifest.
        
        Args:
            analyzer: Name of the analyzer (e.g., "threat", "sentiment", "behavioral")
            results_count: Number of results/findings
            analysis_time: Time taken for analysis in seconds
            findings: Optional summary of findings
        """
        self.add_operation(
            f"analysis_{analyzer}",
            "success" if results_count >= 0 else "failed",
            {
                "analyzer": analyzer,
                "results_count": results_count,
                "analysis_time_seconds": analysis_time,
                "findings_summary": findings or {}
            }
        )
    
    def add_report_summary(self, report_type: str, file_path: Path, 
                          generation_time: float):
        """
        Add report generation summary to manifest.
        
        Args:
            report_type: Type of report (e.g., "excel", "word", "pdf")
            file_path: Path to the generated report
            generation_time: Time taken to generate report in seconds
        """
        self.add_output_file(file_path, f"{report_type}_report")
        self.add_operation(
            f"report_{report_type}",
            "success" if file_path.exists() else "failed",
            {
                "report_type": report_type,
                "file_path": str(file_path),
                "generation_time_seconds": generation_time
            }
        )


# Ensure the class is exported
__all__ = ['RunManifest']