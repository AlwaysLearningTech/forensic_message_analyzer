#!/usr/bin/env python3
"""
Legal compliance utilities for the forensic message analyzer.

Ensures adherence to:
- FRE 901 (Authentication) - evidence must be authenticated
- FRE 1001-1008 (Best Evidence Rule) - original or best copy
- FRE 803(6) (Business Records Exception)
- FRE 106 (Rule of Completeness) - full context preserved
- Daubert Standard - reliable, reproducible methodology
- SWGDE Guidelines - digital evidence handling best practices
- NIST SP 800-86 - incident handling guide for digital forensics
"""

import hashlib
import json
import logging
import platform
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytz

from ..config import Config
from ..forensic_utils import ForensicRecorder

logger = logging.getLogger(__name__)

# Analyzer version – kept in sync with src/__init__.py
ANALYZER_VERSION = "4.0.0"

# Standards referenced throughout the module
APPLICABLE_STANDARDS = [
    "Federal Rules of Evidence (FRE) 901 - Authentication",
    "Federal Rules of Evidence (FRE) 1001-1008 - Best Evidence Rule",
    "Federal Rules of Evidence (FRE) 803(6) - Business Records Exception",
    "Federal Rules of Evidence (FRE) 106 - Rule of Completeness",
    "Daubert Standard - Reliable and Reproducible Methodology",
    "SWGDE Guidelines - Digital Evidence Handling Best Practices",
    "NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response",
]


class LegalComplianceManager:
    """
    Manages legal compliance for forensic message analysis.

    Provides methodology documentation, completeness validation,
    authentication records, and forensic examination report headers
    in accordance with federal rules of evidence and digital forensics
    standards.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        forensic_recorder: Optional[ForensicRecorder] = None,
    ):
        """
        Initialize the LegalComplianceManager.

        Args:
            config: Config instance. A new one is created if not provided.
            forensic_recorder: ForensicRecorder for chain-of-custody logging.
                               A new one is created if not provided.
        """
        self.config = config or Config()
        self.forensic = forensic_recorder or ForensicRecorder()
        self.tz = pytz.timezone(self.config.timezone)

    # ------------------------------------------------------------------
    # Timezone-aware timestamp helpers
    # ------------------------------------------------------------------

    def now(self) -> datetime:
        """Return the current time in the configured timezone."""
        return datetime.now(self.tz)

    def format_timestamp(self, dt: Optional[datetime] = None) -> str:
        """
        Format a datetime for display in reports.

        Args:
            dt: Datetime to format. Uses current time if *None*.

        Returns:
            Human-readable timestamp string with timezone abbreviation.
        """
        if dt is None:
            dt = self.now()
        elif dt.tzinfo is None:
            dt = self.tz.localize(dt)
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")

    # ------------------------------------------------------------------
    # 1. Methodology Statement (Daubert Standard)
    # ------------------------------------------------------------------

    def generate_methodology_statement(
        self,
        data_sources: Optional[List[str]] = None,
        analysis_methods: Optional[List[str]] = None,
    ) -> str:
        """
        Generate a Daubert-compliant methodology statement.

        The statement describes tools, data sources, analysis methods,
        standards followed, and examiner identification so that the
        methodology can be independently reviewed and reproduced.

        Args:
            data_sources: List of data source descriptions examined.
            analysis_methods: List of analysis methods applied.

        Returns:
            Multi-line methodology statement suitable for inclusion
            in a forensic report.
        """
        timestamp = self.format_timestamp()
        sources = data_sources or self._get_configured_sources()
        methods = analysis_methods or self._get_default_analysis_methods()

        lines: List[str] = []
        lines.append("METHODOLOGY STATEMENT")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Date of Analysis: {timestamp}")
        lines.append(f"Examiner: {self.config.examiner_name or 'Not specified'}")
        lines.append(f"Organization: {self.config.organization or 'Not specified'}")
        lines.append("")
        lines.append("Tool Identification:")
        lines.append(f"  - Forensic Message Analyzer v{ANALYZER_VERSION}")
        lines.append(f"  - Python {sys.version.split()[0]}")
        lines.append(f"  - Platform: {platform.system()} {platform.release()}")
        lines.append("")
        lines.append("Data Sources Examined:")
        for src in sources:
            lines.append(f"  - {src}")
        lines.append("")
        lines.append("Analysis Methods Applied:")
        for method in methods:
            lines.append(f"  - {method}")
        lines.append("")
        lines.append("Standards Followed:")
        for std in APPLICABLE_STANDARDS:
            lines.append(f"  - {std}")
        lines.append("")
        lines.append(
            "This analysis was conducted using a systematic, reproducible "
            "methodology in accordance with the Daubert standard for the "
            "admissibility of expert testimony. All steps are documented "
            "in the accompanying chain of custody log."
        )

        statement = "\n".join(lines)

        self.forensic.record_action(
            "methodology_statement_generated",
            f"Generated methodology statement at {timestamp}",
        )

        return statement

    # ------------------------------------------------------------------
    # 2. Completeness Validation (FRE 106)
    # ------------------------------------------------------------------

    def validate_completeness(
        self, messages: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Validate conversation completeness per FRE 106
        (Rule of Completeness).

        Checks that:
        - Conversation context is preserved (not just isolated messages).
        - Both sides of conversations are represented.
        - No significant gaps exist in message sequences.

        Args:
            messages: List of message dicts, each expected to contain
                      at least ``sender``, ``timestamp``, and optionally
                      ``conversation_id``.

        Returns:
            A validation report dictionary.
        """
        report: Dict[str, Any] = {
            "validated_at": self.format_timestamp(),
            "total_messages": len(messages),
            "conversations": {},
            "gaps_detected": [],
            "one_sided_conversations": [],
            "is_complete": True,
            "issues": [],
        }

        if not messages:
            report["is_complete"] = False
            report["issues"].append("No messages provided for completeness validation")
            self.forensic.record_action(
                "completeness_validation",
                "Completeness validation failed: no messages provided",
            )
            return report

        # Group messages by conversation
        conversations: Dict[str, List[Dict[str, Any]]] = {}
        for msg in messages:
            conv_id = msg.get("conversation_id") or msg.get("contact") or "unknown"
            conversations.setdefault(conv_id, []).append(msg)

        for conv_id, conv_messages in conversations.items():
            senders = set()
            timestamps: List[datetime] = []

            for msg in conv_messages:
                sender = msg.get("sender") or msg.get("from") or "unknown"
                senders.add(sender)
                ts = msg.get("timestamp")
                if ts:
                    try:
                        if isinstance(ts, str):
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        elif isinstance(ts, datetime):
                            dt = ts
                        else:
                            continue
                        timestamps.append(dt)
                    except (ValueError, TypeError):
                        pass

            # Check for one-sided conversations
            if len(senders) < 2:
                report["one_sided_conversations"].append(
                    {
                        "conversation_id": str(conv_id),
                        "senders": list(senders),
                        "message_count": len(conv_messages),
                    }
                )
                report["issues"].append(
                    f"Conversation '{conv_id}' appears one-sided "
                    f"(only sender(s): {', '.join(senders)})"
                )

            # Check for chronological gaps (threshold: 24 hours)
            if len(timestamps) >= 2:
                sorted_ts = sorted(timestamps)
                for i in range(1, len(sorted_ts)):
                    gap = sorted_ts[i] - sorted_ts[i - 1]
                    if gap.total_seconds() > 86400:  # 24 hours
                        gap_info = {
                            "conversation_id": str(conv_id),
                            "gap_start": sorted_ts[i - 1].isoformat(),
                            "gap_end": sorted_ts[i].isoformat(),
                            "gap_hours": round(gap.total_seconds() / 3600, 1),
                        }
                        report["gaps_detected"].append(gap_info)
                        report["issues"].append(
                            f"Gap of {gap_info['gap_hours']} hours detected in "
                            f"conversation '{conv_id}'"
                        )

            report["conversations"][str(conv_id)] = {
                "message_count": len(conv_messages),
                "unique_senders": list(senders),
                "has_multiple_participants": len(senders) >= 2,
            }

        if report["gaps_detected"] or report["one_sided_conversations"]:
            report["is_complete"] = False

        self.forensic.record_action(
            "completeness_validation",
            f"Validated completeness: {len(conversations)} conversations, "
            f"{len(report['issues'])} issues found",
        )

        return report

    # ------------------------------------------------------------------
    # 3. Authentication Records (FRE 901)
    # ------------------------------------------------------------------

    def generate_authentication_records(
        self,
        source_files: Optional[List[Path]] = None,
        db_path: Optional[Path] = None,
        screenshot_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Generate FRE 901-compliant authentication records.

        Produces:
        - SHA-256 hashes for every source file.
        - Database integrity verification record.
        - Screenshot provenance documentation.
        - Chain of custody entries logged via the forensic recorder.

        Args:
            source_files: Explicit list of files to authenticate.
            db_path: Path to the messages database (optional).
            screenshot_dir: Directory containing screenshots (optional).

        Returns:
            Authentication records dictionary.
        """
        timestamp = self.format_timestamp()
        records: Dict[str, Any] = {
            "generated_at": timestamp,
            "examiner": self.config.examiner_name or "Not specified",
            "standard": "FRE 901 - Authentication of Evidence",
            "file_hashes": [],
            "database_verification": None,
            "screenshot_provenance": [],
            "chain_of_custody_entries": [],
        }

        # --- Source file hashes ---
        files_to_hash: List[Path] = list(source_files or [])

        # Add database files from config when not explicitly supplied
        if db_path is None and self.config.messages_db_path:
            db_path = Path(self.config.messages_db_path)
        if db_path and db_path.exists():
            files_to_hash.append(db_path)

        for fpath in files_to_hash:
            if fpath.exists():
                file_hash = self._compute_sha256(fpath)
                entry = {
                    "file": str(fpath),
                    "sha256": file_hash,
                    "size_bytes": fpath.stat().st_size,
                    "modified": datetime.fromtimestamp(
                        fpath.stat().st_mtime
                    ).isoformat(),
                    "authenticated_at": timestamp,
                }
                records["file_hashes"].append(entry)

                coc_entry = (
                    f"Authenticated {fpath.name} - SHA-256: {file_hash[:16]}..."
                )
                records["chain_of_custody_entries"].append(coc_entry)
                self.forensic.record_action(
                    "file_authenticated",
                    f"Authenticated {fpath.name} with SHA-256 hash",
                )

        # --- Database integrity verification ---
        if db_path and db_path.exists():
            db_record = {
                "database_path": str(db_path),
                "sha256": self._compute_sha256(db_path),
                "size_bytes": db_path.stat().st_size,
                "verified_at": timestamp,
                "verification_method": "SHA-256 hash of database file",
            }
            # Check for WAL/SHM companion files
            for suffix, cfg_attr in [(".db-wal", "messages_db_wal"), (".db-shm", "messages_db_shm")]:
                companion = getattr(self.config, cfg_attr, None)
                if companion:
                    companion_path = Path(companion)
                    if companion_path.exists():
                        db_record[f"companion{suffix}"] = {
                            "path": str(companion_path),
                            "sha256": self._compute_sha256(companion_path),
                        }
            records["database_verification"] = db_record
            self.forensic.record_action(
                "database_integrity_verified",
                f"Database integrity verified: {db_path.name}",
            )

        # --- Screenshot provenance ---
        if screenshot_dir is None and self.config.screenshot_source_dir:
            screenshot_dir = Path(self.config.screenshot_source_dir)
        if screenshot_dir and screenshot_dir.exists():
            image_extensions = {".png", ".jpg", ".jpeg", ".heic", ".webp", ".tiff"}
            for img_path in sorted(screenshot_dir.iterdir()):
                if img_path.suffix.lower() in image_extensions:
                    prov = {
                        "file": str(img_path),
                        "sha256": self._compute_sha256(img_path),
                        "size_bytes": img_path.stat().st_size,
                        "modified": datetime.fromtimestamp(
                            img_path.stat().st_mtime
                        ).isoformat(),
                        "documented_at": timestamp,
                    }
                    records["screenshot_provenance"].append(prov)
            self.forensic.record_action(
                "screenshot_provenance_documented",
                f"Documented provenance for {len(records['screenshot_provenance'])} screenshots",
            )

        self.forensic.record_action(
            "authentication_records_generated",
            f"Generated authentication records for {len(records['file_hashes'])} files",
        )

        return records

    # ------------------------------------------------------------------
    # 4. Forensic Examination Report Header
    # ------------------------------------------------------------------

    def generate_report_header(self) -> Dict[str, str]:
        """
        Generate a forensic examination report header.

        Contains case identification, examiner information, examination
        date, tool identification, and a standards-compliance statement.

        Returns:
            Dictionary of header fields suitable for inclusion in
            Word/PDF reports.
        """
        timestamp = self.format_timestamp()

        header = {
            "report_title": "Forensic Digital Communications Analysis Report",
            "case_number": self.config.case_number or "Not assigned",
            "case_name": self.config.case_name or "Not assigned",
            "examiner_name": self.config.examiner_name or "Not specified",
            "organization": self.config.organization or "Not specified",
            "date_of_examination": timestamp,
            "tools_used": f"Forensic Message Analyzer v{ANALYZER_VERSION}",
            "methodology": (
                "Systematic extraction, automated threat and sentiment analysis, "
                "and manual review of digital communications with full chain of "
                "custody documentation."
            ),
            "standards_compliance": (
                "This examination was conducted in accordance with the Federal "
                "Rules of Evidence (FRE 901, FRE 1001-1008, FRE 803(6), FRE 106), "
                "the Daubert standard for reliable and reproducible methodology, "
                "SWGDE best practices for digital evidence handling, and "
                "NIST SP 800-86 guidelines for digital forensic techniques."
            ),
        }

        self.forensic.record_action(
            "report_header_generated",
            f"Generated forensic report header for case {header['case_number']}",
        )

        return header

    # ------------------------------------------------------------------
    # Helper: standards compliance statement (reusable text block)
    # ------------------------------------------------------------------

    def get_standards_compliance_statement(self) -> str:
        """
        Return a standalone standards-compliance statement.

        Suitable for insertion into reports, chain of custody documents,
        or evidence packages.
        """
        return (
            "STANDARDS COMPLIANCE STATEMENT\n"
            + "=" * 60
            + "\n\n"
            "This forensic analysis was conducted in compliance with the "
            "following standards and guidelines:\n\n"
            + "\n".join(f"  - {s}" for s in APPLICABLE_STANDARDS)
            + "\n\n"
            "All digital evidence was handled in accordance with SWGDE best "
            "practices. Hash values (SHA-256) were computed for all source "
            "files to satisfy FRE 901 authentication requirements. The "
            "original evidence was preserved unmodified in compliance with "
            "the Best Evidence Rule (FRE 1001-1008). Conversation context "
            "was maintained per the Rule of Completeness (FRE 106). The "
            "methodology applied is reliable, reproducible, and subject to "
            "peer review in accordance with the Daubert standard.\n"
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _compute_sha256(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash {file_path}: {e}")
            return ""

    def _get_configured_sources(self) -> List[str]:
        """Return a human-readable list of data sources from config."""
        sources: List[str] = []
        if self.config.messages_db_path:
            sources.append(f"iMessage database ({self.config.messages_db_path})")
        if self.config.whatsapp_source_dir:
            sources.append(f"WhatsApp export directory ({self.config.whatsapp_source_dir})")
        if self.config.screenshot_source_dir:
            sources.append(f"Screenshot directory ({self.config.screenshot_source_dir})")
        if not sources:
            sources.append("No data sources configured")
        return sources

    def _get_default_analysis_methods(self) -> List[str]:
        """Return the default list of analysis methods."""
        methods = [
            "Automated message extraction from source databases and exports",
            "SHA-256 cryptographic hashing of all source files (FRE 901)",
            "Automated threat detection and classification",
            "Sentiment analysis of message content",
            "Chronological timeline reconstruction",
            "Manual expert review of flagged content",
            "Chain of custody documentation for all operations",
        ]
        if self.config.enable_image_analysis:
            methods.append("Image analysis and OCR of screenshots")
        return methods
