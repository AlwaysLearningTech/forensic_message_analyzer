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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytz

from ..config import Config
from ..forensic_utils import ForensicRecorder

logger = logging.getLogger(__name__)

from .. import __version__ as ANALYZER_VERSION

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

    @property
    def tz_abbreviation(self) -> str:
        """Current timezone abbreviation (e.g. 'PST', 'PDT')."""
        return self.now().strftime('%Z')

    def convert_to_local(self, ts) -> str:
        """Convert a UTC timestamp to the configured local timezone for display.

        Accepts pd.Timestamp, datetime, or string. Returns formatted string
        like '2024-03-15 15:30:00 PDT'. Returns the original value as a string
        if conversion fails.
        """
        if ts is None or (isinstance(ts, str) and not ts.strip()):
            return ''
        try:
            import pandas as pd
            # Parse to pandas Timestamp (handles strings, datetimes, Timestamps)
            parsed = pd.to_datetime(ts, utc=True)
            if pd.isna(parsed):
                return str(ts)
            # Convert to local timezone
            local_dt = parsed.to_pydatetime().astimezone(self.tz)
            return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        except Exception:
            return str(ts)

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

        The statement is written for a non-technical audience (judges,
        opposing counsel, paralegals). It describes the tools, data sources,
        analysis methods, standards followed, and examiner identification
        in plain language so the methodology can be independently
        reviewed and reproduced — and so the testifying party can speak
        to it on the stand.

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

        case_numbers = list(getattr(self.config, 'case_numbers', []) or [])
        if not case_numbers and self.config.case_number:
            case_numbers = [self.config.case_number]
        case_number_block = (
            "  - " + "\n  - ".join(case_numbers)
            if case_numbers else "  - Not assigned"
        )

        lines: List[str] = []
        lines.append("METHODOLOGY STATEMENT")
        lines.append("=" * 60)
        lines.append("")
        lines.append("Plain-language guide for the legal team")
        lines.append("-" * 60)
        lines.append(
            "This document explains, step by step, exactly what the analyzer "
            "did with the source data, why each step was done, and how the "
            "results can be independently reproduced. It is written for "
            "judges, opposing counsel, and paralegals — no technical "
            "background is assumed."
        )
        lines.append("")

        # ---- Identification ----
        lines.append("1. CASE IDENTIFICATION")
        lines.append("-" * 60)
        lines.append(f"Date of Analysis: {timestamp}")
        lines.append(f"Examiner: {self.config.examiner_name or 'Not specified'}")
        lines.append(f"Organization: {self.config.organization or 'Not specified'}")
        lines.append("Case Number(s):")
        lines.append(case_number_block)
        lines.append(f"Case Name: {self.config.case_name or 'Not assigned'}")
        lines.append("")

        # ---- Tools ----
        lines.append("2. TOOLS USED")
        lines.append("-" * 60)
        lines.append(f"  - Forensic Message Analyzer v{ANALYZER_VERSION} (open-source)")
        lines.append(f"  - Python {sys.version.split()[0]} runtime")
        lines.append(f"  - Operating system: {platform.system()} {platform.release()}")
        lines.append(
            "Open-source software allows opposing counsel and the court "
            "to inspect every line of code that processed the evidence."
        )
        lines.append("")

        # ---- Sources ----
        lines.append("3. DATA SOURCES EXAMINED")
        lines.append("-" * 60)
        for src in sources:
            lines.append(f"  - {src}")
        lines.append(
            "Each source file was hashed (SHA-256) before any processing "
            "and the hash was recorded in the chain of custody log. The "
            "originals are never opened for writing — only read."
        )
        lines.append("")

        # ---- Step-by-step pipeline ----
        lines.append("4. STEP-BY-STEP ANALYSIS PIPELINE")
        lines.append("-" * 60)
        lines.append(
            "The analyzer runs in eight numbered phases. Each phase is "
            "logged with a UTC timestamp and an action description, and "
            "every file produced is hashed."
        )
        lines.append("")
        lines.append(
            "  Phase 1 — Extraction. The analyzer reads each configured "
            "source (iMessage SQLite database, WhatsApp text export, "
            "email .eml/.mbox files, Microsoft Teams export, screenshot "
            "directory) and converts every message into a uniform record "
            "(sender, recipient, timestamp, content, source). For "
            "iMessage, the modern attributedBody binary format is decoded; "
            "edit history (iOS 16+), retracted/deleted messages, URL "
            "previews, and shared locations are recovered from the BLOB "
            "columns where present. Tapbacks and system messages are "
            "filtered out."
        )
        lines.append("")
        lines.append(
            "  Phase 2 — Local analysis. Four independent automated "
            "analyzers process the messages:"
        )
        lines.append(
            "    (a) Threat detection — regular-expression matches against "
            "        a published catalogue of physical-threat, stalking, "
            "        harassment, intimidation, property-damage, and "
            "        extortion phrases (see analysis_patterns.yaml in the "
            "        source repository for the exact patterns and the "
            "        empirical literature each is drawn from)."
        )
        lines.append(
            "    (b) Sentiment analysis — TextBlob (a peer-reviewed "
            "        natural-language toolkit, MIT-licensed) computes a "
            "        polarity score (-1.0 negative … +1.0 positive) and a "
            "        subjectivity score for each message."
        )
        lines.append(
            "    (c) Behavioural pattern detection — additional regex "
            "        families for emotional manipulation, gaslighting, "
            "        controlling behaviour, isolation, and love-bombing, "
            "        each tied to the empirical literature on "
            "        intimate-partner coercive control (see "
            "        analysis_patterns.yaml header notes)."
        )
        lines.append(
            "    (d) Communication metrics — message volume, frequency, "
            "        time-of-day distribution, and inter-message gap "
            "        statistics computed by message and by participant."
        )
        lines.append(
            "  These analyzers are intentionally tuned to over-flag "
            "(high recall, low precision). False positives are expected "
            "and are removed in the manual-review phase. The point of "
            "these screens is to surface candidates a human can review "
            "in minutes instead of having to read every message."
        )
        lines.append("")
        lines.append(
            "  Phase 3 — AI batch screening (optional). When an Anthropic "
            "Claude API key is configured, the analyzer submits batches of "
            "messages to Anthropic's batch API for a second opinion on "
            "threats, coercive control, and risk indicators. The model "
            "and prompt are recorded with the run. The AI is used as an "
            "additional flagging mechanism only — every AI-flagged item "
            "is submitted to the same manual-review process as items "
            "flagged by the local analyzers, and only items confirmed "
            "during review are reflected in the final findings."
        )
        lines.append("")
        lines.append(
            "  Phase 4 — Manual review. Every flagged item is presented "
            "to a qualified reviewer through either a command-line or a "
            "Flask-based web interface. The reviewer marks each item "
            "Relevant, Not Relevant, or Uncertain and may add notes. "
            "Decisions are written to disk as JSON immediately, so the "
            "review can be paused and resumed without losing work."
        )
        lines.append("")
        lines.append(
            "  Phase 5 — Post-review behavioural analysis. Conversation-"
            "level patterns (escalation timelines, response-latency "
            "anomalies, unilateral monologue stretches) are computed "
            "across the full message set, restricted to mapped persons "
            "to avoid pulling in irrelevant third-party traffic."
        )
        lines.append("")
        lines.append(
            "  Phase 6 — Executive narrative. When AI is configured, a "
            "single Anthropic Claude call produces a plain-language "
            "narrative summary that the legal team can read first. The "
            "narrative cites only items that survived manual review."
        )
        lines.append("")
        lines.append(
            "  Phase 7 — Report generation. The analyzer writes Excel, "
            "Word, PDF, HTML, JSON, CSV, an iMessage-style chat-bubble "
            "HTML, and an interactive timeline. Every output file is "
            "hashed (SHA-256) and the hash is recorded in the chain of "
            "custody log."
        )
        lines.append("")
        lines.append(
            "  Phase 8 — Documentation. The analyzer emits a chain-of-"
            "custody JSON document covering every action taken during "
            "the run, plus a run manifest listing every input file (with "
            "hash) and every output file (with hash) and the exact "
            "configuration used. The methodology statement (this "
            "document) is also produced."
        )
        lines.append("")

        # ---- Analysis methods (list form for quick reference) ----
        lines.append("5. ANALYSIS METHODS APPLIED (quick reference)")
        lines.append("-" * 60)
        for method in methods:
            lines.append(f"  - {method}")
        lines.append("")

        # ---- Standards ----
        lines.append("6. LEGAL STANDARDS — HOW EACH IS SATISFIED")
        lines.append("-" * 60)
        lines.append(
            "  FRE 901 (Authentication). Every source file was hashed "
            "(SHA-256) on first read. The same hash can be re-computed at "
            "any time to prove the evidence has not been altered. The "
            "chain-of-custody log records each hash with a timestamp."
        )
        lines.append("")
        lines.append(
            "  FRE 1001-1008 (Best Evidence Rule). Source files are "
            "opened read-only. When working copies are needed they are "
            "hashed against the source. Original metadata "
            "(timestamps, sender/recipient identifiers, attachment "
            "references) is preserved in the extracted record."
        )
        lines.append("")
        lines.append(
            "  FRE 803(6) (Business Records Exception). Messages were "
            "captured in the regular course of communication on the "
            "device's normal messaging applications. The analyzer adds "
            "no content; it only re-organises and indexes what was "
            "already there."
        )
        lines.append("")
        lines.append(
            "  FRE 106 (Rule of Completeness). The completeness "
            "validation step (recorded in this report) checks every "
            "conversation for one-sided extraction and for >24-hour "
            "gaps; flagged conversations are listed by ID with the "
            "specific issue so the legal team can request supplemental "
            "production if needed."
        )
        lines.append("")
        lines.append(
            "  Daubert (FRE 702). The methodology is testable (an open-"
            "source test suite re-runs the entire pipeline against "
            "synthetic data on every commit), has been peer-reviewed "
            "(the libraries used — pandas, Pillow, TextBlob, openpyxl, "
            "python-docx, reportlab, anthropic — are widely adopted), "
            "has known and documented error characteristics (see "
            "Limitations section of every report), follows published "
            "standards (SWGDE, NIST SP 800-86), and is generally "
            "accepted in digital-forensics practice."
        )
        lines.append("")
        lines.append(
            "  SWGDE Best Practices. The Scientific Working Group on "
            "Digital Evidence's standards for handling, hashing, and "
            "preserving digital evidence are followed throughout. See "
            "https://www.swgde.org/documents for the published guidance."
        )
        lines.append("")
        lines.append(
            "  NIST SP 800-86. The National Institute of Standards and "
            "Technology's guide to forensic-technique integration was "
            "the procedural template for the eight-phase pipeline above."
        )
        lines.append("")

        # ---- What this method does NOT do ----
        lines.append("7. SCOPE LIMITATIONS")
        lines.append("-" * 60)
        lines.append(
            "  - The automated screens are tuned for recall, not "
            "    precision. False positives are expected. Every flagged "
            "    item was manually reviewed; only confirmed items appear "
            "    in the findings."
        )
        lines.append(
            "  - The analyzer does not interpret intent, credibility, or "
            "    truthfulness. Those are matters for the trier of fact."
        )
        lines.append(
            "  - The analyzer cannot recover messages that were deleted "
            "    before the source data was preserved, or messages "
            "    exchanged on platforms not configured as a source."
        )
        lines.append(
            "  - Sentiment analysis (TextBlob) is calibrated on general "
            "    English text and may misclassify sarcasm, code-switching, "
            "    or domain-specific vocabulary. It is provided as an "
            "    additional indexing aid only."
        )
        lines.append("")

        # ---- Reproducibility ----
        lines.append("8. REPRODUCIBILITY")
        lines.append("-" * 60)
        lines.append(
            "Given the same source files (verified by SHA-256 hash) and "
            "the same configuration (preserved in the run manifest), "
            "running the analyzer again will produce byte-identical "
            "extraction output. The local analyzers are deterministic. "
            "AI calls are non-deterministic by design but the model name, "
            "prompt, and token counts are recorded so the call can be "
            "audited; the AI is never the sole basis for any finding "
            "(see Phase 3 above)."
        )
        lines.append("")
        lines.append("END OF METHODOLOGY STATEMENT")

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
                file_hash = self.forensic.compute_hash(fpath)
                entry = {
                    "file": str(fpath),
                    "sha256": file_hash,
                    "size_bytes": fpath.stat().st_size,
                    "modified": datetime.fromtimestamp(
                        fpath.stat().st_mtime, tz=timezone.utc
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
                "sha256": self.forensic.compute_hash(db_path),
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
                            "sha256": self.forensic.compute_hash(companion_path),
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
                        "sha256": self.forensic.compute_hash(img_path),
                        "size_bytes": img_path.stat().st_size,
                        "modified": datetime.fromtimestamp(
                            img_path.stat().st_mtime, tz=timezone.utc
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

        case_numbers = list(getattr(self.config, 'case_numbers', []) or [])
        if not case_numbers and self.config.case_number:
            case_numbers = [self.config.case_number]

        header = {
            "report_title": "Forensic Digital Communications Analysis Report",
            "case_number": self.config.case_number or "Not assigned",
            "case_numbers": case_numbers or ["Not assigned"],
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
        or evidence packages. Plain-language so the testifying party can
        speak to it on the stand.
        """
        return (
            "STANDARDS COMPLIANCE STATEMENT\n"
            + "=" * 60
            + "\n\n"
            "This forensic analysis was conducted in compliance with the "
            "following standards. Each is summarised in plain language "
            "below so the party offering this report can speak to how "
            "the standard was satisfied.\n\n"
            + "\n".join(f"  - {s}" for s in APPLICABLE_STANDARDS)
            + "\n\n"
            "HOW EACH STANDARD WAS SATISFIED:\n\n"
            "  FRE 901 — Authentication. Every source file was hashed "
            "(SHA-256) before any processing. The same hash can be "
            "re-computed at any time to prove the evidence has not been "
            "altered. Hashes for source files and every output file are "
            "recorded in the chain-of-custody log.\n\n"
            "  FRE 1001-1008 — Best Evidence. Source files were opened "
            "read-only. Original metadata (timestamps, sender/recipient "
            "identifiers, attachment references) is preserved in the "
            "extracted record. The original evidence is never modified.\n\n"
            "  FRE 803(6) — Business Records. Messages were captured in "
            "the regular course of communication on the device's normal "
            "messaging applications. The analyzer adds no content; it "
            "only re-organises and indexes what was already there.\n\n"
            "  FRE 106 — Rule of Completeness. The completeness "
            "validation report (included with this analysis) checks "
            "every conversation for one-sided extraction and for >24-"
            "hour gaps; any flagged conversations are listed with the "
            "specific issue.\n\n"
            "  Daubert (FRE 702). The methodology is testable (an "
            "open-source test suite re-runs the entire pipeline on every "
            "code change), uses peer-reviewed libraries (pandas, "
            "TextBlob, etc.), has documented error characteristics (see "
            "the Limitations section), follows published standards "
            "(SWGDE, NIST SP 800-86), and is generally accepted in "
            "digital-forensics practice.\n\n"
            "  SWGDE / NIST SP 800-86. The Scientific Working Group on "
            "Digital Evidence's best practices and NIST's guide to "
            "forensic-technique integration were the procedural template "
            "for the eight-phase pipeline used here.\n\n"
            "See the accompanying Methodology Statement for a step-by-"
            "step description of every phase, and the chain-of-custody "
            "log for the timestamped audit trail of every operation.\n"
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
