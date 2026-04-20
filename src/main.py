#!/usr/bin/env python3
"""
Main orchestration script for the forensic message analyzer.
Coordinates extraction, analysis, review, and reporting phases.
"""

import sys
import json
import copy
import shutil
import zipfile
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import Config
from src.forensic_utils import ForensicRecorder, ForensicIntegrity
from src.third_party_registry import ThirdPartyRegistry
from src.extractors.data_extractor import DataExtractor
from src.extractors.screenshot_extractor import ScreenshotExtractor
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.analyzers.sentiment_analyzer import SentimentAnalyzer
from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
from src.analyzers.yaml_pattern_analyzer import YamlPatternAnalyzer
from src.analyzers.screenshot_analyzer import ScreenshotAnalyzer
from src.analyzers.communication_metrics import CommunicationMetricsAnalyzer
from src.reporters.excel_reporter import ExcelReporter
from src.reporters.forensic_reporter import ForensicReporter
from src.reporters.json_reporter import JSONReporter
from src.reporters.html_reporter import HtmlReporter
from src.review.manual_review_manager import ManualReviewManager
from src.utils.run_manifest import RunManifest
from src.utils.timeline_generator import TimelineGenerator


class ForensicAnalyzer:
    """Main orchestrator for the forensic analysis workflow."""
    
    def __init__(self, config: Config = None):
        """Initialize the forensic analyzer with necessary components.

        Args:
            config: Configuration instance. If None, creates a new one.
                    The caller is responsible for setting config.output_dir
                    to the desired run-specific directory (see run.py).
        """
        self.config = config if config is not None else Config()
        self.forensic = ForensicRecorder(Path(self.config.output_dir))
        self.integrity = ForensicIntegrity(self.forensic)
        self.manifest = RunManifest(self.forensic, config=self.config)
        self.third_party_registry = ThirdPartyRegistry(self.forensic, self.config)
        
        # Record session start
        self.forensic.record_action("session_start", "Forensic analysis session initialized")
        self._extracted_data_path = None
        self._analysis_results_path = None

    # ------------------------------------------------------------------
    # Source file integrity
    # ------------------------------------------------------------------

    def _hash_source_files(self):
        """Hash all source files before extraction to establish chain of custody."""
        print("\n[*] Hashing source files for chain of custody...")
        hashed = 0

        # iMessage database
        if self.config.messages_db_path:
            db_path = Path(self.config.messages_db_path).expanduser()
            if db_path.exists():
                h = self.forensic.compute_hash(db_path)
                self.forensic.record_action(
                    "source_file_hashed", f"Pre-extraction hash of iMessage database",
                    {"file": str(db_path), "hash": h}
                )
                hashed += 1

        # WhatsApp source files
        wa_dir = self.config.whatsapp_source_dir
        if wa_dir:
            wa_path = Path(wa_dir).expanduser()
            if wa_path.is_dir():
                for f in sorted(wa_path.rglob("*")):
                    if f.is_file():
                        h = self.forensic.compute_hash(f)
                        self.forensic.record_action(
                            "source_file_hashed", f"Pre-extraction hash of WhatsApp file",
                            {"file": str(f), "hash": h}
                        )
                        hashed += 1

        # Email source files
        email_dir = self.config.email_source_dir
        if email_dir:
            email_path = Path(email_dir).expanduser()
            if email_path.is_dir():
                for f in sorted(email_path.rglob("*")):
                    if f.is_file():
                        h = self.forensic.compute_hash(f)
                        self.forensic.record_action(
                            "source_file_hashed", f"Pre-extraction hash of email file",
                            {"file": str(f), "hash": h}
                        )
                        hashed += 1

        # Teams source files
        teams_dir = self.config.teams_source_dir
        if teams_dir:
            teams_path = Path(teams_dir).expanduser()
            if teams_path.is_dir():
                for f in sorted(teams_path.rglob("*")):
                    if f.is_file():
                        h = self.forensic.compute_hash(f)
                        self.forensic.record_action(
                            "source_file_hashed", f"Pre-extraction hash of Teams file",
                            {"file": str(f), "hash": h}
                        )
                        hashed += 1

        # Screenshot source files (hashed individually during extraction,
        # but record them here too for completeness)
        ss_dir = self.config.screenshot_source_dir
        if ss_dir:
            ss_path = Path(ss_dir).expanduser()
            if ss_path.is_dir():
                for f in sorted(ss_path.iterdir()):
                    if f.is_file():
                        h = self.forensic.compute_hash(f)
                        self.forensic.record_action(
                            "source_file_hashed", f"Pre-extraction hash of screenshot",
                            {"file": str(f), "hash": h}
                        )
                        hashed += 1

        # Counseling source files (YAML + PDFs)
        counseling_dir = self.config.counseling_source_dir
        if counseling_dir:
            counseling_path = Path(counseling_dir).expanduser()
            if counseling_path.is_dir():
                for f in sorted(counseling_path.rglob("*")):
                    if f.is_file():
                        h = self.forensic.compute_hash(f)
                        self.forensic.record_action(
                            "source_file_hashed", f"Pre-extraction hash of counseling file",
                            {"file": str(f), "hash": h}
                        )
                        hashed += 1

        print(f"    Hashed {hashed} source files")

    # ------------------------------------------------------------------
    # Source file preservation (forensic archive)
    # ------------------------------------------------------------------

    def _preserve_source_files(self):
        """Create a zipped archive of all source evidence files.

        Copies every configured source file into a temporary
        ``preserved_sources/`` tree inside the run folder, computes
        SHA-256 hashes (cross-validated against the hashes already
        recorded by ``_hash_source_files``), zips the tree into
        ``preserved_sources.zip``, and removes the temporary tree.

        The originals are **never** modified or deleted.
        """
        run_dir = Path(self.config.output_dir)
        staging = run_dir / "preserved_sources"
        staging.mkdir(parents=True, exist_ok=True)
        preserved_count = 0

        print("\n[*] Preserving source evidence files...")

        def _copy_and_hash(src: Path, dest: Path, label: str):
            """Copy a single file and record its hash."""
            nonlocal preserved_count
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            h = self.forensic.compute_hash(dest)
            self.forensic.record_action(
                "source_preserved",
                f"Preserved {label}: {src.name}",
                {"original": str(src), "preserved": str(dest), "hash": h},
            )
            preserved_count += 1

        # --- iMessage database files ---
        for attr in ("messages_db_path", "messages_db_wal", "messages_db_shm"):
            val = getattr(self.config, attr, None)
            if val:
                p = Path(val).expanduser()
                if p.is_file():
                    _copy_and_hash(p, staging / "imessage" / p.name, "iMessage DB")

        # --- WhatsApp: only .zip files (not extracted dirs/media) ---
        wa_dir = self.config.whatsapp_source_dir
        if wa_dir:
            wa_path = Path(wa_dir).expanduser()
            if wa_path.is_dir():
                for f in sorted(wa_path.glob("*.zip")):
                    if f.is_file():
                        _copy_and_hash(f, staging / "whatsapp" / f.name, "WhatsApp ZIP")

        # --- Email ---
        email_dir = self.config.email_source_dir
        if email_dir:
            email_path = Path(email_dir).expanduser()
            if email_path.is_dir():
                for f in sorted(email_path.rglob("*")):
                    if f.is_file():
                        rel = f.relative_to(email_path)
                        _copy_and_hash(f, staging / "email" / rel, "email")

        # --- Microsoft Teams ---
        teams_dir = self.config.teams_source_dir
        if teams_dir:
            teams_path = Path(teams_dir).expanduser()
            if teams_path.is_dir():
                for f in sorted(teams_path.rglob("*")):
                    if f.is_file():
                        rel = f.relative_to(teams_path)
                        _copy_and_hash(f, staging / "teams" / rel, "Teams")

        # --- Screenshots ---
        ss_dir = self.config.screenshot_source_dir
        if ss_dir:
            ss_path = Path(ss_dir).expanduser()
            if ss_path.is_dir():
                for f in sorted(ss_path.iterdir()):
                    if f.is_file():
                        _copy_and_hash(f, staging / "screenshots" / f.name, "screenshot")

        # --- Counseling records ---
        counseling_dir = self.config.counseling_source_dir
        if counseling_dir:
            counseling_path = Path(counseling_dir).expanduser()
            if counseling_path.is_dir():
                for f in sorted(counseling_path.rglob("*")):
                    if f.is_file():
                        rel = f.relative_to(counseling_path)
                        _copy_and_hash(f, staging / "counseling" / rel, "counseling")

        if preserved_count == 0:
            print("    No source files found to preserve")
            # Clean up empty staging dir
            if staging.exists():
                shutil.rmtree(staging)
            return

        # --- Zip the staging tree ---
        zip_path = run_dir / "preserved_sources.zip"
        print(f"    Archiving {preserved_count} source files...")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(staging.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(staging))

        # Hash the archive itself
        archive_hash = self.forensic.compute_hash(zip_path)
        self.forensic.record_action(
            "source_archive_created",
            f"Created source evidence archive with {preserved_count} files",
            {"archive": str(zip_path), "hash": archive_hash, "file_count": preserved_count},
        )
        self.manifest.add_output_file(zip_path)

        # Remove unzipped staging tree (originals are untouched)
        shutil.rmtree(staging)

        print(f"    Preserved {preserved_count} source files → {zip_path.name}")

    # ------------------------------------------------------------------
    # Attachment preservation (FRE 1002 — Best Evidence Rule)
    # ------------------------------------------------------------------

    def _preserve_attachments(self, extracted_data: Dict):
        """
        Create hash-verified working copies of all attachment files.

        Copies each original attachment to output_dir/attachments/ and
        updates the message dicts to reference the preserved copy.
        Deduplicates so the same source file is only copied once even
        if referenced by multiple messages.
        """
        messages = extracted_data.get('messages', [])
        dest_dir = Path(self.config.output_dir) / "attachments"

        preserved = {}   # {original_path_str: preserved_path}
        preserved_count = 0
        image_count = 0
        missing_count = 0

        IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.heic', '.heif', '.tiff', '.bmp', '.webp'}

        print("\n[*] Preserving attachment files (FRE 1002 — Best Evidence Rule)...")

        for msg in messages:
            # Handle primary attachment path
            att_path_str = msg.get('attachment')
            if att_path_str:
                att_path = Path(att_path_str)
                if att_path_str in preserved:
                    # Already copied — just update the reference
                    msg['attachment'] = str(preserved[att_path_str])
                elif att_path.is_file():
                    copy_path = self.integrity.create_working_copy(att_path, dest_dir)
                    if copy_path:
                        preserved[att_path_str] = copy_path
                        msg['attachment'] = str(copy_path)
                        preserved_count += 1
                        if att_path.suffix.lower() in IMAGE_EXTS:
                            image_count += 1
                else:
                    missing_count += 1
                    self.forensic.record_action(
                        "attachment_missing",
                        f"Attachment file not found: {att_path_str}",
                        {"path": att_path_str, "message_id": msg.get('message_id', '')}
                    )

            # Handle attachments list (multiple per message)
            for att in msg.get('attachments', []):
                att_list_path_str = att.get('path')
                if not att_list_path_str:
                    continue
                att_list_path = Path(att_list_path_str)
                if att_list_path_str in preserved:
                    att['path'] = str(preserved[att_list_path_str])
                elif att_list_path.is_file():
                    copy_path = self.integrity.create_working_copy(att_list_path, dest_dir)
                    if copy_path:
                        att['path'] = str(copy_path)
                        if att_list_path_str not in preserved:
                            preserved_count += 1
                            if att_list_path.suffix.lower() in IMAGE_EXTS:
                                image_count += 1
                        preserved[att_list_path_str] = copy_path
                else:
                    if att_list_path_str not in preserved:
                        missing_count += 1

        other_count = preserved_count - image_count
        print(f"    Preserved {preserved_count} attachment files "
              f"({image_count} images, {other_count} other)")
        if missing_count:
            print(f"    WARNING: {missing_count} attachment files not found on disk")

    # ------------------------------------------------------------------
    # Pipeline state (for resume after crash)
    # ------------------------------------------------------------------

    def _save_pipeline_state(self, review_session_id: str = None,
                             review_results_path: str = None,
                             ai_batch_results_path: str = None,
                             review_complete: bool = False):
        """Save pipeline state so a crashed run can resume or finalize later."""
        state = {
            "timestamp": datetime.now().isoformat(),
            "extracted_data_path": str(self._extracted_data_path) if self._extracted_data_path else None,
            "analysis_results_path": str(self._analysis_results_path) if self._analysis_results_path else None,
            "ai_batch_results_path": ai_batch_results_path,
            "review_results_path": review_results_path,
            "review_session_id": review_session_id,
            "review_complete": review_complete,
        }
        state_path = Path(self.config.output_dir) / "pipeline_state.json"
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)
        self.forensic.record_action("pipeline_state_saved", f"Pipeline state saved for resume", {"state_path": str(state_path)})

    def _load_pipeline_state(self) -> Optional[Dict]:
        """Load pipeline state from a previous run. Returns None if no state file."""
        state_path = Path(self.config.output_dir) / "pipeline_state.json"
        if not state_path.exists():
            return None
        with open(state_path) as f:
            return json.load(f)

    def _clear_pipeline_state(self):
        """Remove pipeline state file after successful completion."""
        state_path = Path(self.config.output_dir) / "pipeline_state.json"
        if state_path.exists():
            state_path.unlink()
        
    def run_extraction_phase(self) -> Dict:
        """Run the data extraction phase."""
        print("\n" + "="*60)
        print("PHASE 1: DATA EXTRACTION")
        print("="*60)

        # Ensure we are writing into a run subfolder.  If the caller
        # (e.g. direct ForensicAnalyzer usage without run.py) didn't
        # create one, do it now so nothing lands in the base output dir.
        output_dir = Path(self.config.output_dir)
        if not re.search(r'run_\d{8}_\d{6}', output_dir.name):
            run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_dir = output_dir / f"run_{run_ts}"
            run_dir.mkdir(parents=True, exist_ok=True)
            print(f"    [!] output_dir was not a run subfolder — created {run_dir.name}")
            self.forensic.record_action(
                "run_folder_created",
                f"Auto-created run subfolder (caller did not set one)",
                {"original_output_dir": str(output_dir), "run_dir": str(run_dir)},
            )
            self.config.output_dir = str(run_dir)
            # Re-point forensic recorder at the new directory
            self.forensic = ForensicRecorder(run_dir)
            self.integrity = ForensicIntegrity(self.forensic)
            self.manifest = RunManifest(self.forensic, config=self.config)

        # Hash all source files BEFORE reading them (chain of custody)
        self._hash_source_files()

        # Archive source evidence into the run folder (before extraction)
        self._preserve_source_files()

        extractor = DataExtractor(self.forensic, third_party_registry=self.third_party_registry, config=self.config)
        
        # Extract all message data
        print("\n[*] Extracting message data from all sources...")
        try:
            all_messages = extractor.extract_all()
            print(f"    Extracted {len(all_messages)} total messages")
        except Exception as e:
            print(f"    Error extracting messages: {e}")
            all_messages = []

        if not all_messages:
            print("\n[ABORT] No messages extracted. Cannot proceed with analysis.")
            print("    Check your data sources and contact mappings in .env")
            raise RuntimeError("Extraction produced 0 messages — aborting to avoid wasting API credits")
        
        # Catalog screenshots
        print("\n[*] Cataloging screenshots...")
        screenshots = []
        if self.config.screenshot_source_dir:
            try:
                screenshot_extractor = ScreenshotExtractor(
                    self.config.screenshot_source_dir,
                    self.forensic
                )
                screenshots = screenshot_extractor.extract_screenshots()
                print(f"    Cataloged {len(screenshots)} screenshots")
            except Exception as e:
                print(f"    Error cataloging screenshots: {e}")
        else:
            print("    No screenshot directory configured")
        
        # Save extracted data
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = Path(self.config.output_dir) / f"extracted_data_{timestamp}.json"
        
        extraction_results = {
            'messages': all_messages,
            'screenshots': screenshots,
            'combined': all_messages,  # For backwards compatibility
            'third_party_contacts': self.third_party_registry.get_all(),
        }

        # Preserve original attachment files with hash verification (FRE 1002)
        self._preserve_attachments(extraction_results)

        with open(output_file, 'w') as f:
            json.dump(extraction_results, f, indent=2, default=str)

        self._extracted_data_path = output_file
        self.manifest.add_operation("extraction", "success",
                                    {"message_count": len(all_messages),
                                     "screenshot_count": len(screenshots)})
        print(f"\n[✓] Extraction complete. Data saved to {output_file}")

        return extraction_results
    
    def run_analysis_phase(self, data: Dict) -> Dict:
        """Run the analysis phase on extracted data."""
        print("\n" + "="*60)
        print("PHASE 2: AUTOMATED ANALYSIS")
        print("="*60)
        
        results = {}
        messages = data.get('messages', [])
        
        if not messages:
            print("\n[!] No message data to analyze")
            return results
        
        # Convert to DataFrame for analysis
        import pandas as pd
        combined_df = pd.DataFrame(messages)
        
        print(f"\n[*] Analyzing {len(combined_df)} messages")
        
        # Run threat analysis
        print("\n[*] Analyzing threats...")
        threat_analyzer = ThreatAnalyzer(self.forensic)
        threat_results = threat_analyzer.detect_threats(combined_df)
        threat_summary = threat_analyzer.generate_threat_summary(threat_results)
        results['threats'] = {
            'details': threat_results.to_dict('records') if hasattr(threat_results, 'to_dict') else threat_results,
            'summary': threat_summary
        }
        print(f"    Detected threats in {threat_summary.get('messages_with_threats', 0)} messages")
        
        # Run sentiment analysis
        print("\n[*] Analyzing sentiment...")
        sentiment_analyzer = SentimentAnalyzer(self.forensic)
        sentiment_results = sentiment_analyzer.analyze_sentiment(combined_df)
        results['sentiment'] = sentiment_results.to_dict('records') if hasattr(sentiment_results, 'to_dict') else sentiment_results
        print("    Sentiment analysis complete")
        
        # NOTE: Behavioral analysis moved to Phase 4 (after manual review) to ensure trends are based on reviewed/confirmed data, not raw detections.
        
        # Run pattern analysis
        print("\n[*] Running pattern detection...")
        pattern_analyzer = YamlPatternAnalyzer(self.forensic)
        pattern_results = pattern_analyzer.analyze_patterns(combined_df)
        results['patterns'] = pattern_results.to_dict('records') if hasattr(pattern_results, 'to_dict') else pattern_results
        print(f"    Pattern detection complete")
        
        # Process screenshots
        if data.get('screenshots'):
            print("\n[*] Analyzing screenshots...")
            screenshot_analyzer = ScreenshotAnalyzer(
                self.forensic, third_party_registry=self.third_party_registry,
                screenshots_dir=self.config.screenshot_source_dir,
            )
            # Run contact extraction on already-extracted screenshots
            for screenshot in data['screenshots']:
                text = screenshot.get('extracted_text', '')
                if text:
                    contacts = screenshot_analyzer._extract_contact_info(
                        text, screenshot.get('filename', '')
                    )
                    screenshot['contacts_found'] = contacts
            screenshot_results = data['screenshots']
            results['screenshots'] = screenshot_results
            print(f"    Analyzed {len(screenshot_results)} screenshots")
        
        # Communication metrics
        print("\n[*] Calculating communication metrics...")
        metrics_analyzer = CommunicationMetricsAnalyzer(forensic_recorder=self.forensic)
        metrics_results = metrics_analyzer.analyze_messages(messages)
        results['metrics'] = metrics_results
        print("    Communication metrics calculated")

        # Save the enriched DataFrame for Phase 4 behavioral analysis. At this point combined_df has threat, sentiment, and pattern columns.
        self._enriched_df = combined_df.copy()

        # AI batch analysis runs in Phase 3 (after this phase).
        # Placeholder here; populated by run_ai_batch_phase().
        results['ai_analysis'] = {}

        # Save analysis results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = Path(self.config.output_dir) / f"analysis_results_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        self._analysis_results_path = output_file
        self.manifest.add_operation("analysis", "success",
                                    {"message_count": len(messages),
                                     "analyzers_run": list(results.keys())})
        print(f"\n[✓] Analysis complete. Results saved to {output_file}")

        return results

    def run_ai_batch_phase(self, extracted_data: Dict) -> Dict:
        """Run AI batch processing on messages (Phase 3, pre-review).

        Sends mapped-contact messages to Claude for classification:
        threats, coercive control, behavioral patterns, sentiment.
        Does NOT generate the executive summary — that runs post-review
        in finalize so it can incorporate review decisions.

        Args:
            extracted_data: Raw extraction data with all messages.

        Returns:
            AI batch results dict (without summary), or empty dict on skip/error.
        """
        print("\n" + "="*60)
        print("PHASE 3: PRE-REVIEW SCREENING")
        print("="*60)

        try:
            from src.analyzers.ai_analyzer import AIAnalyzer
            ai_analyzer = AIAnalyzer(forensic_recorder=self.forensic, config=self.config)
            if not ai_analyzer.client:
                print("    Pre-review screening skipped - AI not configured")
                return ai_analyzer._empty_analysis()

            messages = extracted_data.get('messages', [])
            ai_contacts = self.config.ai_contacts
            ai_specified = self.config.ai_contacts_specified
            mapped_messages = [
                m for m in messages
                if m.get('source') != 'counseling'
                and m.get('sender') in ai_contacts
                and m.get('recipient') in ai_contacts
                and (ai_specified is None
                     or m.get('sender') in ai_specified
                     or m.get('recipient') in ai_specified)
            ]
            skipped = len(messages) - len(mapped_messages)
            if skipped:
                print(f"    Filtered to {len(mapped_messages)} mapped-contact "
                      f"messages (skipped {skipped} unmapped)")

            # generate_summary=False — summary runs post-review in finalize
            ai_results = ai_analyzer.analyze_messages(
                mapped_messages, batch_size=self.config.batch_size,
                generate_summary=False,
            )
            threat_count = len(ai_results.get('threat_assessment', {}).get('details', []))
            cc_count = len(ai_results.get('coercive_control', {}).get('patterns', []))
            print(f"    AI batch complete - {threat_count} threats, "
                  f"{cc_count} coercive control patterns found")

            self.manifest.add_operation("ai_batch_analysis", "success",
                                        {"message_count": len(mapped_messages),
                                         "threats": threat_count,
                                         "coercive_control_patterns": cc_count})

            # Save AI results to disk so finalize can load them
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ai_output_file = Path(self.config.output_dir) / f"ai_batch_results_{timestamp}.json"
            with open(ai_output_file, 'w') as f:
                json.dump(ai_results, f, indent=2, default=str)
            self._ai_batch_results_path = ai_output_file
            print(f"    AI batch results saved to {ai_output_file.name}")

            return ai_results

        except Exception as e:
            print(f"    AI batch analysis error: {e}")
            import traceback
            traceback.print_exc()
            return {}

    def run_review_phase(self, analysis_results: Dict, extracted_data: Dict, resume_session_id: str = None) -> Dict:
        """Run the interactive manual review phase on flagged items."""
        print("\n" + "="*60)
        print("PHASE 4: INTERACTIVE MANUAL REVIEW")
        print("="*60)

        manager = ManualReviewManager(session_id=resume_session_id, config=self.config,
                                       forensic_recorder=self.forensic)
        self._review_session_id = manager.session_id
        already_reviewed = manager.reviewed_item_ids

        # Present items for review — only from mapped contacts
        items_for_review = []

        # Determine which contacts are legally relevant (same filter as AI analysis)
        ai_contacts = self.config.ai_contacts
        ai_specified = self.config.ai_contacts_specified

        def _is_mapped(item: dict) -> bool:
            """Check if a message involves only mapped contacts."""
            sender = item.get('sender', '')
            recipient = item.get('recipient', '')
            if sender not in ai_contacts or recipient not in ai_contacts:
                return False
            if ai_specified is not None:
                if sender not in ai_specified and recipient not in ai_specified:
                    return False
            return True

        # Add threats from local analyzers (Phase 2) for review.
        # These findings are stamped source="pattern_matched" because they come from deterministic regex/YAML rules; juries and opposing counsel treat them differently from AI-screened findings.
        if 'threats' in analysis_results:
            threat_details = analysis_results['threats'].get('details', [])
            # threat_details is a list of dicts, not a DataFrame
            if isinstance(threat_details, list):
                for idx, item in enumerate(threat_details):
                    if item.get('threat_detected') and _is_mapped(item):
                        items_for_review.append({
                            'id': f"threat_{idx}",
                            'type': 'threat',
                            'source': 'pattern_matched',
                            'method': 'yaml_patterns',
                            'content': item.get('content', ''),
                            'categories': item.get('threat_categories', ''),
                            'confidence': item.get('threat_confidence', 0),
                            'message_id': item.get('message_id', ''),
                        })

        # AI-detected threats and coercive-control patterns carry source="ai_screened". These come from an LLM and are explicitly non-evidentiary until confirmed by a human reviewer; the source tag is what lets reports distinguish them in court.
        ai_analysis = analysis_results.get('ai_analysis', {})
        ai_model_name = ai_analysis.get('model') or 'claude'
        ai_threats = ai_analysis.get('threat_assessment', {})
        if ai_threats.get('found'):
            for i, detail in enumerate(ai_threats.get('details', [])):
                if isinstance(detail, dict):
                    items_for_review.append({
                        'id': f"ai_threat_{i}",
                        'type': 'ai_threat',
                        'source': 'ai_screened',
                        'method': ai_model_name,
                        'content': detail.get('quote', ''),
                        'categories': f"{detail.get('type', '')} — {detail.get('target', '')}",
                        'confidence': detail.get('severity', ''),
                        'message_id': '',
                        'rcw_relevance': detail.get('rcw_relevance', ''),
                    })

        # Add AI-detected coercive control patterns for review
        ai_cc = ai_analysis.get('coercive_control', {})
        if ai_cc.get('detected'):
            for i, pattern in enumerate(ai_cc.get('patterns', [])):
                if isinstance(pattern, dict):
                    items_for_review.append({
                        'id': f"ai_coercive_{i}",
                        'type': 'ai_coercive_control',
                        'source': 'ai_screened',
                        'method': ai_model_name,
                        'content': pattern.get('quote', ''),
                        'categories': f"Coercive control: {pattern.get('type', '')}",
                        'confidence': pattern.get('severity', ''),
                        'message_id': '',
                    })

        # Add ALL email messages for review — emails are low-volume and each
        # is purposeful.  Third-party emails (counselors, attorneys, family)
        # provide crucial corroboration; mapped-person emails may need context
        # annotations from the reviewer.
        all_messages = extracted_data.get('messages', [])
        mapped_persons = set(self.config.contact_mappings.keys())
        for msg in all_messages:
            if msg.get('source') != 'email':
                continue
            sender = msg.get('sender', '')
            recipient = msg.get('recipient', '')
            is_third_party = sender not in mapped_persons or recipient not in mapped_persons
            item_type = 'third_party_email' if is_third_party else 'email'
            subject = msg.get('subject', '')
            content = msg.get('content', '')
            label = f"Subject: {subject}" if subject else (content[:80] if content else '(no content)')
            items_for_review.append({
                'id': f"email_{msg.get('message_id', '')}",
                'type': item_type,
                'source': 'extracted',
                'method': 'email_import',
                'content': content,
                'categories': f"{'Third-Party ' if is_third_party else ''}Email: {sender} → {recipient}",
                'confidence': 0.0,
                'message_id': msg.get('message_id', ''),
                'subject': subject,
            })

        print(f"\n[*] {len(items_for_review)} items flagged for review (local threats + AI threats + AI coercive control + emails)")

        # Filter out already-reviewed items (resume support)
        if already_reviewed:
            total_flagged = len(items_for_review)
            items_for_review = [i for i in items_for_review if i['id'] not in already_reviewed]
            skipped = total_flagged - len(items_for_review)
            if skipped:
                print(f"    Resuming: {skipped} already reviewed, {len(items_for_review)} remaining")

        # Save pipeline state with review session ID (for crash recovery)
        self._save_pipeline_state(review_session_id=manager.session_id)

        # Choose review mode (web or terminal)
        # Only pass mapped-contact messages to the review UI
        all_messages = extracted_data.get('messages', [])
        messages = [m for m in all_messages if _is_mapped(m)]
        screenshots = extracted_data.get('screenshots', [])

        review_mode = 'terminal'
        if items_for_review:
            try:
                choice = input("\n    Review mode: (W)eb interface or (T)erminal? [W]: ").strip().upper()
                if choice != 'T':
                    review_mode = 'web'
            except (EOFError, KeyboardInterrupt):
                review_mode = 'terminal'

        if review_mode == 'web' and items_for_review:
            try:
                from src.review.web_review import WebReview
                web = WebReview(manager, forensic_recorder=self.forensic, config=self.config)
                web.start_review(messages, items_for_review, screenshots=screenshots)
            except ImportError:
                print("    Flask not installed. Falling back to terminal review.")
                from src.review.interactive_review import InteractiveReview
                interactive = InteractiveReview(manager, config=self.config)
                interactive.review_flagged_items(messages, items_for_review)
        else:
            from src.review.interactive_review import InteractiveReview
            interactive = InteractiveReview(manager, config=self.config)
            interactive.review_flagged_items(messages, items_for_review)

        # Get review summary
        relevant = manager.get_reviews_by_decision('relevant')
        not_relevant = manager.get_reviews_by_decision('not_relevant')
        uncertain = manager.get_reviews_by_decision('uncertain')

        review_summary = {
            'total_reviewed': len(relevant) + len(not_relevant) + len(uncertain),
            'relevant': len(relevant),
            'not_relevant': len(not_relevant),
            'uncertain': len(uncertain),
            'reviews': manager.reviews
        }

        print(f"    Relevant: {review_summary['relevant']}")
        print(f"    Not Relevant: {review_summary['not_relevant']}")
        print(f"    Uncertain: {review_summary['uncertain']}")

        print("\n[✓] Review phase complete")

        self.manifest.add_operation("manual_review", "success",
                                    {"total_reviewed": review_summary['total_reviewed'],
                                     "relevant": review_summary['relevant'],
                                     "not_relevant": review_summary['not_relevant'],
                                     "uncertain": review_summary['uncertain']})

        # Persist review results to disk for finalize phase
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        review_output = Path(self.config.output_dir) / f"review_results_{timestamp}.json"
        with open(review_output, 'w') as f:
            json.dump(review_summary, f, indent=2, default=str)
        self._review_results_path = review_output

        return review_summary
    
    def run_behavioral_phase(self, extracted_data: Dict, analysis_results: Dict, review_results: Dict) -> Dict:
        """Run behavioral analysis on review-filtered data (Phase 4).

        Uses the enriched DataFrame from Phase 2 (with threat, sentiment, and
        pattern columns) and applies Phase 3 review decisions so behavioral
        analysis only considers confirmed threats.
        """
        print("\n" + "="*60)
        print("PHASE 5: BEHAVIORAL ANALYSIS (POST-REVIEW)")
        print("="*60)

        import pandas as pd

        # Use the enriched DataFrame from Phase 2 (has threat/sentiment/pattern columns)
        enriched_df = getattr(self, '_enriched_df', None)

        if enriched_df is None or enriched_df.empty:
            # Fallback: create from raw messages (no enrichment columns)
            messages = extracted_data.get('messages', [])
            if not messages:
                print("\n[!] No message data to analyze")
                return {}
            enriched_df = pd.DataFrame(messages)
            print("    Note: Using raw messages (enriched DataFrame not available)")

        # Apply Phase 3 review decisions: clear threat annotations not confirmed in review
        approved_ids = set()
        for r in review_results.get('reviews', []):
            if r.get('decision') in ('relevant', 'uncertain'):
                approved_ids.add(r.get('item_id', ''))

        cleared_count = 0
        if 'threat_detected' in enriched_df.columns:
            for idx in enriched_df.index:
                if enriched_df.at[idx, 'threat_detected']:
                    item_id = f"threat_{idx}"
                    if item_id not in approved_ids:
                        enriched_df.at[idx, 'threat_detected'] = False
                        enriched_df.at[idx, 'threat_categories'] = ''
                        enriched_df.at[idx, 'threat_confidence'] = 0
                        enriched_df.at[idx, 'harmful_content'] = False
                        cleared_count += 1

        confirmed_threats = int(enriched_df['threat_detected'].sum()) if 'threat_detected' in enriched_df.columns else 0
        has_sentiment = 'sentiment_score' in enriched_df.columns

        if cleared_count:
            print(f"\n[*] Cleared {cleared_count} unconfirmed threats from behavioral input")
        print(f"[*] Behavioral analysis: {len(enriched_df)} messages, "
              f"{confirmed_threats} confirmed threats, "
              f"sentiment data: {'yes' if has_sentiment else 'no'}")

        # Run behavioral analysis on the review-filtered enriched data
        behavioral_analyzer = BehavioralAnalyzer(self.forensic)
        behavioral_results = behavioral_analyzer.analyze_patterns(enriched_df)

        print("    Behavioral analysis complete")

        return behavioral_results
    
    def _filter_analysis_by_review(self, analysis: Dict, review: Dict) -> Dict:
        """Filter analysis results to only include human-verified findings.

        Only threats and risk indicators explicitly marked 'relevant' or
        'uncertain' during manual review survive into analysis reports.
        Unreviewed and rejected findings are cleared.

        The forensic all-messages export is NOT affected by this filtering —
        it uses extracted_data directly and remains a complete, unfiltered record.

        Args:
            analysis: Raw analysis results from Phase 2.
            review: Review decisions from Phase 3.

        Returns:
            Deep copy of analysis with unverified findings removed.
        """
        filtered = copy.deepcopy(analysis)

        # Build set of item IDs that were approved during review
        approved_ids = set()
        for r in review.get('reviews', []):
            if r.get('decision') in ('relevant', 'uncertain'):
                approved_ids.add(r.get('item_id', ''))

        reviewed_count = review.get('total_reviewed', 0)
        approved_count = len(approved_ids)

        # --- Filter threat details ---
        if 'threats' in filtered:
            details = filtered['threats'].get('details', [])
            cleared = 0
            for idx, item in enumerate(details):
                if item.get('threat_detected'):
                    item_id = f"threat_{idx}"
                    if item_id not in approved_ids:
                        # Not approved: clear threat annotations
                        item['threat_detected'] = False
                        item['threat_categories'] = ''
                        item['threat_confidence'] = 0
                        item['harmful_content'] = False
                        cleared += 1

            # Regenerate summary from filtered data
            confirmed = [d for d in details if d.get('threat_detected')]
            old_summary = filtered['threats'].get('summary', {})
            filtered['threats']['summary'] = {
                'total_messages': old_summary.get('total_messages', len(details)),
                'messages_with_threats': len(confirmed),
                'threat_percentage': len(confirmed) / len(details) * 100 if details else 0,
                'high_confidence_threats': sum(
                    1 for d in confirmed if d.get('threat_confidence', 0) >= 0.75
                ),
                'timestamp': old_summary.get('timestamp', ''),
            }

            if cleared:
                print(f"    Filtered {cleared} unverified threats from reports")

        # --- Filter AI analysis findings ---
        # AI analysis runs post-review (Phase 5) and doesn't need filtering.

        self.forensic.record_action(
            "analysis_filtered_by_review",
            f"Filtered analysis for reports: {approved_count} approved of {reviewed_count} reviewed",
            {
                "reviewed": reviewed_count,
                "approved": approved_count,
                "approved_ids": list(approved_ids),
            },
        )

        return filtered


    def run_reporting_phase(self, data: Dict, analysis: Dict, review: Dict) -> Dict:
        """Generate reports in multiple formats."""
        print("\n" + "="*60)
        print("PHASE 7: REPORT GENERATION")
        print("="*60)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports = {}

        # Filter analysis to only include human-verified findings
        # The forensic all-messages export (CSV/Excel) uses extracted_data directly
        # and is NOT affected by this filtering.
        print("\n[*] Filtering analysis by review decisions...")
        filtered_analysis = self._filter_analysis_by_review(analysis, review)

        # Use ForensicReporter for comprehensive reports
        forensic_reporter = ForensicReporter(self.forensic, config=self.config)

        # Generate all report formats (with filtered analysis)
        print("\n[*] Generating comprehensive reports...")
        generated_reports = forensic_reporter.generate_comprehensive_report(
            data, filtered_analysis, review
        )

        for format_name, path in generated_reports.items():
            reports[format_name] = str(path)
            print(f"    {format_name.upper()} report: {path.name}")

        # Also generate separate Excel report if needed
        if 'excel' not in reports:
            print("\n[*] Generating Excel report...")
            try:
                enriched_data = data.copy()

                excel_reporter = ExcelReporter(self.forensic, config=self.config)
                excel_path = Path(self.config.output_dir) / f"report_{timestamp}.xlsx"
                excel_reporter.generate_report(enriched_data, filtered_analysis, review, excel_path)
                reports['excel'] = str(excel_path)
                print(f"    Saved to {excel_path}")
            except Exception as e:
                print(f"    Error generating Excel report: {e}")
                import traceback
                traceback.print_exc()

        # Generate HTML/PDF report with inline images
        print("\n[*] Generating HTML/PDF report (with inline images)...")
        try:
            html_reporter = HtmlReporter(self.forensic, config=self.config)
            html_base = Path(self.config.output_dir) / f"report_{timestamp}"
            html_paths = html_reporter.generate_report(data, filtered_analysis, review, html_base)
            for fmt, path in html_paths.items():
                reports[fmt] = str(path)
                print(f"    {fmt.upper()} report: {path.name}")
        except Exception as e:
            print(f"    Error generating HTML/PDF report: {e}")
            import traceback
            traceback.print_exc()

        # Generate chat-bubble HTML report
        print("\n[*] Generating chat-bubble HTML report...")
        try:
            from src.reporters.chat_reporter import ChatReporter
            chat_reporter = ChatReporter(self.forensic, config=self.config)
            chat_base = Path(self.config.output_dir) / f"report_{timestamp}"
            chat_paths = chat_reporter.generate_report(data, filtered_analysis, review, chat_base)
            for fmt, path in chat_paths.items():
                reports[fmt] = str(path)
                print(f"    {fmt.upper()} report: {path.name}")
        except Exception as e:
            print(f"    Error generating chat report: {e}")
            import traceback
            traceback.print_exc()

        # Generate JSON report if needed
        if 'json' not in reports:
            print("\n[*] Generating JSON report...")
            try:
                json_reporter = JSONReporter(self.forensic, config=self.config)
                json_path = Path(self.config.output_dir) / f"report_{timestamp}.json"
                json_reporter.generate_report(data, filtered_analysis, review, json_path)
                reports['json'] = str(json_path)
                print(f"    Saved to {json_path}")
            except Exception as e:
                print(f"    Error generating JSON report: {e}")

        # Generate legal team summary docx (after all reports so file table is complete)
        legal_text = getattr(forensic_reporter, '_legal_summary_text', None)
        if legal_text:
            print("\n[*] Generating legal team summary document...")
            try:
                summary_path = Path(self.config.output_dir) / f"legal_team_summary_{timestamp}.docx"
                forensic_reporter._generate_legal_summary_docx(legal_text, summary_path, reports)
                reports['legal_summary'] = str(summary_path)
                file_hash = self.forensic.compute_hash(summary_path)
                self.forensic.record_action(
                    "legal_summary_generated",
                    f"Generated legal team summary with hash {file_hash}",
                    {"path": str(summary_path), "hash": file_hash}
                )
                print(f"    Saved to {summary_path.name}")
            except Exception as e:
                print(f"    Error generating legal team summary: {e}")
                import traceback
                traceback.print_exc()

        # Generate the READ ME FIRST cover sheet last so it can point at
        # every other file by actual filename. This is the document the
        # legal team should open first.
        print("\n[*] Generating READ ME FIRST cover sheet...")
        try:
            cover_path = forensic_reporter.generate_cover_sheet(reports, timestamp)
            reports['cover_sheet'] = str(cover_path)
            print(f"    Saved to {cover_path.name}")
        except Exception as e:
            print(f"    Error generating cover sheet: {e}")
            import traceback
            traceback.print_exc()

        print("\n[✓] Report generation complete")

        self.manifest.add_operation("reporting", "success",
                                    {"report_formats": list(reports.keys())})
        for fmt, path in reports.items():
            self.manifest.add_output_file(Path(path), f"{fmt}_report")

        return reports
    
    def run_documentation_phase(self, data: Dict, analysis_results: Dict = None) -> Dict:
        """Generate final documentation and chain of custody."""
        print("\n" + "="*60)
        print("PHASE 8: DOCUMENTATION")
        print("="*60)
        
        # Generate chain of custody
        print("\n[*] Generating chain of custody...")
        chain_path = self.forensic.generate_chain_of_custody()
        if chain_path:
            print(f"    Saved to {chain_path}")
        else:
            print("    WARNING: Chain of custody generation failed")
        
        # Generate timeline if we have message data
        timeline_path = None
        combined_data = data.get('messages', data.get('combined', []))
        if combined_data:
            print("\n[*] Generating timeline...")
            timeline_gen = TimelineGenerator(self.forensic, config=self.config)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            timeline_path = Path(self.config.output_dir) / f"timeline_{timestamp}.html"

            # Convert to DataFrame
            import pandas as pd
            if isinstance(combined_data, list):
                df = pd.DataFrame(combined_data)
            else:
                df = combined_data

            # Merge analysis columns if available (join on message_id for safety)
            if analysis_results:
                threat_details = analysis_results.get('threats', {}).get('details', [])
                if threat_details and isinstance(threat_details, list):
                    analysis_df = pd.DataFrame(threat_details)
                    analysis_cols = ['threat_detected', 'threat_categories', 'threat_confidence',
                                   'harmful_content', 'sentiment_score', 'sentiment_polarity',
                                   'sentiment_subjectivity', 'patterns_detected', 'pattern_score']
                    merge_cols = [c for c in analysis_cols if c in analysis_df.columns and c not in df.columns]
                    if merge_cols and 'message_id' in df.columns and 'message_id' in analysis_df.columns:
                        df = df.merge(
                            analysis_df[['message_id'] + merge_cols],
                            on='message_id', how='left',
                        )
                    elif merge_cols:
                        # Fallback: positional only if lengths match exactly
                        if len(analysis_df) == len(df):
                            for col in merge_cols:
                                df[col] = analysis_df[col].values

            timeline_gen.create_timeline(df, timeline_path, extracted_data=data)
            print(f"    Saved to {timeline_path}")
        else:
            print("\n[!] Skipping timeline generation (no message data)")
        
        # Generate run manifest
        print("\n[*] Generating run manifest...")
        manifest_path = self.manifest.generate_manifest()
        print(f"    Saved to {manifest_path}")
        
        print("\n[✓] Documentation complete")
        
        result = {}
        if chain_path:
            result['chain_of_custody'] = str(chain_path)
        result['manifest'] = str(manifest_path)
        if timeline_path:
            result['timeline'] = str(timeline_path)
        
        return result
    
    def run_full_analysis(self, resume: bool = False):
        """Run extraction, analysis, AI batch, and review phases (1-4), then stop.

        After review completes, pipeline state is saved and the process
        exits.  Run ``run_finalize()`` (via ``python3 run.py --finalize``)
        to continue with behavioral analysis, AI summary, reporting, and
        documentation (Phases 5-8).

        Args:
            resume: If True, skip extraction and analysis by loading
                    saved state from a previous run. Resumes at the review phase.
        """
        print("\n" + "="*80)
        print(" FORENSIC MESSAGE ANALYZER — PHASES 1-4 ")
        print("="*80)
        print(f"Session started: {datetime.now()}")
        print(f"Output directory: {self.config.output_dir}")

        resume_session_id = None

        if resume:
            state = self._load_pipeline_state()
            if state and not state.get("review_complete"):
                ext_path = state.get("extracted_data_path")
                ana_path = state.get("analysis_results_path")
                resume_session_id = state.get("review_session_id")

                if ext_path and ana_path and Path(ext_path).exists() and Path(ana_path).exists():
                    print(f"\n[*] Resuming from saved state ({state.get('timestamp', 'unknown')})")
                    print(f"    Extraction: {Path(ext_path).name}")
                    print(f"    Analysis:   {Path(ana_path).name}")
                    if resume_session_id:
                        print(f"    Review session: {resume_session_id}")

                    with open(ext_path) as f:
                        extracted_data = json.load(f)
                    with open(ana_path) as f:
                        analysis_results = json.load(f)

                    self._extracted_data_path = Path(ext_path)
                    self._analysis_results_path = Path(ana_path)

                    print("\n    Skipping Phases 1-3 (extraction, analysis, AI batch) — already completed.")
                else:
                    print("\n[!] State file found but data files missing. Starting fresh.")
                    resume = False
            else:
                print("\n[!] No resumable state found. Starting fresh.")
                resume = False

        try:
            if not resume:
                # Phase 1: Extraction
                extracted_data = self.run_extraction_phase()

                # Phase 2: Local Analysis (threat, sentiment, pattern — no AI)
                analysis_results = self.run_analysis_phase(extracted_data)

                # Phase 3: AI Batch Analysis (pre-review, no summary)
                ai_batch_results = self.run_ai_batch_phase(extracted_data)
                analysis_results['ai_analysis'] = ai_batch_results

                # Re-save analysis results now that AI batch data is included,
                # so finalize can load the complete analysis from disk.
                if self._analysis_results_path:
                    with open(self._analysis_results_path, 'w') as f:
                        json.dump(analysis_results, f, indent=2, default=str)

                # Save state so review can be resumed if process dies
                self._save_pipeline_state()

            # Phase 4: Manual Review (reviews local + AI findings)
            review_results = self.run_review_phase(analysis_results, extracted_data, resume_session_id=resume_session_id)

            # Save complete state with review results for finalize
            self._save_pipeline_state(
                review_session_id=getattr(self, '_review_session_id', None),
                review_results_path=str(self._review_results_path) if getattr(self, '_review_results_path', None) else None,
                ai_batch_results_path=str(self._ai_batch_results_path) if getattr(self, '_ai_batch_results_path', None) else None,
                review_complete=True,
            )

            print("\n" + "="*80)
            print(" REVIEW COMPLETE — PIPELINE PAUSED ")
            print("="*80)
            print(f"\nRun directory: {self.config.output_dir}")
            print(f"\nTo generate reports, run:")
            print(f"  python3 run.py --finalize \"{self.config.output_dir}\"")
            print(f"\nOr auto-detect the latest run:")
            print(f"  python3 run.py --finalize")

        except Exception as e:
            print(f"\n[ERROR] Workflow failed: {e}")
            import traceback
            traceback.print_exc()
            raise

    def run_finalize(self):
        """Run post-review phases (5-8) using saved pipeline state.

        Loads extraction data, analysis results (including AI batch results),
        and review decisions from disk. Runs behavioral analysis, AI executive
        summary, reporting, and documentation.
        """
        print("\n" + "="*80)
        print(" FORENSIC MESSAGE ANALYZER — FINALIZE (POST-REVIEW) ")
        print("="*80)
        print(f"Session started: {datetime.now()}")
        print(f"Output directory: {self.config.output_dir}")

        state = self._load_pipeline_state()
        if not state:
            raise RuntimeError(
                "No pipeline state found. Run the full pipeline first "
                "(python3 run.py) to complete Phases 1-4."
            )
        if not state.get("review_complete"):
            raise RuntimeError(
                "Review is not yet complete. Run the full pipeline or "
                "resume review (python3 run.py --resume) before finalizing."
            )

        # Validate all required paths exist
        ext_path = state.get("extracted_data_path")
        ana_path = state.get("analysis_results_path")
        rev_path = state.get("review_results_path")

        missing = []
        for label, path in [("Extraction data", ext_path), ("Analysis results", ana_path), ("Review results", rev_path)]:
            if not path or not Path(path).exists():
                missing.append(f"{label}: {path or '(not set)'}")
        if missing:
            raise RuntimeError(
                "Pipeline state references missing files:\n  " + "\n  ".join(missing)
            )

        # Load saved data
        print(f"\n[*] Loading saved pipeline data...")
        print(f"    Extraction: {Path(ext_path).name}")
        print(f"    Analysis:   {Path(ana_path).name}")
        print(f"    Review:     {Path(rev_path).name}")

        with open(ext_path) as f:
            extracted_data = json.load(f)
        with open(ana_path) as f:
            analysis_results = json.load(f)
        with open(rev_path) as f:
            review_results = json.load(f)

        self._extracted_data_path = Path(ext_path)
        self._analysis_results_path = Path(ana_path)

        # Reconstruct enriched DataFrame for Phase 4 behavioral analysis.
        # During the initial run, Phase 2 enriches a DataFrame with threat/sentiment/pattern
        # columns and saves it as self._enriched_df. Since finalize runs in a new process,
        # we must rebuild it from the saved analysis results.
        import pandas as pd
        messages = extracted_data.get('messages', [])
        if messages:
            enriched_df = pd.DataFrame(messages)
            # Merge threat columns from analysis details
            threat_details = analysis_results.get('threats', {}).get('details', [])
            if threat_details and len(threat_details) == len(enriched_df):
                threat_df = pd.DataFrame(threat_details)
                for col in ['threat_detected', 'threat_categories', 'threat_confidence', 'harmful_content']:
                    if col in threat_df.columns and col not in enriched_df.columns:
                        enriched_df[col] = threat_df[col].values
            # Merge sentiment columns
            sentiment_data = analysis_results.get('sentiment', [])
            if sentiment_data and len(sentiment_data) == len(enriched_df):
                sentiment_df = pd.DataFrame(sentiment_data)
                for col in ['sentiment_score', 'sentiment_polarity', 'sentiment_subjectivity']:
                    if col in sentiment_df.columns and col not in enriched_df.columns:
                        enriched_df[col] = sentiment_df[col].values
            # Merge pattern columns
            pattern_data = analysis_results.get('patterns', [])
            if pattern_data and len(pattern_data) == len(enriched_df):
                pattern_df = pd.DataFrame(pattern_data)
                for col in ['patterns_detected', 'pattern_score']:
                    if col in pattern_df.columns and col not in enriched_df.columns:
                        enriched_df[col] = pattern_df[col].values
            self._enriched_df = enriched_df

        self.forensic.record_action(
            "finalize_started",
            "Post-review finalization started from saved pipeline state",
            {"state_timestamp": state.get("timestamp", "unknown")},
        )

        try:
            # Phase 5: Behavioral Analysis (post-review)
            try:
                behavioral_results = self.run_behavioral_phase(extracted_data, analysis_results, review_results)
                analysis_results['behavioral'] = behavioral_results
            except Exception as e:
                print(f"\n[!] Behavioral analysis failed (non-fatal): {e}")
                analysis_results['behavioral'] = {}

            # Update third-party contact data (screenshots may have added more during analysis)
            extracted_data['third_party_contacts'] = self.third_party_registry.get_all()
            tp_summary = self.third_party_registry.get_summary()
            if tp_summary['total'] > 0:
                print(f"\n[*] Discovered {tp_summary['total']} third-party contacts")
                for src, count in tp_summary['by_source'].items():
                    print(f"    {src}: {count}")

            # Phase 6: Executive Summary (post-review)
            # Batch results already exist from Phase 3 (pre-review).
            # Now generate summary, risks, and recommendations using the
            # summary model, incorporating the actual conversation messages.
            ai_results = analysis_results.get('ai_analysis', {})
            if ai_results and ai_results.get('total_messages', 0) > 0:
                print("\n" + "="*60)
                print("PHASE 6: EXECUTIVE SUMMARY (POST-REVIEW)")
                print("="*60)
                try:
                    from src.analyzers.ai_analyzer import AIAnalyzer
                    from src.utils.pricing import get_pricing
                    ai_analyzer = AIAnalyzer(forensic_recorder=self.forensic, config=self.config)
                    if ai_analyzer.client:
                        # Build message list for the summary using the same
                        # contact filter as Phase 3 (AI batch analysis).
                        ai_contacts = self.config.ai_contacts
                        ai_specified = self.config.ai_contacts_specified
                        summary_messages = [
                            m for m in extracted_data.get('messages', [])
                            if m.get('source') != 'counseling'
                            and m.get('sender') in ai_contacts
                            and m.get('recipient') in ai_contacts
                            and (ai_specified is None
                                 or m.get('sender') in ai_specified
                                 or m.get('recipient') in ai_specified)
                        ]
                        summary_messages.sort(key=lambda m: m.get('timestamp', ''))

                        # Show accurate cost estimate before calling the API
                        if summary_messages:
                            sample_text, msg_count, _ = (
                                ai_analyzer._format_messages_for_summary(summary_messages)
                            )
                            est_input = ai_analyzer._estimate_tokens(sample_text) + 500
                            est_output = 4096
                            sp = get_pricing(ai_analyzer.summary_model)
                            est_cost = (
                                (est_input / 1_000_000) * sp['input']
                                + (est_output / 1_000_000) * sp['output']
                            )
                            print(
                                f"    {len(summary_messages):,} messages for executive summary "
                                f"(~{est_input:,} input tokens)"
                            )
                            print(
                                f"    Estimated summary cost: ~${est_cost:.4f} "
                                f"({ai_analyzer.summary_model})"
                            )
                            if est_cost > 1.00:
                                print(
                                    f"    Cost exceeds $1.00 — press Ctrl+C within "
                                    f"5 seconds to abort..."
                                )
                                try:
                                    import time as _time
                                    _time.sleep(5)
                                except KeyboardInterrupt:
                                    print("\n    Summary generation aborted by user.")
                                    summary_messages = None

                        if summary_messages is not None:
                            ai_results = ai_analyzer.generate_post_review_summary(
                                ai_results, messages=summary_messages
                            )
                            analysis_results['ai_analysis'] = ai_results
                            print(f"    Executive summary generated")
                        else:
                            print("    Executive summary skipped (user aborted)")
                    else:
                        print("    Executive summary skipped — AI not configured")
                except Exception as e:
                    print(f"    Executive summary error (non-fatal): {e}")
            else:
                print("\n[*] No pre-screening results found — skipping executive summary")

            # Phase 7: Reporting
            reports = self.run_reporting_phase(extracted_data, analysis_results, review_results)

            # Phase 8: Documentation (pass analysis_results for enriched timeline)
            documentation = self.run_documentation_phase(extracted_data, analysis_results)

            print("\n" + "="*80)
            print(" WORKFLOW COMPLETE ")
            print("="*80)
            print(f"\nAll outputs saved to: {self.config.output_dir}")
            print("\nGenerated files:")
            for report_type, path in reports.items():
                print(f"  - {report_type}: {Path(path).name}")
            for doc_type, path in documentation.items():
                print(f"  - {doc_type}: {Path(path).name}")

            # Clean up pipeline state file after successful completion
            self._clear_pipeline_state()

        except Exception as e:
            print(f"\n[ERROR] Finalize failed: {e}")
            import traceback
            traceback.print_exc()
            raise


def main(config: Config = None, resume: bool = False):
    """Main entry point for the forensic analyzer (Phases 1-4).

    Runs extraction, local analysis, and manual review, then stops.
    Use ``finalize()`` to run the remaining phases.

    Args:
        config: Configuration instance. If None, creates a new one.
        resume: If True, resume from saved pipeline state (skip extraction + analysis).

    Returns:
        bool: True if completed successfully, False otherwise.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.run_full_analysis(resume=resume)
        return True
    except Exception as e:
        print(f"\n[ERROR] Analysis failed: {e}")
        return False


def finalize(config: Config = None):
    """Entry point for the finalize (post-review) phase (Phases 4-7).

    Loads saved pipeline state including review decisions, then runs
    behavioral analysis, AI analysis, reporting, and documentation.

    Args:
        config: Configuration instance. ``config.output_dir`` must point
                to the run directory from the original pipeline run.

    Returns:
        bool: True if completed successfully, False otherwise.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.run_finalize()
        return True
    except Exception as e:
        print(f"\n[ERROR] Finalize failed: {e}")
        return False