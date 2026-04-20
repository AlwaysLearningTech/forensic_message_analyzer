#!/usr/bin/env python3
"""
Main orchestration script for the forensic message analyzer.
Coordinates extraction, analysis, review, and reporting phases.
"""

import sys
import json
import copy
import logging
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import Config
from src.forensic_utils import ForensicRecorder, ForensicIntegrity
from src.third_party_registry import ThirdPartyRegistry
from src.utils.run_manifest import RunManifest


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
        self.forensic = ForensicRecorder(Path(self.config.output_dir), config=self.config)
        self.integrity = ForensicIntegrity(self.forensic)
        self.manifest = RunManifest(self.forensic, config=self.config)
        self.third_party_registry = ThirdPartyRegistry(self.forensic, self.config)

        # Evidence preservation (hashing, archive, working copies, contact auto-map) is delegated to a dedicated helper so this orchestrator is not also an archive manager. The helper reads+writes the same config and forensic recorder.
        from .utils.evidence_preserver import EvidencePreserver
        self.evidence = EvidencePreserver(self.config, self.forensic, self.integrity, self.manifest)
        
        # Record session start
        self.forensic.record_action("session_start", "Forensic analysis session initialized")
        self._extracted_data_path = None
        self._analysis_results_path = None

    # ------------------------------------------------------------------
    # Source file integrity
    # ------------------------------------------------------------------

    def _hash_source_files(self):
        """Hash all source files before extraction. Delegates to EvidencePreserver."""
        self.evidence.hash_sources()

    # ------------------------------------------------------------------
    # Source file preservation (forensic archive)
    # ------------------------------------------------------------------

    def _preserve_source_files(self):
        """Archive every configured source file into preserved_sources.zip. Delegates to EvidencePreserver."""
        self.evidence.preserve_sources()

    # ------------------------------------------------------------------
    # Redaction application
    # ------------------------------------------------------------------

    def _apply_redactions_to_messages(self, data: Dict) -> Dict:
        """Return a shallow copy of ``data`` with per-message content rewritten through any active redactions.

        Loads redactions from review_dir/redactions_*.json (session_id matches the review session when available). When no redaction file exists the input is returned unchanged. The raw extracted_data JSON produced earlier in the pipeline is NOT modified — it remains available for challenge in discovery.
        """
        try:
            from .review.redaction_manager import RedactionManager
        except ImportError:
            return data

        session_id = getattr(self, "_review_session_id", None)
        if session_id:
            rm = RedactionManager(session_id=session_id, config=self.config, forensic_recorder=self.forensic)
        else:
            return data

        if not rm._records:
            return data

        new_data = dict(data)
        new_messages = []
        redacted_count = 0
        for msg in data.get("messages", []):
            msg_id = msg.get("message_id")
            if not msg_id:
                new_messages.append(msg)
                continue
            active = rm.active_for(msg_id)
            if not active:
                new_messages.append(msg)
                continue
            copy_msg = dict(msg)
            copy_msg["content"] = rm.apply(msg_id, msg.get("content") or "")
            copy_msg["_redactions_applied"] = [
                {"reason": r["reason"], "authority": r["authority"], "examiner": r["examiner"]}
                for r in active
            ]
            new_messages.append(copy_msg)
            redacted_count += 1

        new_data["messages"] = new_messages
        if redacted_count:
            logger.info(f"\n[*] Applied redactions to {redacted_count} message(s)")
            self.forensic.record_action(
                "redactions_applied_for_rendering",
                f"Redactions applied to {redacted_count} messages prior to reporting",
                {"count": redacted_count},
            )
        return new_data

    # ------------------------------------------------------------------
    # Output signing (detached Ed25519)
    # ------------------------------------------------------------------

    def _sign_artifact(self, path: Path):
        """Sign a final artifact if a signer can be built. Errors are non-fatal."""
        if path is None or not Path(path).is_file():
            return
        try:
            from .utils.signing import Signer
            key_path = getattr(self.config, "examiner_signing_key", None)
            signer = Signer(
                key_path=Path(key_path) if key_path else None,
                run_dir=Path(self.config.output_dir),
            )
            sig, pub = signer.sign_file(Path(path))
            self.forensic.record_action(
                "artifact_signed",
                f"Signed {Path(path).name} ({'ephemeral key' if signer.is_ephemeral else 'configured key'})",
                {"file": str(path), "sig": str(sig), "public_key": str(pub), "ephemeral_key": signer.is_ephemeral},
            )
        except Exception as exc:
            self.forensic.record_action(
                "artifact_sign_skipped",
                f"Could not sign {Path(path).name}: {exc}",
                {"file": str(path), "error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Contact auto-mapping from vCard exports
    # ------------------------------------------------------------------

    def _apply_contact_automapping(self):
        """Merge vCard-derived contacts into config.contact_mappings. Delegates to EvidencePreserver."""
        self.evidence.apply_contact_automapping()

    # ------------------------------------------------------------------
    # Working-copy routing (FRE 1002 — Best Evidence Rule)
    # ------------------------------------------------------------------

    def _route_sources_to_working_copies(self):
        """Copy each source into run_dir/working_copies and repoint the config. Delegates to EvidencePreserver."""
        self.evidence.route_to_working_copies()

    # ------------------------------------------------------------------
    # Attachment preservation (FRE 1002 — Best Evidence Rule)
    # ------------------------------------------------------------------

    def _preserve_attachments(self, extracted_data: Dict):
        """
        Create hash-verified working copies of all attachment files.

        Copies each original attachment to output_dir/attachments/ and updates the message dicts to reference the preserved copy. Deduplicates so the same source file is only copied once even if referenced by multiple messages.
        """
        messages = extracted_data.get('messages', [])
        dest_dir = Path(self.config.output_dir) / "attachments"

        preserved = {}   # {original_path_str: preserved_path}
        preserved_count = 0
        image_count = 0
        missing_count = 0

        IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.heic', '.heif', '.tiff', '.bmp', '.webp'}

        logger.info("\n[*] Preserving attachment files (FRE 1002 — Best Evidence Rule)...")

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
        logger.info(f"    Preserved {preserved_count} attachment files "
              f"({image_count} images, {other_count} other)")
        if missing_count:
            logger.info(f"    WARNING: {missing_count} attachment files not found on disk")

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
        """Phase 1: data extraction. Delegates to src.pipeline.extraction."""
        from .pipeline import extraction
        return extraction.run(self)
    
    def run_analysis_phase(self, data: Dict) -> Dict:
        """Phase 2: automated analysis. Delegates to src.pipeline.analysis."""
        from .pipeline import analysis
        return analysis.run(self, data)

    def run_ai_batch_phase(self, extracted_data: Dict) -> Dict:
        """Phase 3: pre-review AI screening. Delegates to src.pipeline.ai_batch."""
        from .pipeline import ai_batch
        return ai_batch.run(self, extracted_data)

    def run_review_phase(self, analysis_results: Dict, extracted_data: Dict, resume_session_id: str = None) -> Dict:
        """Phase 4: manual review. Delegates to src.pipeline.review."""
        from .pipeline import review
        return review.run(self, analysis_results, extracted_data, resume_session_id)
    
    def run_behavioral_phase(self, extracted_data: Dict, analysis_results: Dict, review_results: Dict) -> Dict:
        """Phase 5: post-review behavioral analysis. Delegates to src.pipeline.behavioral."""
        from .pipeline import behavioral
        return behavioral.run(self, extracted_data, analysis_results, review_results)
    
    def _filter_analysis_by_review(self, analysis: Dict, review: Dict) -> Dict:
        """Filter analysis results to only include human-verified findings.

        Only threats and risk indicators explicitly marked 'relevant' or 'uncertain' during manual review survive into analysis reports. Unreviewed and rejected findings are cleared.

        The forensic all-messages export is NOT affected by this filtering — it uses extracted_data directly and remains a complete, unfiltered record.

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
                logger.info(f"    Filtered {cleared} unverified threats from reports")

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
        """Phase 7: report generation. Delegates to src.pipeline.reporting."""
        from .pipeline import reporting
        return reporting.run(self, data, analysis, review)

    def run_documentation_phase(self, data: Dict, analysis_results: Dict = None, review_decisions: Dict = None) -> Dict:
        """Phase 8: documentation + manifest. Delegates to src.pipeline.documentation."""
        from .pipeline import documentation
        return documentation.run(self, data, analysis_results, review_decisions)
    
    def run_full_analysis(self, resume: bool = False):
        """Run extraction, analysis, AI batch, and review phases (1-4), then stop.

        After review completes, pipeline state is saved and the process exits. Run ``run_finalize()`` (via ``python3 run.py --finalize``) to continue with behavioral analysis, AI summary, reporting, and documentation (Phases 5-8).

        Args:
            resume: If True, skip extraction and analysis by loading saved state from a previous run. Resumes at the review phase.
        """
        logger.info("\n" + "="*80)
        logger.info(" FORENSIC MESSAGE ANALYZER — PHASES 1-4 ")
        logger.info("="*80)
        logger.info(f"Session started: {datetime.now()}")
        logger.info(f"Output directory: {self.config.output_dir}")

        resume_session_id = None

        if resume:
            state = self._load_pipeline_state()
            if state and not state.get("review_complete"):
                ext_path = state.get("extracted_data_path")
                ana_path = state.get("analysis_results_path")
                resume_session_id = state.get("review_session_id")

                if ext_path and ana_path and Path(ext_path).exists() and Path(ana_path).exists():
                    logger.info(f"\n[*] Resuming from saved state ({state.get('timestamp', 'unknown')})")
                    logger.info(f"    Extraction: {Path(ext_path).name}")
                    logger.info(f"    Analysis:   {Path(ana_path).name}")
                    if resume_session_id:
                        logger.info(f"    Review session: {resume_session_id}")

                    with open(ext_path) as f:
                        extracted_data = json.load(f)
                    with open(ana_path) as f:
                        analysis_results = json.load(f)

                    self._extracted_data_path = Path(ext_path)
                    self._analysis_results_path = Path(ana_path)

                    logger.info("\n    Skipping Phases 1-3 (extraction, analysis, AI batch) — already completed.")
                else:
                    logger.info("\n[!] State file found but data files missing. Starting fresh.")
                    resume = False
            else:
                logger.info("\n[!] No resumable state found. Starting fresh.")
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

                # Re-save analysis results now that AI batch data is included, so finalize can load the complete analysis from disk.
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

            logger.info("\n" + "="*80)
            logger.info(" REVIEW COMPLETE — PIPELINE PAUSED ")
            logger.info("="*80)
            logger.info(f"\nRun directory: {self.config.output_dir}")
            logger.info(f"\nTo generate reports, run:")
            logger.info(f"  python3 run.py --finalize \"{self.config.output_dir}\"")
            logger.info(f"\nOr auto-detect the latest run:")
            logger.info(f"  python3 run.py --finalize")

        except Exception as e:
            logger.info(f"\n[ERROR] Workflow failed: {e}")
            import traceback
            traceback.print_exc()
            raise

    def run_finalize(self):
        """Run post-review phases (5-8) using saved pipeline state.

        Loads extraction data, analysis results (including AI batch results), and review decisions from disk. Runs behavioral analysis, AI executive summary, reporting, and documentation.
        """
        logger.info("\n" + "="*80)
        logger.info(" FORENSIC MESSAGE ANALYZER — FINALIZE (POST-REVIEW) ")
        logger.info("="*80)
        logger.info(f"Session started: {datetime.now()}")
        logger.info(f"Output directory: {self.config.output_dir}")

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
        logger.info(f"\n[*] Loading saved pipeline data...")
        logger.info(f"    Extraction: {Path(ext_path).name}")
        logger.info(f"    Analysis:   {Path(ana_path).name}")
        logger.info(f"    Review:     {Path(rev_path).name}")

        with open(ext_path) as f:
            extracted_data = json.load(f)
        with open(ana_path) as f:
            analysis_results = json.load(f)
        with open(rev_path) as f:
            review_results = json.load(f)

        self._extracted_data_path = Path(ext_path)
        self._analysis_results_path = Path(ana_path)

        # Reconstruct enriched DataFrame for Phase 4 behavioral analysis. During the initial run, Phase 2 enriches a DataFrame with threat/sentiment/pattern columns and saves it as self._enriched_df. Since finalize runs in a new process, we must rebuild it from the saved analysis results.
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
                logger.info(f"\n[!] Behavioral analysis failed (non-fatal): {e}")
                analysis_results['behavioral'] = {}

            # Update third-party contact data (screenshots may have added more during analysis)
            extracted_data['third_party_contacts'] = self.third_party_registry.get_all()
            tp_summary = self.third_party_registry.get_summary()
            if tp_summary['total'] > 0:
                logger.info(f"\n[*] Discovered {tp_summary['total']} third-party contacts")
                for src, count in tp_summary['by_source'].items():
                    logger.info(f"    {src}: {count}")

            # Phase 6: Executive Summary (post-review)
            # Batch results already exist from Phase 3 (pre-review). Now generate summary, risks, and recommendations using the summary model, incorporating the actual conversation messages.
            ai_results = analysis_results.get('ai_analysis', {})
            if ai_results and ai_results.get('total_messages', 0) > 0:
                logger.info("\n" + "="*60)
                logger.info("PHASE 6: EXECUTIVE SUMMARY (POST-REVIEW)")
                logger.info("="*60)
                try:
                    from src.analyzers.ai_analyzer import AIAnalyzer
                    from src.utils.pricing import get_pricing
                    ai_analyzer = AIAnalyzer(forensic_recorder=self.forensic, config=self.config)
                    if ai_analyzer.client:
                        # Build message list for the summary using the same contact filter as Phase 3 (AI batch analysis).
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
                            logger.info(
                                f"    {len(summary_messages):,} messages for executive summary "
                                f"(~{est_input:,} input tokens)"
                            )
                            logger.info(
                                f"    Estimated summary cost: ~${est_cost:.4f} "
                                f"({ai_analyzer.summary_model})"
                            )
                            if est_cost > 1.00:
                                logger.info(
                                    f"    Cost exceeds $1.00 — press Ctrl+C within "
                                    f"5 seconds to abort..."
                                )
                                try:
                                    import time as _time
                                    _time.sleep(5)
                                except KeyboardInterrupt:
                                    logger.info("\n    Summary generation aborted by user.")
                                    summary_messages = None

                        if summary_messages is not None:
                            ai_results = ai_analyzer.generate_post_review_summary(
                                ai_results, messages=summary_messages
                            )
                            analysis_results['ai_analysis'] = ai_results
                            logger.info(f"    Executive summary generated")
                        else:
                            logger.info("    Executive summary skipped (user aborted)")
                    else:
                        logger.info("    Executive summary skipped — AI not configured")
                except Exception as e:
                    logger.info(f"    Executive summary error (non-fatal): {e}")
            else:
                logger.info("\n[*] No pre-screening results found — skipping executive summary")

            # Phase 7: Reporting
            reports = self.run_reporting_phase(extracted_data, analysis_results, review_results)

            # Phase 8: Documentation (pass review so the events timeline can show only reviewer-confirmed findings)
            documentation = self.run_documentation_phase(extracted_data, analysis_results, review_results)

            logger.info("\n" + "="*80)
            logger.info(" WORKFLOW COMPLETE ")
            logger.info("="*80)
            logger.info(f"\nAll outputs saved to: {self.config.output_dir}")
            logger.info("\nGenerated files:")
            for report_type, path in reports.items():
                logger.info(f"  - {report_type}: {Path(path).name}")
            for doc_type, path in documentation.items():
                logger.info(f"  - {doc_type}: {Path(path).name}")

            # Clean up pipeline state file after successful completion
            self._clear_pipeline_state()

        except Exception as e:
            logger.info(f"\n[ERROR] Finalize failed: {e}")
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
        logger.info(f"\n[ERROR] Analysis failed: {e}")
        return False


def finalize(config: Config = None):
    """Entry point for the finalize (post-review) phase (Phases 4-7).

    Loads saved pipeline state including review decisions, then runs behavioral analysis, AI analysis, reporting, and documentation.

    Args:
        config: Configuration instance. ``config.output_dir`` must point to the run directory from the original pipeline run.

    Returns:
        bool: True if completed successfully, False otherwise.
    """
    try:
        analyzer = ForensicAnalyzer(config)
        analyzer.run_finalize()
        return True
    except Exception as e:
        logger.info(f"\n[ERROR] Finalize failed: {e}")
        return False