"""Phase 1: data extraction."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict

from ..extractors.data_extractor import DataExtractor
from ..extractors.screenshot_extractor import ScreenshotExtractor
from ..forensic_utils import ForensicIntegrity, ForensicRecorder
from ..utils.run_manifest import RunManifest

logger = logging.getLogger(__name__)


def run(analyzer) -> Dict:
    """Run the data extraction phase against analyzer.config and return the extraction results dict."""
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 1: DATA EXTRACTION")
    logger.info("=" * 60)

    # Ensure we are writing into a run subfolder. If the caller (e.g. direct ForensicAnalyzer usage without run.py) didn't create one, do it now so nothing lands in the base output dir.
    output_dir = Path(analyzer.config.output_dir)
    if not re.search(r"run_\d{8}_\d{6}", output_dir.name):
        run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = output_dir / f"run_{run_ts}"
        run_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"    [!] output_dir was not a run subfolder — created {run_dir.name}")
        analyzer.forensic.record_action(
            "run_folder_created",
            "Auto-created run subfolder (caller did not set one)",
            {"original_output_dir": str(output_dir), "run_dir": str(run_dir)},
        )
        analyzer.config.output_dir = str(run_dir)
        analyzer.forensic = ForensicRecorder(run_dir)
        analyzer.integrity = ForensicIntegrity(analyzer.forensic)
        analyzer.manifest = RunManifest(analyzer.forensic, config=analyzer.config)
        # Re-bind the evidence helper so it uses the refreshed recorder/integrity/manifest.
        from ..utils.evidence_preserver import EvidencePreserver
        analyzer.evidence = EvidencePreserver(analyzer.config, analyzer.forensic, analyzer.integrity, analyzer.manifest)

    analyzer._hash_source_files()
    analyzer._preserve_source_files()
    analyzer._route_sources_to_working_copies()
    analyzer._apply_contact_automapping()

    extractor = DataExtractor(analyzer.forensic, third_party_registry=analyzer.third_party_registry, config=analyzer.config)

    logger.info("\n[*] Extracting message data from all sources...")
    try:
        all_messages = extractor.extract_all()
        logger.info(f"    Extracted {len(all_messages)} total messages")
    except Exception as e:
        logger.info(f"    Error extracting messages: {e}")
        all_messages = []

    if not all_messages:
        logger.info("\n[ABORT] No messages extracted. Cannot proceed with analysis.")
        logger.info("    Check your data sources and contact mappings in .env")
        raise RuntimeError("Extraction produced 0 messages — aborting to avoid wasting API credits")

    logger.info("\n[*] Cataloging screenshots...")
    screenshots = []
    if analyzer.config.screenshot_source_dir:
        try:
            screenshot_extractor = ScreenshotExtractor(analyzer.config.screenshot_source_dir, analyzer.forensic)
            screenshots = screenshot_extractor.extract_screenshots()
            logger.info(f"    Cataloged {len(screenshots)} screenshots")
        except Exception as e:
            logger.info(f"    Error cataloging screenshots: {e}")
    else:
        logger.info("    No screenshot directory configured")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = Path(analyzer.config.output_dir) / f"extracted_data_{timestamp}.json"

    extraction_results = {
        "messages": all_messages,
        "screenshots": screenshots,
        "combined": all_messages,  # legacy alias
        "third_party_contacts": analyzer.third_party_registry.get_all(),
    }

    analyzer._preserve_attachments(extraction_results)

    with open(output_file, "w") as f:
        json.dump(extraction_results, f, indent=2, default=str)

    analyzer._extracted_data_path = output_file
    analyzer.manifest.add_operation(
        "extraction",
        "success",
        {"message_count": len(all_messages), "screenshot_count": len(screenshots)},
    )
    logger.info(f"\n[✓] Extraction complete. Data saved to {output_file}")

    return extraction_results
