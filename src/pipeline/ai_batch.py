"""Phase 3: pre-review AI screening (Anthropic Claude batch API)."""

from __future__ import annotations

import json
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


def run(analyzer, extracted_data: Dict) -> Dict:
    """Submit mapped-contact messages to Claude for threat and coercive-control classification.

    Does NOT generate the executive summary — that runs post-review in finalize so it can incorporate the reviewer's confirmed decisions. Returns the batch results dict, or {} on skip/error.
    """
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 3: PRE-REVIEW SCREENING")
    logger.info("=" * 60)

    try:
        from ..analyzers.ai_analyzer import AIAnalyzer
        ai_analyzer = AIAnalyzer(forensic_recorder=analyzer.forensic, config=analyzer.config)
        if not ai_analyzer.client:
            logger.info("    Pre-review screening skipped - AI not configured")
            return ai_analyzer._empty_analysis()

        messages = extracted_data.get("messages", [])
        ai_contacts = analyzer.config.ai_contacts
        ai_specified = analyzer.config.ai_contacts_specified
        mapped_messages = [
            m for m in messages
            if m.get("source") != "counseling"
            and m.get("sender") in ai_contacts
            and m.get("recipient") in ai_contacts
            and (
                ai_specified is None
                or m.get("sender") in ai_specified
                or m.get("recipient") in ai_specified
            )
        ]
        skipped = len(messages) - len(mapped_messages)
        if skipped:
            logger.info(f"    Filtered to {len(mapped_messages)} mapped-contact messages (skipped {skipped} unmapped)")

        ai_results = ai_analyzer.analyze_messages(
            mapped_messages,
            batch_size=analyzer.config.batch_size,
            generate_summary=False,
        )
        threat_count = len(ai_results.get("threat_assessment", {}).get("details", []))
        cc_count = len(ai_results.get("coercive_control", {}).get("patterns", []))
        logger.info(f"    AI batch complete - {threat_count} threats, {cc_count} coercive control patterns found")

        analyzer.manifest.add_operation(
            "ai_batch_analysis",
            "success",
            {
                "message_count": len(mapped_messages),
                "threats": threat_count,
                "coercive_control_patterns": cc_count,
            },
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ai_output_file = Path(analyzer.config.output_dir) / f"ai_batch_results_{timestamp}.json"
        with open(ai_output_file, "w") as f:
            json.dump(ai_results, f, indent=2, default=str)
        analyzer._ai_batch_results_path = ai_output_file
        logger.info(f"    AI batch results saved to {ai_output_file.name}")

        return ai_results
    except Exception as e:
        logger.info(f"    AI batch analysis error: {e}")
        traceback.print_exc()
        return {}
