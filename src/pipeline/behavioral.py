"""Phase 5: post-review behavioral analysis."""

from __future__ import annotations

import logging
from typing import Dict

from ..analyzers.behavioral_analyzer import BehavioralAnalyzer

logger = logging.getLogger(__name__)


def run(analyzer, extracted_data: Dict, analysis_results: Dict, review_results: Dict) -> Dict:
    """Run behavioral analysis on review-filtered data.

    Consumes the enriched DataFrame produced in Phase 2 (threat + sentiment + pattern columns) and clears any threat annotations that did not survive manual review, so conversation-level behavioral trends are built on confirmed findings only.
    """
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 5: BEHAVIORAL ANALYSIS (POST-REVIEW)")
    logger.info("=" * 60)

    import pandas as pd

    enriched_df = getattr(analyzer, "_enriched_df", None)

    if enriched_df is None or enriched_df.empty:
        messages = extracted_data.get("messages", [])
        if not messages:
            logger.info("\n[!] No message data to analyze")
            return {}
        enriched_df = pd.DataFrame(messages)
        logger.info("    Note: Using raw messages (enriched DataFrame not available)")

    approved_ids = set()
    for r in review_results.get("reviews", []):
        if r.get("decision") in ("relevant", "uncertain"):
            approved_ids.add(r.get("item_id", ""))

    cleared_count = 0
    if "threat_detected" in enriched_df.columns:
        for idx in enriched_df.index:
            if enriched_df.at[idx, "threat_detected"]:
                item_id = f"threat_{idx}"
                if item_id not in approved_ids:
                    enriched_df.at[idx, "threat_detected"] = False
                    enriched_df.at[idx, "threat_categories"] = ""
                    enriched_df.at[idx, "threat_confidence"] = 0
                    enriched_df.at[idx, "harmful_content"] = False
                    cleared_count += 1

    confirmed_threats = int(enriched_df["threat_detected"].sum()) if "threat_detected" in enriched_df.columns else 0
    has_sentiment = "sentiment_score" in enriched_df.columns

    if cleared_count:
        logger.info(f"\n[*] Cleared {cleared_count} unconfirmed threats from behavioral input")
    logger.info(
        f"[*] Behavioral analysis: {len(enriched_df)} messages, "
        f"{confirmed_threats} confirmed threats, "
        f"sentiment data: {'yes' if has_sentiment else 'no'}"
    )

    behavioral_analyzer = BehavioralAnalyzer(analyzer.forensic)
    behavioral_results = behavioral_analyzer.analyze_patterns(enriched_df)

    logger.info("    Behavioral analysis complete")
    return behavioral_results
