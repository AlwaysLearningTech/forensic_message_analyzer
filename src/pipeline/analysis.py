"""Phase 2: automated analysis (threats, sentiment, patterns, screenshots, metrics)."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict

from ..analyzers.communication_metrics import CommunicationMetricsAnalyzer
from ..analyzers.screenshot_analyzer import ScreenshotAnalyzer
from ..analyzers.sentiment_analyzer import SentimentAnalyzer
from ..analyzers.threat_analyzer import ThreatAnalyzer
from ..analyzers.yaml_pattern_analyzer import YamlPatternAnalyzer

logger = logging.getLogger(__name__)


def run(analyzer, data: Dict) -> Dict:
    """Run automated analysis on the extraction results and return a dict of analyzer outputs."""
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 2: AUTOMATED ANALYSIS")
    logger.info("=" * 60)

    results: Dict = {}
    messages = data.get("messages", [])

    if not messages:
        logger.info("\n[!] No message data to analyze")
        return results

    import pandas as pd
    combined_df = pd.DataFrame(messages)

    logger.info(f"\n[*] Analyzing {len(combined_df)} messages")

    logger.info("\n[*] Analyzing threats...")
    threat_analyzer = ThreatAnalyzer(analyzer.forensic)
    threat_results = threat_analyzer.detect_threats(combined_df)
    threat_summary = threat_analyzer.generate_threat_summary(threat_results)
    results["threats"] = {
        "details": threat_results.to_dict("records") if hasattr(threat_results, "to_dict") else threat_results,
        "summary": threat_summary,
    }
    logger.info(f"    Detected threats in {threat_summary.get('messages_with_threats', 0)} messages")

    logger.info("\n[*] Analyzing sentiment...")
    sentiment_analyzer = SentimentAnalyzer(analyzer.forensic)
    sentiment_results = sentiment_analyzer.analyze_sentiment(combined_df)
    results["sentiment"] = sentiment_results.to_dict("records") if hasattr(sentiment_results, "to_dict") else sentiment_results
    logger.info("    Sentiment analysis complete")

    logger.info("\n[*] Running pattern detection...")
    pattern_analyzer = YamlPatternAnalyzer(analyzer.forensic)
    pattern_results = pattern_analyzer.analyze_patterns(combined_df)
    results["patterns"] = pattern_results.to_dict("records") if hasattr(pattern_results, "to_dict") else pattern_results
    logger.info("    Pattern detection complete")

    if data.get("screenshots"):
        logger.info("\n[*] Analyzing screenshots...")
        screenshot_analyzer = ScreenshotAnalyzer(
            analyzer.forensic,
            third_party_registry=analyzer.third_party_registry,
            screenshots_dir=analyzer.config.screenshot_source_dir,
        )
        for screenshot in data["screenshots"]:
            text = screenshot.get("extracted_text", "")
            if text:
                contacts = screenshot_analyzer._extract_contact_info(text, screenshot.get("filename", ""))
                screenshot["contacts_found"] = contacts
        results["screenshots"] = data["screenshots"]
        logger.info(f"    Analyzed {len(data['screenshots'])} screenshots")

    logger.info("\n[*] Calculating communication metrics...")
    metrics_analyzer = CommunicationMetricsAnalyzer(forensic_recorder=analyzer.forensic)
    results["metrics"] = metrics_analyzer.analyze_messages(messages)
    logger.info("    Communication metrics calculated")

    # Save the enriched DataFrame for the behavioral phase (post-review). At this point combined_df carries threat, sentiment, and pattern columns.
    analyzer._enriched_df = combined_df.copy()

    # AI batch analysis runs in Phase 3 (after this phase). Placeholder; populated by run_ai_batch_phase.
    results["ai_analysis"] = {}

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = analyzer.config.analysis_dir() / f"analysis_results_{timestamp}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    analyzer._analysis_results_path = output_file
    analyzer.manifest.add_operation(
        "analysis",
        "success",
        {"message_count": len(messages), "analyzers_run": list(results.keys())},
    )
    logger.info(f"\n[✓] Analysis complete. Results saved to {output_file}")
    return results
