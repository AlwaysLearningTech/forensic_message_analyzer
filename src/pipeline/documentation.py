"""Phase 8: chain of custody + timelines + run manifest."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from ..utils.timeline_generator import TimelineGenerator
from ..utils.events_timeline import collect_events, render_events_timeline

logger = logging.getLogger(__name__)


def run(analyzer, data: Dict, analysis_results: Optional[Dict] = None, review_decisions: Optional[Dict] = None) -> Dict:
    """Emit chain of custody, both timelines, and the run manifest for the finalized run."""
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 8: DOCUMENTATION")
    logger.info("=" * 60)

    logger.info("\n[*] Generating chain of custody...")
    chain_path = analyzer.forensic.generate_chain_of_custody()
    if chain_path:
        logger.info(f"    Saved to {chain_path}")
        analyzer._sign_artifact(Path(chain_path))
    else:
        logger.info("    WARNING: Chain of custody generation failed")

    timeline_path = _build_timeline(analyzer, data, analysis_results)
    events_timeline_path = _build_events_timeline(analyzer, data, analysis_results, review_decisions or {})

    logger.info("\n[*] Generating run manifest...")
    manifest_path = analyzer.manifest.generate_manifest()
    logger.info(f"    Saved to {manifest_path}")

    logger.info("\n[✓] Documentation complete")

    result: Dict[str, str] = {}
    if chain_path:
        result["chain_of_custody"] = str(chain_path)
    result["manifest"] = str(manifest_path)
    if timeline_path:
        result["timeline"] = str(timeline_path)
    if events_timeline_path:
        result["events_timeline"] = str(events_timeline_path)
    return result


def _build_events_timeline(analyzer, data: Dict, analysis_results: Optional[Dict], review_decisions: Dict) -> Optional[Path]:
    """Render the sparse, executive-view timeline of confirmed events only."""
    logger.info("\n[*] Generating events timeline (big-picture view)...")
    events = collect_events(data, analysis_results or {}, review_decisions)
    if not events:
        logger.info("    Skipping events timeline — no confirmed events to plot")
        return None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(analyzer.config.output_dir) / f"events_timeline_{timestamp}.html"
    render_events_timeline(
        events,
        out,
        config=analyzer.config,
        case_name=getattr(analyzer.config, "case_name", "") or "",
        case_number=getattr(analyzer.config, "case_number", "") or "",
    )
    analyzer._sign_artifact(out)
    logger.info(f"    Saved {len(events)} events to {out.name}")
    return out


def _build_timeline(analyzer, data: Dict, analysis_results: Optional[Dict]) -> Optional[Path]:
    """Emit an interactive timeline HTML joined with any available threat/sentiment columns."""
    combined_data = data.get("messages", data.get("combined", []))
    if not combined_data:
        logger.info("\n[!] Skipping timeline generation (no message data)")
        return None

    logger.info("\n[*] Generating timeline...")
    timeline_gen = TimelineGenerator(analyzer.forensic, config=analyzer.config)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    timeline_path = Path(analyzer.config.output_dir) / f"timeline_{timestamp}.html"

    import pandas as pd
    df = pd.DataFrame(combined_data) if isinstance(combined_data, list) else combined_data

    if analysis_results:
        threat_details = analysis_results.get("threats", {}).get("details", [])
        if threat_details and isinstance(threat_details, list):
            analysis_df = pd.DataFrame(threat_details)
            analysis_cols = [
                "threat_detected", "threat_categories", "threat_confidence",
                "harmful_content", "sentiment_score", "sentiment_polarity",
                "sentiment_subjectivity", "patterns_detected", "pattern_score",
            ]
            merge_cols = [c for c in analysis_cols if c in analysis_df.columns and c not in df.columns]
            if merge_cols and "message_id" in df.columns and "message_id" in analysis_df.columns:
                df = df.merge(analysis_df[["message_id"] + merge_cols], on="message_id", how="left")
            elif merge_cols and len(analysis_df) == len(df):
                for col in merge_cols:
                    df[col] = analysis_df[col].values

    timeline_gen.create_timeline(df, timeline_path, extracted_data=data)
    logger.info(f"    Saved to {timeline_path}")
    return timeline_path
