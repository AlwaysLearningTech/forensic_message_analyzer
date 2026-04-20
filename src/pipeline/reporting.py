"""Phase 7: report generation across every output format."""

from __future__ import annotations

import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict

from ..reporters.excel_reporter import ExcelReporter
from ..reporters.forensic_reporter import ForensicReporter
from ..reporters.html_reporter import HtmlReporter
from ..reporters.json_reporter import JSONReporter

logger = logging.getLogger(__name__)


def run(analyzer, data: Dict, analysis: Dict, review: Dict) -> Dict:
    """Render every report format, sign each emitted file, and register them with the manifest."""
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 7: REPORT GENERATION")
    logger.info("=" * 60)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports: Dict[str, str] = {}

    # Apply redactions before any reporter renders content. Raw extracted_data JSON already preserved the unredacted content for discovery-challenge purposes.
    data = analyzer._apply_redactions_to_messages(data)

    logger.info("\n[*] Filtering analysis by review decisions...")
    filtered_analysis = analyzer._filter_analysis_by_review(analysis, review)

    forensic_reporter = ForensicReporter(analyzer.forensic, config=analyzer.config)

    logger.info("\n[*] Generating comprehensive reports...")
    generated_reports = forensic_reporter.generate_comprehensive_report(data, filtered_analysis, review)
    for format_name, path in generated_reports.items():
        reports[format_name] = str(path)
        logger.info(f"    {format_name.upper()} report: {path.name}")

    if "excel" not in reports:
        logger.info("\n[*] Generating Excel report...")
        try:
            excel_reporter = ExcelReporter(analyzer.forensic, config=analyzer.config)
            excel_path = Path(analyzer.config.output_dir) / f"report_{timestamp}.xlsx"
            excel_reporter.generate_report(data.copy(), filtered_analysis, review, excel_path)
            reports["excel"] = str(excel_path)
            logger.info(f"    Saved to {excel_path}")
        except Exception as e:
            logger.info(f"    Error generating Excel report: {e}")
            traceback.print_exc()

    logger.info("\n[*] Generating HTML/PDF report (with inline images)...")
    try:
        html_reporter = HtmlReporter(analyzer.forensic, config=analyzer.config)
        html_base = Path(analyzer.config.output_dir) / f"report_{timestamp}"
        for fmt, path in html_reporter.generate_report(data, filtered_analysis, review, html_base).items():
            reports[fmt] = str(path)
            logger.info(f"    {fmt.upper()} report: {path.name}")
    except Exception as e:
        logger.info(f"    Error generating HTML/PDF report: {e}")
        traceback.print_exc()

    logger.info("\n[*] Generating chat-bubble HTML report...")
    try:
        from ..reporters.chat_reporter import ChatReporter
        chat_reporter = ChatReporter(analyzer.forensic, config=analyzer.config)
        chat_base = Path(analyzer.config.output_dir) / f"report_{timestamp}"
        for fmt, path in chat_reporter.generate_report(data, filtered_analysis, review, chat_base).items():
            reports[fmt] = str(path)
            logger.info(f"    {fmt.upper()} report: {path.name}")
    except Exception as e:
        logger.info(f"    Error generating chat report: {e}")
        traceback.print_exc()

    if "json" not in reports:
        logger.info("\n[*] Generating JSON report...")
        try:
            json_reporter = JSONReporter(analyzer.forensic, config=analyzer.config)
            json_path = Path(analyzer.config.output_dir) / f"report_{timestamp}.json"
            json_reporter.generate_report(data, filtered_analysis, review, json_path)
            reports["json"] = str(json_path)
            logger.info(f"    Saved to {json_path}")
        except Exception as e:
            logger.info(f"    Error generating JSON report: {e}")

    # Sign every report file with a detached Ed25519 signature.
    for _fmt, path in list(reports.items()):
        analyzer._sign_artifact(Path(path))

    legal_text = getattr(forensic_reporter, "_legal_summary_text", None)
    if legal_text:
        logger.info("\n[*] Generating legal team summary document...")
        try:
            summary_path = Path(analyzer.config.output_dir) / f"legal_team_summary_{timestamp}.docx"
            forensic_reporter._generate_legal_summary_docx(legal_text, summary_path, reports)
            reports["legal_summary"] = str(summary_path)
            file_hash = analyzer.forensic.compute_hash(summary_path)
            analyzer.forensic.record_action(
                "legal_summary_generated",
                f"Generated legal team summary with hash {file_hash}",
                {"path": str(summary_path), "hash": file_hash},
            )
            logger.info(f"    Saved to {summary_path.name}")
        except Exception as e:
            logger.info(f"    Error generating legal team summary: {e}")
            traceback.print_exc()

    logger.info("\n[*] Generating READ ME FIRST cover sheet...")
    try:
        cover_path = forensic_reporter.generate_cover_sheet(reports, timestamp)
        reports["cover_sheet"] = str(cover_path)
        logger.info(f"    Saved to {cover_path.name}")
    except Exception as e:
        logger.info(f"    Error generating cover sheet: {e}")
        traceback.print_exc()

    logger.info("\n[✓] Report generation complete")

    analyzer.manifest.add_operation("reporting", "success", {"report_formats": list(reports.keys())})
    for fmt, path in reports.items():
        analyzer.manifest.add_output_file(Path(path), f"{fmt}_report")

    return reports
