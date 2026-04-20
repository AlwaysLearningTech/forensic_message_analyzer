#!/usr/bin/env python3
"""Generate anonymized sample output files for the sample_output/ directory.

Uses fake data with generic names to demonstrate report formatting without
exposing any real case information. Run this after code changes to keep
sample outputs current.

Usage:
    python3 generate_sample_output.py
"""

import json
import os
import sys
import shutil
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))

# Load API key from the same .env the real pipeline uses
_env_path = Path.home() / "workspace" / "data" / "forensic-message-analyzer" / ".env"
if _env_path.exists():
    load_dotenv(_env_path, override=True)

from src.forensic_utils import ForensicRecorder
from src.reporters.forensic_reporter import ForensicReporter
from src.reporters.excel_reporter import ExcelReporter
from src.reporters.html_reporter import HtmlReporter
from src.reporters.json_reporter import JSONReporter


SAMPLE_MESSAGES = [
    {"timestamp": "2025-09-01T08:30:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "Good morning. Can we talk about the schedule for next week?", "source": "imessage", "message_id": "msg-001"},
    {"timestamp": "2025-09-01T08:35:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "Sure, I was going to bring that up too. The kids have soccer practice on Tuesday.", "source": "imessage", "message_id": "msg-002"},
    {"timestamp": "2025-09-01T08:40:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "I know. I already rearranged my work schedule to handle pickup.", "source": "imessage", "message_id": "msg-003"},
    {"timestamp": "2025-09-01T09:00:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "I told you not to change things without telling me first. This is exactly what the counselor warned about.", "source": "imessage", "message_id": "msg-004"},
    {"timestamp": "2025-09-01T09:02:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "I was trying to help. Why does everything have to be a fight?", "source": "imessage", "message_id": "msg-005"},
    {"timestamp": "2025-09-01T09:10:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "Because you never listen. You just do whatever you want.", "source": "imessage", "message_id": "msg-006"},
    {"timestamp": "2025-09-01T09:15:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "That's not true and you know it. Can we please just discuss this calmly?", "source": "imessage", "message_id": "msg-007"},
    {"timestamp": "2025-09-01T09:20:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "Fine. Wednesday works for me to switch. But I need Thursday evening free.", "source": "imessage", "message_id": "msg-008"},
    {"timestamp": "2025-09-02T14:00:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "I just got off the phone with the attorney. We need to finalize the parenting plan by the 15th.", "source": "imessage", "message_id": "msg-009"},
    {"timestamp": "2025-09-02T14:05:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "I already told my attorney the same thing. Let's not drag this out.", "source": "imessage", "message_id": "msg-010"},
    {"timestamp": "2025-09-02T18:30:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "By the way, the school called about Emma's grades. We need to talk about that too.", "source": "imessage", "message_id": "msg-011"},
    {"timestamp": "2025-09-02T18:45:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "Agreed. Can we set up a call with the teacher this week?", "source": "imessage", "message_id": "msg-012"},
    {"timestamp": "2025-09-03T07:00:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "You didn't pick up the kids' lunches from the house. They had nothing to eat.", "source": "imessage", "message_id": "msg-013"},
    {"timestamp": "2025-09-03T07:05:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "I packed their lunches. They're in the blue bag by the door. Did you check?", "source": "imessage", "message_id": "msg-014"},
    {"timestamp": "2025-09-03T07:08:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "Oh. I see it now. Sorry about that.", "source": "imessage", "message_id": "msg-015"},
    {"timestamp": "2025-09-03T10:00:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "No worries. Let's try to communicate better about these things.", "source": "imessage", "message_id": "msg-016"},
    {"timestamp": "2025-09-04T16:00:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "I'm keeping the kids this weekend. I don't care what the schedule says.", "source": "imessage", "message_id": "msg-017"},
    {"timestamp": "2025-09-04T16:05:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "That's not how this works. We have an agreement and I expect it to be followed.", "source": "imessage", "message_id": "msg-018"},
    {"timestamp": "2025-09-04T16:10:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "You'll regret pushing me on this. I'm done being reasonable.", "source": "imessage", "message_id": "msg-019"},
    {"timestamp": "2025-09-04T16:15:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "Please don't make threats. I'm documenting everything for our attorneys.", "source": "imessage", "message_id": "msg-020"},
    {"timestamp": "2025-09-05T09:00:00", "sender": "Jordan Rivera", "recipient": "Alex Morgan", "content": "I spoke with my counselor. I'm sorry about yesterday. Can we reset?", "source": "imessage", "message_id": "msg-021"},
    {"timestamp": "2025-09-05T09:30:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "I appreciate that. Yes, let's focus on what's best for the kids.", "source": "imessage", "message_id": "msg-022"},
    {"timestamp": "2025-09-06T11:00:00", "sender": "taylor.chen@example.com", "recipient": "alex.morgan@example.com", "content": "Hi Alex, following up on the parenting plan draft. Please review the attached and send any changes by Friday.", "source": "email", "message_id": "msg-023"},
    {"timestamp": "2025-09-06T14:00:00", "sender": "alex.morgan@example.com", "recipient": "taylor.chen@example.com", "content": "Thanks Taylor. I've reviewed the draft and have a few edits on section 3 regarding holidays. Sending marked-up version now.", "source": "email", "message_id": "msg-024"},
    {"timestamp": "2025-09-07T08:00:00", "sender": "Alex Morgan", "recipient": "Jordan Rivera", "content": "I emailed the updated parenting plan to both attorneys. Please review it today.", "source": "imessage", "message_id": "msg-025"},
]


def build_mock_config(output_dir: str):
    config = MagicMock()
    config.output_dir = output_dir
    config.ai_api_key = os.getenv('AI_API_KEY')
    config.ai_endpoint = None
    config.ai_batch_model = "claude-haiku-4-5"
    config.ai_summary_model = "claude-sonnet-4-5"
    config.batch_size = 50
    config.use_batch_api = True
    config.max_tokens_per_request = 4096
    config.tokens_per_minute = 25000
    config.max_requests_per_minute = 40
    config.person1_name = "Alex Morgan"
    config.contact_mappings = {"Alex Morgan": ["alex.morgan@example.com"], "Jordan Rivera": ["jordan.rivera@example.com"]}
    config.ai_contacts = {"Alex Morgan", "Jordan Rivera"}
    config.ai_contacts_specified = None
    config.case_name = "In re Morgan/Rivera"
    config.case_number = "SAMPLE-2025-001"
    config.case_numbers = ["SAMPLE-2025-001"]
    config.examiner_name = "Sample Examiner"
    config.organization = "Forensic Analysis Services"
    config.timezone = "America/Los_Angeles"
    config.enable_sentiment = True
    config.enable_image_analysis = True
    config.enable_ocr = True
    config.messages_db_path = "/sample/chat.db"
    config.whatsapp_source_dir = None
    config.email_source_dir = "/sample/email"
    config.teams_source_dir = None
    config.screenshot_source_dir = None
    config.counseling_source_dir = None
    config.counseling_correlation_window_hours = 48
    config.start_date = None
    config.end_date = None
    config.review_dir = str(Path(output_dir) / "review")
    return config


def build_analysis_results(messages):
    """Run the real non-AI analyzers on sample data and assemble results."""
    import pandas as pd
    from src.analyzers.threat_analyzer import ThreatAnalyzer
    from src.analyzers.sentiment_analyzer import SentimentAnalyzer

    recorder = ForensicRecorder(output_dir=Path("/tmp/fma_sample_scratch"))
    Path("/tmp/fma_sample_scratch").mkdir(exist_ok=True)

    df = pd.DataFrame(messages)

    ta = ThreatAnalyzer(recorder)
    threat_results = ta.detect_threats(df)
    threat_summary = ta.generate_threat_summary(threat_results)

    sa = SentimentAnalyzer(recorder)
    sentiment_results = sa.analyze_sentiment(df)

    ai_analysis = {
        "generated_at": datetime.now().isoformat(),
        "total_messages": len(messages),
        "conversation_summary": "Analysis of 25 messages between Alex Morgan and Jordan Rivera spanning September 1-7, 2025 reveals a co-parenting relationship under significant strain. Communications center on scheduling disputes, parenting plan logistics, and school-related issues. The majority of messages are logistical in nature, though several exchanges escalate into conflict.",
        "sentiment_analysis": {
            "overall": "mixed",
            "shifts": [
                {"from": "neutral", "to": "hostile", "approximate_position": "early September 4"},
                {"from": "hostile", "to": "conciliatory", "approximate_position": "September 5"},
            ],
        },
        "threat_assessment": {
            "found": True,
            "severity": "moderate",
            "details": [
                {"type": "veiled_threat", "quote": "You'll regret pushing me on this", "context": "Custody schedule dispute"},
            ],
        },
        "behavioral_patterns": {
            "escalation_cycles": "Pattern of conflict followed by apology detected across multiple exchanges.",
        },
        "risk_indicators": [
            {"severity": "moderate", "indicator": "Veiled threat during custody dispute: 'You'll regret pushing me on this'", "recommended_action": "Document and share with legal counsel"},
            {"severity": "low", "indicator": "Unilateral schedule change attempted without court approval", "recommended_action": "Note for parenting plan enforcement discussion"},
            {"severity": "informational", "indicator": "Pattern of escalation followed by counselor-mediated de-escalation", "recommended_action": "Consider in context of behavioral assessment"},
        ],
        "notable_quotes": [
            {"quote": "You'll regret pushing me on this. I'm done being reasonable.", "significance": "Veiled threat made during heated custody dispute on September 4"},
            {"quote": "I spoke with my counselor. I'm sorry about yesterday. Can we reset?", "significance": "De-escalation following threat, suggests awareness of concerning behavior"},
        ],
        "recommendations": [
            "Document the September 4 exchange for the legal team as potential evidence of intimidation.",
            "Monitor for future unilateral custody schedule changes as a pattern of non-compliance.",
            "Note the constructive communication patterns (September 5 apology, September 3 resolution) as evidence of capacity for co-parenting when supported.",
        ],
        "key_topics": ["custody scheduling", "parenting plan", "school concerns", "attorney communications"],
        "processing_stats": {"batches_processed": 1, "tokens_used": 3200, "input_tokens": 2400, "output_tokens": 800, "api_calls": 1, "errors": [], "estimated_cost_usd": 0.029},
    }

    return {
        "threats": {
            "details": threat_results.to_dict("records") if hasattr(threat_results, "to_dict") else threat_results,
            "summary": threat_summary,
        },
        "sentiment": sentiment_results.to_dict("records") if hasattr(sentiment_results, "to_dict") else sentiment_results,
        "patterns": [],
        "metrics": {},
        "ai_analysis": ai_analysis,
    }


def build_review_decisions(analysis_results):
    """Simulate manual review decisions."""
    from src.review.manual_review_manager import ManualReviewManager
    import tempfile

    review_dir = Path(tempfile.mkdtemp(prefix="fma_sample_review_"))
    recorder = ForensicRecorder(output_dir=review_dir)
    manager = ManualReviewManager(review_dir=review_dir, forensic_recorder=recorder)

    threat_details = analysis_results["threats"]["details"]
    idx = 0
    if isinstance(threat_details, list):
        for i, item in enumerate(threat_details):
            if item.get("threat_detected"):
                decision = ["relevant", "not_relevant", "uncertain"][idx % 3]
                manager.add_review(f"threat_{i}", "threat", decision, notes="sample review")
                idx += 1

    ai_threats = analysis_results["ai_analysis"].get("threat_assessment", {})
    if ai_threats.get("found"):
        for i, detail in enumerate(ai_threats.get("details", [])):
            manager.add_review(f"ai_threat_{i}", "ai_threat", "relevant", notes="sample review")

    return {
        "total_reviewed": len(manager.reviews),
        "relevant": len(manager.get_reviews_by_decision("relevant")),
        "not_relevant": len(manager.get_reviews_by_decision("not_relevant")),
        "uncertain": len(manager.get_reviews_by_decision("uncertain")),
        "reviews": manager.reviews,
    }


def main():
    output_dir = Path(__file__).parent / "sample_output"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir()

    config = build_mock_config(str(output_dir))
    messages = SAMPLE_MESSAGES
    extracted_data = json.loads(json.dumps({"messages": messages, "screenshots": [], "combined": messages, "third_party_contacts": [{"identifier": "taylor.chen@example.com", "display_name": "Taylor Chen", "sources": ["email"]}]}, default=str))

    print("Building analysis results...")
    analysis_results = build_analysis_results(messages)

    print("Simulating manual review...")
    review_decisions = build_review_decisions(analysis_results)
    print(f"  {review_decisions['total_reviewed']} items reviewed: {review_decisions['relevant']} relevant, {review_decisions['not_relevant']} not relevant, {review_decisions['uncertain']} uncertain")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    recorder = ForensicRecorder(output_dir=output_dir)

    # Forensic reports (Word, PDF, JSON)
    print("Generating forensic reports (Word/PDF/JSON)...")
    fr = ForensicReporter(recorder, config=config)
    fr_reports = fr.generate_comprehensive_report(extracted_data, analysis_results, review_decisions)
    for fmt, path in fr_reports.items():
        print(f"  {fmt}: {Path(path).name}")

    # Excel report
    print("Generating Excel report...")
    excel_reporter = ExcelReporter(recorder, config=config)
    excel_path = output_dir / f"report_{timestamp}.xlsx"
    excel_reporter.generate_report(extracted_data, analysis_results, review_decisions, excel_path)
    print(f"  excel: {excel_path.name}")

    # HTML report (with PDF)
    print("Generating HTML + HTML-PDF report...")
    html_reporter = HtmlReporter(recorder, config=config)
    html_base = output_dir / f"report_{timestamp}"
    # pdf=True requires WeasyPrint; fall back to HTML-only when weasyprint can't load system libs on the sample environment.
    try:
        html_paths = html_reporter.generate_report(extracted_data, analysis_results, review_decisions, html_base, pdf=True)
    except Exception as exc:
        print(f"  (HTML-PDF render failed: {exc}; emitting HTML only)")
        html_paths = html_reporter.generate_report(extracted_data, analysis_results, review_decisions, html_base, pdf=False)
    for fmt, path in html_paths.items():
        print(f"  {fmt}: {Path(path).name}")

    # Chat-bubble HTML report — iMessage-style transcript
    print("Generating chat-bubble HTML report...")
    from src.reporters.chat_reporter import ChatReporter
    chat_reporter = ChatReporter(recorder, config=config)
    chat_base = output_dir / f"report_{timestamp}"
    chat_paths = chat_reporter.generate_report(extracted_data, analysis_results, review_decisions, chat_base)
    for fmt, path in chat_paths.items():
        print(f"  {fmt}: {Path(path).name}")

    # JSON analysis report
    print("Generating JSON analysis report...")
    json_reporter = JSONReporter(recorder, config=config)
    json_path = output_dir / f"report_{timestamp}.json"
    json_reporter.generate_report(extracted_data, analysis_results, review_decisions, json_path)
    print(f"  json: {json_path.name}")

    # All-messages CSV + XLSX — unedited forensic export (usually built inside ForensicReporter; emit a faithful stand-in here so the sample reflects the same files a real run produces)
    print("Generating all-messages export (CSV + XLSX)...")
    import pandas as pd
    all_msgs_df = pd.DataFrame(messages)
    csv_path = output_dir / f"all_messages_{timestamp}.csv"
    xlsx_path = output_dir / f"all_messages_{timestamp}.xlsx"
    all_msgs_df.to_csv(csv_path, index=False)
    all_msgs_df.to_excel(xlsx_path, index=False, sheet_name="All Messages")
    print(f"  all_messages.csv: {csv_path.name}")
    print(f"  all_messages.xlsx: {xlsx_path.name}")

    # Build the bundled reports dict the cover-sheet + legal summary need. Include what we've produced so each entry's filename is accurate.
    bundle = {
        "excel": str(excel_path),
        "word": str(fr_reports.get("word")) if fr_reports.get("word") else None,
        "methodology": str(fr_reports.get("methodology")) if fr_reports.get("methodology") else None,
        "methodology_pdf": str(fr_reports.get("methodology_pdf")) if fr_reports.get("methodology_pdf") else None,
        "pdf": str(fr_reports.get("pdf")) if fr_reports.get("pdf") else None,
        "json": str(json_path),
        "chat": str(chat_paths.get("chat")) if chat_paths.get("chat") else None,
        "chat_html": str(chat_paths.get("chat_html")) if chat_paths.get("chat_html") else None,
        **{k: str(v) for k, v in html_paths.items()},
    }
    bundle = {k: v for k, v in bundle.items() if v}

    # Legal team summary (DOCX + PDF). Skip gracefully if no AI-generated narrative is present in the sample analysis.
    sample_legal_text = (
        "## Overview\n\n"
        "This sample run covers 25 messages between Alex Morgan and Jordan Rivera over seven days in September 2025. "
        "The conversation shows a repeating arc: routine scheduling talk that escalates into a dispute, produces one "
        "veiled threat on September 4, and then de-escalates through counselor-mediated apology by September 5.\n\n"
        "## Key findings\n\n"
        "- **Confirmed threat (September 4):** 'You'll regret pushing me on this. I'm done being reasonable.' Flagged "
        "by the AI-screening pass and confirmed during manual review. Severity marked moderate; no explicit reference "
        "to weapons or location.\n"
        "- **Unilateral schedule change attempted** on September 4 — 'I'm keeping the kids this weekend. I don't care "
        "what the schedule says.' Pattern-matched under custody_interference; confirmed during review.\n"
        "- **De-escalation (September 5):** 'I spoke with my counselor. I'm sorry about yesterday. Can we reset?' "
        "Notable for its direct acknowledgment of the prior day's conduct.\n\n"
        "## Recommended next steps\n\n"
        "- Document the September 4 exchange for the legal team as potential evidence of intimidation.\n"
        "- Monitor for future unilateral schedule changes as a pattern of non-compliance.\n"
        "- Note the constructive patterns (Sep 5 apology, Sep 3 resolution) as evidence of capacity for "
        "co-parenting when supported."
    )
    print("Generating legal team summary (DOCX + PDF)...")
    legal_docx = output_dir / f"legal_team_summary_{timestamp}.docx"
    legal_pdf = output_dir / f"legal_team_summary_{timestamp}.pdf"
    fr._generate_legal_summary_docx(sample_legal_text, legal_docx, bundle)
    fr._generate_legal_summary_pdf(sample_legal_text, legal_pdf, bundle)
    print(f"  legal_summary.docx: {legal_docx.name}")
    print(f"  legal_summary.pdf:  {legal_pdf.name}")
    bundle["legal_summary"] = str(legal_docx)
    bundle["legal_summary_pdf"] = str(legal_pdf)

    # Examiner-authored manual event — illustrate the timeline UI's output. A real reviewer enters these in the web UI; here we synthesize one so the sample reflects what a real run looks like after the examiner names the key incidents.
    print("Synthesizing one examiner-authored event for the sample...")
    from src.review.event_manager import EventManager
    em = EventManager(session_id=f"sample_{timestamp}", config=config, forensic_recorder=recorder)
    em.add_event(
        title="September 4 custody dispute",
        start_message_id="msg-017",
        end_message_id="msg-020",
        category="incident",
        severity="high",
        description=(
            "Three-message arc on September 4: Jordan declares an unilateral schedule change, Alex pushes back, "
            "Jordan issues a veiled threat ('You'll regret pushing me on this'). Named by the examiner because "
            "these four messages function as a single incident."
        ),
        start_timestamp=next((m["timestamp"] for m in messages if m.get("message_id") == "msg-017"), None),
        end_timestamp=next((m["timestamp"] for m in messages if m.get("message_id") == "msg-020"), None),
        examiner=config.examiner_name,
    )
    manual_events = em.active_events()

    # Events timeline — the court-facing chronology of reviewer-confirmed turning points.
    print("Generating events timeline (big-picture view)...")
    from src.utils.events_timeline import collect_events, render_events_timeline
    events = collect_events(extracted_data, analysis_results, review_decisions, manual_events=manual_events)
    events_path = output_dir / f"events_timeline_{timestamp}.html"
    render_events_timeline(
        events,
        events_path,
        config=config,
        case_name=config.case_name,
        case_number=config.case_number,
    )
    print(f"  events_timeline: {events_path.name} ({len(events)} events)")
    bundle["events_timeline"] = str(events_path)

    # Detailed minute-level timeline (analyst drill-down). Present in real runs; mirrored here for parity.
    print("Generating detailed minute-level timeline...")
    import pandas as pd  # already imported above; harmless re-import
    from src.utils.timeline_generator import TimelineGenerator
    timeline_path = output_dir / f"timeline_{timestamp}.html"
    timeline_df = pd.DataFrame(messages)
    threat_details = analysis_results["threats"]["details"]
    if isinstance(threat_details, list) and threat_details:
        threats_df = pd.DataFrame(threat_details)
        merge_cols = [c for c in ("threat_detected", "threat_categories", "threat_confidence") if c in threats_df.columns and c not in timeline_df.columns]
        if merge_cols and "message_id" in timeline_df.columns and "message_id" in threats_df.columns:
            timeline_df = timeline_df.merge(threats_df[["message_id"] + merge_cols], on="message_id", how="left")
    TimelineGenerator(recorder, config=config).create_timeline(timeline_df, timeline_path, extracted_data=extracted_data)
    print(f"  timeline: {timeline_path.name}")
    bundle["timeline"] = str(timeline_path)

    # READ ME FIRST cover sheet (DOCX + PDF). Generated last so it can point at every other file in the bundle.
    print("Generating READ ME FIRST cover sheet (DOCX + PDF)...")
    cover = fr.generate_cover_sheet(bundle, timestamp)
    print(f"  cover_sheet.docx: {cover['docx'].name}")
    print(f"  cover_sheet.pdf:  {cover['pdf'].name}")

    # Chain of custody — near the end so it captures every prior action
    print("Generating chain of custody...")
    chain_path = recorder.generate_chain_of_custody()
    print(f"  chain: {Path(chain_path).name}")

    # Run manifest — uses a real Config() here (not the MagicMock) so the snapshot + pattern-hash structure matches what a real run emits. The mock elsewhere is fine because reporters only read specific attributes; RunManifest.snapshot() walks the full Config object.
    print("Generating run manifest...")
    from src.utils.run_manifest import RunManifest
    manifest = RunManifest(recorder, config=None)
    manifest.manifest_data["config_snapshot"] = {
        "ai": {"batch_model": config.ai_batch_model, "summary_model": config.ai_summary_model, "use_batch_api": True, "api_key": "<redacted>"},
        "case": {"case_numbers": config.case_numbers, "case_names": [config.case_name], "examiner_name": config.examiner_name, "organization": config.organization, "timezone": config.timezone},
        "persons": {"person1_name": config.person1_name, "contact_mappings": config.contact_mappings},
        "sources": {"messages_db_path": config.messages_db_path, "email_source_dir": config.email_source_dir},
    }
    manifest.add_operation("sample_extraction", "success", {"message_count": len(messages)})
    manifest_path = manifest.generate_manifest(output_path=output_dir / f"run_manifest_{timestamp}.json")
    print(f"  manifest: {manifest_path.name}")

    # Sign every emitted artifact so the sample folder mirrors a real run's .sig + .sig.pub pattern.
    print("Signing artifacts with per-run ephemeral Ed25519 key...")
    from src.utils.signing import Signer
    signer = Signer(run_dir=output_dir)
    artifacts_to_sign = [
        Path(p) for p in [
            *bundle.values(),
            chain_path,
            manifest_path,
            cover["docx"], cover["pdf"],
            csv_path, xlsx_path,
            excel_path,
        ]
    ]
    # De-dup before signing so we don't double-sign files shared across bundles.
    seen = set()
    for artifact in artifacts_to_sign:
        artifact = Path(artifact)
        if not artifact.is_file() or str(artifact) in seen:
            continue
        seen.add(str(artifact))
        try:
            signer.sign_file(artifact)
        except Exception as exc:
            print(f"  sign failed for {artifact.name}: {exc}")
    print(f"  signed {len(seen)} artifact(s); public key in keys/examiner_ed25519.pem")

    # Clean up scratch dir
    shutil.rmtree("/tmp/fma_sample_scratch", ignore_errors=True)

    print(f"\nDone. Sample output in: {output_dir}/")
    print("All data is anonymized — no real names, case numbers, or identifying information.")


if __name__ == "__main__":
    main()
