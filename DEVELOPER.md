# Developer Guide — Forensic Message Analyzer

This file documents the public Python API of the analyzer, intended for
developers who want to embed the analyzer in another tool, write a custom
extractor or reporter, or run individual phases manually.

End-users should consult [`README.md`](README.md) instead — they don't need
this file to run the analyzer.

> **Authoritative source.** The actual function signatures and method names
> live in `src/`. If anything in this guide disagrees with the source, the
> source wins. Re-read the source before relying on a signature in production
> integrations. The `.github/copilot-instructions.md` file in this repository
> tracks every signature in detail and is regenerated whenever signatures
> change.

## Table of Contents
- [Quick Example](#quick-example)
- [Forensic Utilities](#forensic-utilities)
- [Extractors](#extractors)
- [Analyzers](#analyzers)
- [Reporters](#reporters)
- [Review](#review)
- [Utilities](#utilities)
- [Data Flow](#data-flow)

## Quick Example

```python
from src.forensic_utils import ForensicRecorder, ForensicIntegrity
from src.extractors.imessage_extractor import IMessageExtractor
from src.extractors.whatsapp_extractor import WhatsAppExtractor
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.analyzers.sentiment_analyzer import SentimentAnalyzer
from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
from src.reporters.forensic_reporter import ForensicReporter
from src.config import Config
from pathlib import Path
import pandas as pd

# Initialize configuration and forensic tracking
config = Config()
recorder = ForensicRecorder(Path(config.output_dir))
integrity = ForensicIntegrity(recorder)

# Extract iMessages
imessage_extractor = IMessageExtractor(
    config.messages_db_path, recorder, integrity
)
imessages = imessage_extractor.extract_messages()  # list of dicts

# Extract WhatsApp
whatsapp_extractor = WhatsAppExtractor(
    config.whatsapp_source_dir, recorder, integrity
)
whatsapp_messages = whatsapp_extractor.extract_all()

# Combine into DataFrame
combined_df = pd.DataFrame(imessages + whatsapp_messages)

# Analyze for threats
threat_analyzer = ThreatAnalyzer(recorder)
threats_df = threat_analyzer.detect_threats(combined_df)
threat_summary = threat_analyzer.generate_threat_summary(threats_df)

# Sentiment
sentiment_analyzer = SentimentAnalyzer(recorder)
sentiment_df = sentiment_analyzer.analyze_sentiment(threats_df)

# Behavioural patterns
behavioral_analyzer = BehavioralAnalyzer(recorder)
behavior_results = behavioral_analyzer.analyze_patterns(sentiment_df)

# Reports (filtered to mapped persons from .env)
reporter = ForensicReporter(recorder)
reports = reporter.generate_comprehensive_report(
    extracted_data={'messages': imessages + whatsapp_messages, 'screenshots': []},
    analysis_results={
        'threats': threat_summary,
        'sentiment': sentiment_df.to_dict('records'),
    },
    review_decisions={},
)
```

## Forensic Utilities

### `ForensicRecorder(output_dir=None)`
Records every action with timestamps and SHA-256 hashes.

- `record_action(action, details, metadata=None)` — log a forensic action.
- `compute_hash(file_path)` — SHA-256 of a file (takes a `Path`).
- `generate_chain_of_custody(output_file=None)` — write the chain-of-custody
  JSON; returns the path string.
- `verify_integrity(file_path, expected_hash)` — verify a stored hash.
- `record_file_state(file_path, operation)` — record file open/close events.

### `ForensicIntegrity(forensic_recorder=None)`
Evidence-handling guarantees on top of `ForensicRecorder`.

- `verify_read_only(file_path)` — confirm the source path will not be
  modified by the run.
- `create_working_copy(source_path, dest_dir=None)` — produce a hashed
  working copy.
- `validate_extraction(source_path, extracted_data)` — sanity-check the
  extracted record set against the source.

## Extractors

### `IMessageExtractor(db_path, forensic_recorder, forensic_integrity, config=None)`
- `extract_messages()` — full extraction including `attributedBody`
  decoding, edit history (iOS 16+), deleted-message recovery, URL previews,
  shared locations, per-chat properties, and forensic timestamps.

### `WhatsAppExtractor(export_dir, forensic_recorder, forensic_integrity)`
- `extract_all()` — auto-extracts ZIP archives and parses chat exports.

### `EmailExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)`
- `extract_all()` — parses `.eml` and `.mbox` with full MIME header
  extraction.

### `TeamsExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)`
- `extract_all()` — parses Microsoft Teams personal export TAR archives.

### `ScreenshotExtractor(screenshot_dir, forensic_recorder)`
- `extract_screenshots()` — catalogues image files for OCR.

### `DataExtractor(forensic_recorder, third_party_registry=None)`
Top-level orchestrator that constructs each individual extractor based on
configured paths.
- `extract_all(start_date=None, end_date=None)` — returns a single
  combined list of message dicts. Optional date filters narrow the result.
- `validate_extraction(messages)` — returns a stats dict.

## Analyzers

All analyzers accept a `ForensicRecorder` so their actions are logged to
the same chain of custody as extraction.

### `ThreatAnalyzer(forensic)`
- `detect_threats(df)` — adds `threat_detected`, `threat_categories`,
  `threat_confidence` columns to the DataFrame.
- `generate_threat_summary(df)` — returns a summary dict.

### `SentimentAnalyzer(forensic)`
- `analyze_sentiment(df)` — adds `sentiment_score`, `sentiment_polarity`,
  `sentiment_subjectivity` columns.
- `generate_sentiment_summary(df)` — returns a summary dict.

### `BehavioralAnalyzer(forensic)`
- `analyze_patterns(df)` — returns a behavioural patterns dict.

### `YamlPatternAnalyzer(forensic, patterns_file=None)`
Pattern matcher driven by `patterns/analysis_patterns.yaml`. Each pattern
in the YAML carries a `citation` field pointing at the empirical literature
that justifies inclusion (Stark 2007, Sweet 2019, etc.).
- `analyze_patterns(df)` — adds `patterns_detected` and `pattern_score`.
- `analyze_communication_frequency(df)` — returns a metrics dict.

### `CommunicationMetricsAnalyzer(forensic_recorder=None)`
- `analyze_messages(messages)` — takes a **list** of message dicts (not a
  DataFrame); returns a metrics dict.

### `AIAnalyzer(forensic_recorder=None, config=None)`
Anthropic Claude integration — batch API plus prompt caching.
- `analyze_messages(messages, batch_size=50)` — full batch pipeline.
- `analyze_single_message(message)` — single-message threat assessment for
  real-time / interactive use.

The two-model setup is governed by `AI_BATCH_MODEL` (per-message
classification, cheap model) and `AI_SUMMARY_MODEL` (executive narrative,
higher quality). The legacy single `AI_MODEL` env var was removed in v4.4.0.

### `ScreenshotAnalyzer(forensic, third_party_registry=None)`
- `analyze_screenshots()` — OCRs every screenshot in the configured
  directory; takes no arguments.

### `AttachmentProcessor(forensic)`
- `process_attachments(attachment_dir=None)` — takes an optional `Path`,
  returns a stats dict.

## Reporters

### `ExcelReporter(forensic_recorder, config=None)`
- `generate_report(extracted_data, analysis_results, review_decisions, output_path)` —
  multi-sheet Excel: Overview, Findings Summary, Timeline,
  per-person sheets, Conversation Threads, Manual Review, Third Party Contacts.

### `HtmlReporter(forensic_recorder, config=None)`
- `generate_report(..., pdf=True)` — HTML with inline base64 attachments,
  per-person tables, conversation threads, risk indicators, and three
  legal appendices (Methodology, Completeness Validation, Limitations).
  Optionally renders PDF via WeasyPrint.

### `ChatReporter(forensic_recorder, config=None)`
- `generate_report(...)` — iMessage-style chat-bubble HTML with edit
  history, deleted-message badges, URL preview blocks, and shared
  location blocks.

### `ForensicReporter(forensic_recorder, config=None)`
- `generate_comprehensive_report(extracted_data, analysis_results, review_decisions)` —
  produces Word + PDF + JSON + a standalone Methodology document
  (`methodology_<timestamp>.docx`) and a legal-team summary `.docx`. The
  Methodology document is independent of the findings report so the legal
  team can review the methodology in isolation.

### `JSONReporter(forensic_recorder, config=None)`
- `generate_report(...)` — raw JSON of the analysis output.

## Review

### `ManualReviewManager(review_dir=None)`
- `add_review(item_id, item_type, decision, notes="")` — record a review
  decision. Decisions are persisted to disk immediately so reviews survive
  process termination.
- `get_reviews_by_decision(decision)`, `get_reviews_by_type(item_type)`,
  `get_review_summary()`, `load_reviews(session_id)`.

### `InteractiveReview(review_manager)`
- CLI-based message review.

### `WebReview(review_manager, forensic_recorder=None)`
- Flask-based web review interface. Uses a `threading.Event` for shutdown
  rather than killing the parent process when the user clicks "Complete
  Review".

## Utilities

### `TimelineGenerator(forensic)`
- `create_timeline(df, output_path, raw_messages=None, extracted_data=None)` —
  HTML timeline with case chronology. When `extracted_data` is provided,
  email events are included alongside flagged events. Mapped-person emails
  render as "email"; emails involving unmapped third parties (counsellors,
  attorneys, family) render as "third-party-email".
- `generate_html_timeline(df, raw_messages=None, extracted_data=None)`.

### `ConversationThreader(default_gap_hours=2.0)`
Used by `TimelineGenerator` to group related messages into threads.

### `ThirdPartyRegistry(forensic_recorder, config=None)`
- `register(identifier, display_name, source, context)` — register an
  unmapped contact discovered during extraction.
- `get_all()`, `summary()`.

### `RunManifest(forensic_recorder=None)`
- `add_input_file(path)`, `add_output_file(path)`, `add_operation(...)`,
  `add_extraction_summary(...)`, `add_analysis_summary(...)`,
  `add_report_summary(...)`.
- `generate_manifest(output_path=None)` — returns the `Path` of the
  written manifest. Files must exist on disk to be included.

### `LegalComplianceManager(config)`
The text generators behind every legal section of every report.

- `generate_methodology_sections()` — plain-language walkthrough of every
  phase, cross-referenced to FRE / Daubert factors, returned as a list of
  structured section dicts (heading/level/blocks) so reporters can render
  real headings instead of preformatted text.
- `get_standards_compliance_statement()` — plain-language explanation of
  how each standard (FRE 901, FRE 1001-1008, FRE 803(6), FRE 106, Daubert,
  SWGDE, NIST SP 800-86) is satisfied.
- `validate_completeness(messages)` — FRE-106 rule-of-completeness check;
  flags one-sided conversations and >24-hour gaps.
- `convert_to_local(timestamp)`, `format_timestamp(...)` — timezone-aware
  human-readable formatting used everywhere user-facing text appears.

## Data Flow

```
Source Data → Extraction → Analysis → Review → Reporting → Documentation
     ↓            ↓           ↓         ↓          ↓            ↓
  [Hashed]    [Hashed]    [Logged]  [Tracked]  [Hashed]   [Manifest]
```

Every stage records its actions (with timestamps and SHA-256 hashes where
applicable) into the same `ForensicRecorder` instance, so the final
`chain_of_custody_<timestamp>.json` covers the entire run end-to-end.
