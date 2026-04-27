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
- [Directory Structure](#directory-structure)
- [Data Flow](#data-flow)
- [Quick Example](#quick-example)
- [Forensic Utilities](#forensic-utilities)
- [Extractors](#extractors)
- [Analyzers](#analyzers)
- [Reporters](#reporters)
- [Review](#review)
- [Utilities](#utilities)
- [Testing](#testing)
- [System Readiness](#system-readiness)

## Directory Structure

```text
forensic-message-analyzer/
├── src/
│   ├── extractors/                   # Data extraction modules
│   │   ├── base.py                   # MessageExtractor base class (shared init + _record helper)
│   │   ├── data_extractor.py         # Unified extraction orchestrator
│   │   ├── imessage_extractor.py     # iMessage database extraction
│   │   ├── whatsapp_extractor.py     # WhatsApp export parsing (zip-bomb + zip-slip guards)
│   │   ├── email_extractor.py        # Email .eml/.mbox extraction
│   │   ├── teams_extractor.py        # Microsoft Teams export extraction
│   │   ├── screenshot_extractor.py   # Screenshot cataloging
│   │   ├── sms_backup_extractor.py   # Android SMS Backup & Restore XML
│   │   ├── call_logs_extractor.py    # iOS CallHistory + Android call XML + CSV
│   │   ├── voicemail_extractor.py    # iOS voicemail.db + audio + transcripts
│   │   └── location_extractor.py     # Google Takeout + Apple plist + GPX
│   ├── analyzers/                    # Analysis engines
│   │   ├── ai_analyzer.py            # Anthropic Claude AI analysis (batch + sync)
│   │   ├── threat_analyzer.py        # Threat detection
│   │   ├── sentiment_analyzer.py     # Sentiment analysis
│   │   ├── behavioral_analyzer.py    # Behavioral patterns
│   │   ├── yaml_pattern_analyzer.py  # YAML-defined patterns (DARVO, gaslighting, coercive control)
│   │   ├── communication_metrics.py  # Statistical metrics
│   │   ├── screenshot_analyzer.py    # OCR processing
│   │   └── attachment_processor.py   # Attachment cataloging + EXIF / GPS / tamper scanning
│   ├── pipeline/                     # Per-phase runners (delegated from ForensicAnalyzer)
│   │   ├── extraction.py             # Phase 1
│   │   ├── analysis.py               # Phase 2
│   │   ├── ai_batch.py               # Phase 3
│   │   ├── review.py                 # Phase 4
│   │   ├── behavioral.py             # Phase 5
│   │   ├── reporting.py              # Phase 7
│   │   └── documentation.py          # Phase 8 (includes events_timeline)
│   ├── review/                       # Manual review management
│   │   ├── manual_review_manager.py  # Review decision tracking (required reviewer, append-only amendments)
│   │   ├── redaction_manager.py      # Append-only span / regex redaction workflow
│   │   ├── interactive_review.py     # CLI-based message review
│   │   └── web_review.py             # Flask-based web review UI (hardened cookies, scoped attachments)
│   ├── reporters/                    # Report generation
│   │   ├── forensic_reporter.py      # Main reporter (Word + PDF + methodology DOCX + PDF + JSON)
│   │   ├── excel_reporter.py         # Standalone Excel report with multiple sheets
│   │   ├── html_reporter.py          # HTML/PDF report with inline images, source badges, appendices
│   │   ├── chat_reporter.py          # iMessage-style chat-bubble HTML report
│   │   └── json_reporter.py          # JSON output
│   ├── utils/                        # Utilities and helpers
│   │   ├── conversation_threading.py # Thread detection and grouping
│   │   ├── legal_compliance.py       # Legal standards + structured methodology rendering
│   │   ├── timeline_generator.py     # Detailed minute-level HTML timeline
│   │   ├── events_timeline.py        # Sparse executive-view timeline
│   │   ├── run_manifest.py           # Run documentation (config snapshot, pattern hashes, signed)
│   │   ├── evidence_preserver.py     # Hashing, archiving, working-copy routing, contact auto-map
│   │   ├── signing.py                # Ed25519 detached signatures
│   │   ├── contact_automapper.py     # vCard → contact_mappings merger
│   │   └── pricing.py                # AI model pricing lookup
│   ├── forensic_utils.py             # Chain of custody and integrity (HMAC-chained log)
│   ├── third_party_registry.py       # Unmapped contact tracking
│   ├── config.py                     # Configuration + snapshot() for manifest
│   ├── schema.py                     # TypedDicts for Message / Finding / ReviewRecord
│   └── main.py                       # Thin orchestrator; phase logic lives in src/pipeline/
├── tests/                            # Unit and integration tests
│   ├── test_imports.py               # Dependency verification
│   ├── test_core_functionality.py    # Core component tests
│   ├── test_integration.py           # End-to-end tests
│   ├── test_forensic_utils.py        # Forensic utilities tests
│   ├── test_teams_extractor.py       # Microsoft Teams extractor tests
│   ├── test_third_party_registry.py  # Third-party contact registry tests
│   ├── test_timezone_dst.py          # DST + Apple-epoch round-trip coverage
│   └── run_all_tests.sh              # Test runner script
├── patterns/                         # YAML pattern definitions (with empirical citations)
│   └── analysis_patterns.yaml
├── .github/
│   └── copilot-instructions.md       # Development guidelines
├── validate_before_run.py            # Pre-run validation and cost estimation
├── check_readiness.py                # System readiness checker
├── generate_sample_output.py         # Regenerates sample_output/ from anonymized fixtures
├── run.py                            # Main entry point
├── ROADMAP.md                        # Deferred work (redaction UI, Signal/Telegram)
├── requirements.txt                  # Supported minimum versions
├── requirements-lock.txt             # Pinned versions for reproducible installs
└── .env.example                      # Configuration template
```

## Data Flow

```text
Source Data → Extraction → Analysis → Review → Reporting → Documentation
     ↓            ↓           ↓         ↓          ↓            ↓
  [Hashed]    [Hashed]    [Logged]  [Tracked]  [Hashed]   [Manifest]
```

Every stage records its actions (with timestamps and SHA-256 hashes where applicable) into the same `ForensicRecorder` instance, so the final `chain_of_custody_<timestamp>.json` covers the entire run end-to-end. The forensic JSONL log is HMAC-chained; final reports, manifest, and chain of custody are signed with detached Ed25519.

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
Records every action with timestamps and SHA-256 hashes. Each record now carries `seq`, `prev_hmac`, and `hmac` fields so the persisted JSONL log is tamper-evident — inserting, deleting, reordering, or editing a record breaks the chain at the first affected line.

- `record_action(action, details, metadata=None)` — log a forensic action.
- `compute_hash(file_path)` — SHA-256 of a file (takes a `Path`).
- `generate_chain_of_custody(output_file=None)` — write the chain-of-custody
  JSON; returns the path string.
- `verify_integrity(file_path, expected_hash)` — verify a stored hash.
- `verify_log_chain(log_path=None, key=None)` — walk a persisted JSONL and return `{"verified": bool, "records": int, "error": str|None}`. The per-session HMAC key lives beside the log as `forensic_hmac_key_{session}.bin` (mode 0600); archive both together for third-party verification.
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

All new extractors subclass `MessageExtractor` (`src/extractors/base.py`), which provides the standard `(source, forensic_recorder, forensic_integrity, config=None)` init and a `_record()` helper that tags every forensic entry with the extractor's `SOURCE_NAME`. Legacy extractors (iMessage, WhatsApp, email, Teams, screenshots) still use their own inits but are wire-compatible.

### `IMessageExtractor(db_path, forensic_recorder, forensic_integrity, config=None)`
- `extract_messages()` — full extraction including `attributedBody`
  decoding, edit history (iOS 16+), deleted-message recovery, URL previews,
  shared locations, per-chat properties, and forensic timestamps.
- `_discover_columns(cursor, table_name)` — rejects any table not in `_ALLOWED_SCHEMA_TABLES`. Add to the frozenset if a new chat.db table is introspected.

### `WhatsAppExtractor(export_dir, forensic_recorder, forensic_integrity)`
- `extract_all()` — auto-extracts ZIP archives and parses chat exports. ZIP members are validated against caps (`_MAX_UNCOMPRESSED_BYTES`, `_MAX_MEMBERS`, `_MAX_COMPRESSION_RATIO`); absolute paths and parent-directory traversal are rejected.

### `EmailExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)`
- `extract_all()` — parses `.eml` and `.mbox` with full MIME header
  extraction.

### `TeamsExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)`
- `extract_all()` — parses Microsoft Teams personal export TAR archives.

### `ScreenshotExtractor(screenshot_dir, forensic_recorder)`
- `extract_screenshots()` — catalogues image files for OCR.

### `SMSBackupExtractor(source, forensic_recorder, forensic_integrity, config=None)`
- `extract_all()` — parses the Android "SMS Backup & Restore" XML format (`<sms>` + `<mms>`). MMS base64 attachments are decoded and written alongside the backup as `mms_attachments/<name>` so downstream attachment processing can hash and EXIF-scan them.

### `CallLogsExtractor(source, forensic_recorder, forensic_integrity, config=None)`
- `extract_all()` — parses iOS `CallHistory.storedata` (SQLite), Android call XML, and generic CSV. Direction mapping via `_IOS_TYPE` / `_ANDROID_TYPE`. Contact names auto-resolved against `config.contact_mappings`.

### `VoicemailExtractor(source, forensic_recorder, forensic_integrity, config=None)`
- `extract_all()` — reads iOS `voicemail.db` plus any sibling `rowid.{amr,wav,m4a}` audio. Column discovery via `PRAGMA table_info` keeps it resilient across iOS versions; transcripts from the `transcription` column (when present) are surfaced.

### `LocationExtractor(source, forensic_recorder, forensic_integrity, config=None)`
- `extract_all()` — parses Google Takeout `Records.json` and Semantic Location History, Apple plist exports, and generic GPX 1.1. Returns a unified point-record shape (`timestamp`, `latitude`, `longitude`, optional `accuracy_m`, `source`, raw provenance fields).

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

Set `SKIP_AI_TAGGING=true` in `.env` to skip Phase 3 per-message tagging entirely while still running the Phase 6 executive summary. This is distinct from `USE_BATCH_API`, which controls whether the Anthropic async Batch API protocol is used for submissions.

### `ScreenshotAnalyzer(forensic, third_party_registry=None)`
- `analyze_screenshots()` — OCRs every screenshot in the configured
  directory; takes no arguments.

### `AttachmentProcessor(forensic)`
- `process_attachments(attachment_dir=None)` — takes an optional `Path`,
  returns a stats dict.
- `extract_image_metadata(file_path)` — returns a dict with `exif` (named tags), `gps` (decimal lat/lon/alt decoded from the EXIF GPSInfo IFD), and `anomalies` — a list of forensic flags: `geolocation_present`, `edited_by:<tool>` (Photoshop/Lightroom/GIMP/Affinity/Pixelmator in the Software tag), `datetime_mismatch` (DateTimeOriginal != DateTimeDigitized), `exif_stripped` (no EXIF at all, unusual for camera originals).

## Reporters

### `ExcelReporter(forensic_recorder, config=None)`
- `generate_report(extracted_data, analysis_results, review_decisions, output_path)` —
  multi-sheet Excel: Overview, Findings Summary, Timeline,
  per-person sheets, Conversation Threads, Manual Review, Third Party Contacts.
- Sender and recipient columns display as `"Name (phone/email)"` when `sender_raw` / `recipient_raw` are present on a message.

### `HtmlReporter(forensic_recorder, config=None)`
- `generate_report(..., pdf=True)` — HTML with inline base64 attachments,
  per-person tables, conversation threads, risk indicators, and three
  legal appendices (Methodology, Completeness Validation, Limitations).
  Optionally renders PDF via WeasyPrint.
- Sender and recipient columns display as `"Name (identifier)"` when raw identifiers are present.

### `ChatReporter(forensic_recorder, config=None)`
- `generate_report(...)` — iMessage-style chat-bubble HTML with edit
  history, deleted-message badges, URL preview blocks, and shared
  location blocks.
- Bubble meta line displays `"Name (phone/email)"` when `sender_raw` is present on the message.

### `ForensicReporter(forensic_recorder, config=None)`
- `generate_comprehensive_report(extracted_data, analysis_results, review_decisions)` —
  produces Word + PDF + JSON + a standalone Methodology document in both
  `.docx` and `.pdf` form, and a legal-team summary `.docx`. The Methodology
  document is independent of the findings report so the legal team can
  review the methodology in isolation; the PDF version exists for court
  exhibits and readers without Office.
- Standards Compliance section (in both the findings Word report and the standalone Methodology) is rendered via `LegalComplianceManager.generate_standards_compliance_sections()` — real headings, a bulleted list of standards, and term/definition pairs for how each is satisfied (not a flat text block).

### `JSONReporter(forensic_recorder, config=None)`
- `generate_report(...)` — raw JSON of the analysis output.

## Review

### `ManualReviewManager(review_dir=None, session_id=None, config=None, forensic_recorder=None)`
- `add_review(item_id, item_type, decision, notes="", reviewer=None, source="unknown", method="")` — record a review decision. Decisions are persisted to disk immediately so reviews survive process termination. `reviewer` is required (falls back to `config.examiner_name`); notes are mandatory for `not_relevant` and `uncertain` decisions. Attempting to re-decide an existing item_id raises `ValueError` — use `amend_review()` instead. `source` is stamped so downstream reports can distinguish `pattern_matched` vs `ai_screened` findings.
- `amend_review(item_id, decision, notes, reviewer=None)` — appends a new record marking the prior one `superseded_by`; notes mandatory on amendments. Prior records never mutate.
- `reviewed_item_ids` — set of item_ids whose most recent decision is still active (not superseded).
- `get_reviews_by_decision(decision)`, `get_reviews_by_type(item_type)`,
  `get_review_summary()`, `load_reviews(session_id)`.

### `RedactionManager(review_dir=None, session_id=None, config=None, forensic_recorder=None)`
Append-only redaction workflow for court-ready exhibits. Tracks per-message redactions with mandatory `reason` + `authority` (order/agreement citation) + `examiner` fields, applied to message content at render time in `run_reporting_phase`.

- `redact(message_id, reason, authority, examiner=None, span=None, pattern=None, replacement=None)` — record a span (`(start, end)`) or regex redaction; `reason` and `authority` required.
- `revoke(message_id, reason, examiner=None)` — appends a new record; prior redaction keeps `revoked_at`/`revoked_by` fields so the audit trail survives.
- `apply(message_id, content)` — returns content with active redactions applied. Raw `extracted_data` JSON (persisted before reporting) preserves the unredacted content for discovery-challenge purposes.

### `InteractiveReview(review_manager, config=None)`
- CLI-based message review. Prompts for a reviewer name when `EXAMINER_NAME` is unset; requires a reason on every rejection.

### `WebReview(review_manager, forensic_recorder=None, config=None)`
- Flask-based web review interface. Uses a `threading.Event` for shutdown
  rather than killing the parent process when the user clicks "Complete
  Review". Cookies are HttpOnly + `SameSite=Strict`; the secret key is a per-session random value. Attachment serving is constrained to a fixed set of base directories (WhatsApp, screenshots, output, iMessage attachments) plus a per-request allowlist built from loaded messages.

## Utilities

### `TimelineGenerator(forensic, config=None)`
Minute-level chronological HTML for analysts who need drill-down.

- `create_timeline(df, output_path, raw_messages=None, extracted_data=None)` —
  HTML timeline with case chronology. When `extracted_data` is provided,
  email events are included alongside flagged events. Mapped-person emails
  render as "email"; emails involving unmapped third parties (counsellors,
  attorneys, family) render as "third-party-email".
- `generate_html_timeline(df, raw_messages=None, extracted_data=None)`.

### `events_timeline` module (`src/utils/events_timeline.py`)
Sparse, executive-view timeline for court readers — only the moments the case turns on.

- `collect_events(extracted_data, analysis_results, review_decisions)` — returns a list of reviewer-confirmed events: pattern-matched threats, AI-screened threats, AI coercive-control clusters, local pattern clusters, sentiment shifts. Period-boundary milestones are intentionally excluded.
- `render_events_timeline(events, output_path, config=None, case_name='', case_number='')` — emits compact HTML with per-category badges (threat, pattern, escalation, de-escalation, milestone). Event dates are resolved via ISO parse → natural-language parse ("early September 4") → quote-match against the message corpus, so undated AI output still plots correctly.

### `ConversationThreader(default_gap_hours=2.0)`
Used by `TimelineGenerator` to group related messages into threads.

### `ThirdPartyRegistry(forensic_recorder, config=None)`
- `register(identifier, display_name, source, context)` — register an
  unmapped contact discovered during extraction.
- `get_all()`, `summary()`.

### `RunManifest(forensic_recorder=None, config=None)`
- When `config` is provided, its `snapshot()` is embedded in the manifest as `config_snapshot` (API keys redacted) so an opposing expert can reproduce the exact run settings.
- On init, every `.yaml` under `patterns/` is hashed into `pattern_files` — proves which rule set was in force at run time.
- `add_input_file(path)`, `add_output_file(path)`, `add_operation(...)`,
  `add_extraction_summary(...)`, `add_analysis_summary(...)`,
  `add_report_summary(...)`.
- `generate_manifest(output_path=None)` — returns the `Path` of the
  written manifest. Files must exist on disk to be included. The emitted manifest is signed via the shared `_sign_if_possible` helper, producing sibling `<file>.sig` + `<file>.sig.pub` files.

### `Signer(key_path=None, run_dir=None)` (`src/utils/signing.py`)
Detached Ed25519 signing for manifests, chain of custody, and final reports.

- Loads an existing PEM from `key_path` (typically `EXAMINER_SIGNING_KEY`) or generates an ephemeral key under `run_dir/keys/examiner_ed25519.pem` (mode 0600). Ephemeral mode is still tamper-evident within the run; long-lived mode anchors every run to the examiner's published public cert.
- `sign_file(file_path)` → `(sig_path, pub_path)` writes `<file>.sig` (raw 64-byte Ed25519 signature) and `<file>.sig.pub` (PEM public key).
- `verify_file(file_path)` → `bool` using the sibling `.sig` + `.sig.pub`.
- `is_ephemeral` — True when a key was generated this run.

### `EvidencePreserver(config, forensic, integrity, manifest=None)` (`src/utils/evidence_preserver.py`)
Pre-extraction bookkeeping, split out of `ForensicAnalyzer` so the orchestrator stays thin.

- `hash_sources()` — SHA-256 every configured source file into the chain of custody.
- `preserve_sources()` — copy every source into `run_dir/preserved_sources.zip` with per-file hashes.
- `route_to_working_copies()` — copy every source into `run_dir/working_copies/` and repoint `config` attributes in place. Extractors never read originals.
- `apply_contact_automapping()` — merge vCard-derived contacts into `config.contact_mappings` (opt-in via `CONTACTS_VCARD_DIR`).

### `contact_automapper` module (`src/utils/contact_automapper.py`)
Reduce the "Unknown" third-party surface by importing identifiers from vCard exports.

- `parse_vcard_file(path)` → list of contact dicts (FN/N/TEL/EMAIL).
- `vcards_to_mapping(paths)` → `{display_name: [identifiers]}` merged across files.
- `load_vcards_from_dir(source_dir)` — convenience wrapper.
- `merge_into_config(config, mapping, default_person_slot=None)` — extends `config.contact_mappings` in place; auto-applies `Config._expand_contact_mappings` for phone-format variants. Provenance of every merged entry is recorded in the chain of custody.

### `schema` module (`src/schema.py`)
TypedDicts documenting the contract between extractors, analyzers, review, and reporters.

- `Message`, `Finding`, `ReviewRecord`, `ThreatDetails`, `SentimentDetails`, `AnalysisResults`.
- `FindingSource` Literal: `"pattern_matched" | "ai_screened" | "extracted" | "derived" | "unknown"`.
- `ReviewDecision` Literal: `"relevant" | "not_relevant" | "uncertain"`.
- `Message` includes `sender_raw` (`NotRequired[Optional[str]]`) and `recipient_raw` (`NotRequired[Optional[str]]`) — the raw protocol identifier (phone number, email address, iMessage handle) for each party before contact mapping. `None` for PERSON1's own messages. All extractors (iMessage, email, WhatsApp, SMS, Teams) populate these. Reporters render `"Name (identifier)"` inline when `sender_raw` is present.
- Documentation + type-checker hints; runtime code still uses `dict.get()` with defaults.

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

## Testing

### Run all tests

```bash
# Full suite (integration + unit)
python3 -m pytest tests/ -v

# Non-integration subset (faster; doesn't require fixture data)
python3 -m pytest tests/ --ignore=tests/test_integration.py

# Shell wrapper
./tests/run_all_tests.sh
```

### Run a specific suite

```bash
python3 -m pytest tests/test_imports.py -v            # dependency verification
python3 -m pytest tests/test_core_functionality.py -v # core components
python3 -m pytest tests/test_forensic_utils.py -v     # chain of custody, HMAC log
python3 -m pytest tests/test_timezone_dst.py -v       # DST + Apple-epoch coverage
python3 -m pytest tests/test_integration.py -v        # end-to-end pipeline
python3 -m pytest tests/test_teams_extractor.py -v
python3 -m pytest tests/test_third_party_registry.py -v
python3 -m pytest tests/test_counseling_extractor.py -v
python3 -m pytest tests/test_bugfixes.py -v
```

### Coverage

```bash
python3 -m pytest --cov=src tests/
```

## System Readiness

Before a real run, sanity-check that sources, credentials, and output paths are in place:

```bash
python3 check_readiness.py
```

For a deeper pre-run validation that also estimates AI costs (uses a small amount of API credits):

```bash
python3 validate_before_run.py --env /path/to/.env            # 8-check validation with 5-message AI sample (~$0.01)
python3 validate_before_run.py --env /path/to/.env --no-ai    # Skip the AI sample; extraction stats + cost table only
```
