# Forensic Message Analyzer — Claude Code Instructions

## Critical Rules
1. **Read actual files** — Never guess method names, parameters, or return types. Open the source file.
2. **No diagnostic scripts** — Fix the code directly. Don't create scripts to check things.
3. **No unnecessary scripts** — If asked to create a bash script, write it to a file, not the terminal.
4. **No guessing** — If unsure about a method signature or attribute, read the file.
5. **Auto-commit every change** — After every code change, immediately `git add` the changed files and `git commit` with a descriptive message. Do not batch changes or wait to be asked.

## Project Overview

Multi-phase digital evidence processor for legal use (Python). Data flow:

```
extraction → analysis → manual review → reporting → documentation
```

**Source directories:**
- `src/extractors/` — iMessage, WhatsApp, email, Teams, screenshots
- `src/analyzers/` — threats, sentiment, patterns, OCR, metrics, AI screening
- `src/review/` — manual review (CLI + Flask web interface)
- `src/reporters/` — Excel, Word, PDF, JSON, HTML, chat-bubble HTML
- `src/utils/` — chain of custody, run manifest, timeline, threading, legal compliance
- `src/forensic_utils.py` — forensic integrity, evidence validation, Daubert compliance
- `src/config.py` — configuration, contact mapping
- `src/third_party_registry.py` — unmapped contact tracking

## Contact Mapping System

- `PERSON1_NAME`, `PERSON2_NAME`, `PERSON3_NAME` — display names in all reports
- `PERSON1_MAPPING`, `PERSON2_MAPPING`, `PERSON3_MAPPING` — JSON arrays of identifiers (phones, emails, aliases)
- Phone numbers auto-expand to all common formats; list each number once in any format
- `AI_CONTACTS` — JSON array of person names whose conversations are sent to AI (controls cost)
  - Two-tier filter: party must be in `ai_contacts_specified` AND both parties in `ai_contacts`
  - `ai_contacts_specified` = raw AI_CONTACTS set (or None = all mapped persons)
  - `ai_contacts` = ai_contacts_specified + PERSON1_NAME
- `'Me'` is normalized to PERSON1_NAME during extraction; downstream code never sees `'Me'`

## Verified Class Signatures

These are confirmed by reading the source — do not guess.

### `src/forensic_utils.py`
- **`ForensicRecorder(output_dir=None)`** — optional output_dir
  - `record_action(action, details, metadata=None)` — stores dict with key `details` (NOT `description`)
  - `compute_hash(file_path)` — takes a `Path` object, not bytes
  - `generate_chain_of_custody(output_file=None)` — returns string path or None; chain JSON has `actions`, NOT `hashes`
  - `verify_integrity(file_path, expected_hash)`, `record_file_state(file_path, operation)`, `record_error(error_type, error_message, context)`
- **`ForensicIntegrity(forensic_recorder=None)`** — optional, creates default if None
  - `verify_read_only(file_path)`, `create_working_copy(source_path, dest_dir=None)`, `validate_extraction(source_path, extracted_data)`
- **`EvidenceValidator`** — evidence validation utilities

### `src/config.py`
- **`Config`** — configuration singleton; does NOT have `SOURCE_DIR`
  - `output_dir`, `review_dir`, `contact_mappings`, `ai_api_key`, `ai_endpoint`
  - `ai_batch_model`, `ai_summary_model` (legacy `ai_model` removed in v4.4.0)
  - `email_source_dir`, `teams_source_dir`, `messages_db_path`, `whatsapp_source_dir`, `screenshot_source_dir`
  - `case_number` (newline-joined string), `case_numbers` (list), `case_name`, `examiner_name`, `organization`, `timezone`
  - `use_batch_api`, `tokens_per_minute`, `request_delay_ms`, `max_tokens_per_request`
  - `ai_contacts` (expanded set), `ai_contacts_specified` (raw set or None)

### `src/main.py`
- **`ForensicAnalyzer(config=None)`** — takes **Config**, NOT ForensicRecorder
  - Creates internally: `self.forensic`, `self.integrity`, `self.manifest`, `self.third_party_registry`
  - `run_full_analysis()`, `run_finalize()`, `run_extraction_phase()`, `run_analysis_phase(data)`
  - `run_ai_batch_phase(data)`, `run_review_phase(analysis, data)`, `run_behavioral_phase(data, analysis, review)`
  - `run_reporting_phase(data, analysis, review)`, `run_documentation_phase(data, analysis)`

### `src/extractors/`
- **`DataExtractor(forensic, third_party_registry=None)`** — takes ForensicRecorder
  - `extract_all(start_date=None, end_date=None)` — returns list of message dicts (not dict with source keys)
  - `validate_extraction(messages)` — returns dict
- **`IMessageExtractor(db_path, forensic_recorder, forensic_integrity, config=None)`** — 3-4 params
  - `extract_messages()`, `decode_attributed_body(blob)`, `extract_text_with_fallback(text, attributed_body)`
  - `_parse_edit_history(blob_data)`, `_compute_time_until_read(sent_ts, read_ts)`, `_parse_chat_properties(cursor)`
  - `_parse_rich_link(blob_data)`, `_get_recently_deleted_ids(cursor, placeholders, all_handles)`
  - `_recover_deleted_messages(cursor, message_ids, msg_cols, att_cols)`
  - Alias: `iMessageExtractor` = `IMessageExtractor`
- **`WhatsAppExtractor(export_dir, forensic_recorder, forensic_integrity)`** — 3 params; `extract_all()`
- **`EmailExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)`** — `extract_all()`
- **`TeamsExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)`** — `extract_all()`
- **`ScreenshotExtractor(screenshot_dir, forensic_recorder)`** — 2 params; `extract_screenshots()`

### `src/analyzers/`
- **`ThreatAnalyzer(forensic)`** — `detect_threats(df)`, `generate_threat_summary(df)` — NOT `analyze()`
- **`SentimentAnalyzer(forensic)`** — requires forensic param
  - `analyze_sentiment(df)` — returns DataFrame with `sentiment_score`, `sentiment_polarity`, `sentiment_subjectivity` (NOT `sentiment_label`)
  - `generate_sentiment_summary(df)` — returns Dict
- **`BehavioralAnalyzer(forensic)`** — `analyze_patterns(df)`
- **`YamlPatternAnalyzer(forensic, patterns_file=None)`** — `analyze_patterns(df)`, `analyze_communication_frequency(df)`
- **`ScreenshotAnalyzer(forensic, third_party_registry=None)`** — `analyze_screenshots()` with NO params
- **`AttachmentProcessor(forensic)`** — `process_attachments(attachment_dir=None)` takes optional Path, NOT DataFrame
- **`CommunicationMetricsAnalyzer(forensic_recorder=None)`** — `analyze_messages(messages)` takes list of dicts, NOT DataFrame
  - Alias: `CommunicationMetrics` = `CommunicationMetricsAnalyzer`
- **`AIAnalyzer(forensic_recorder=None, config=None)`** — `analyze_messages(messages, batch_size=50)` — NOT `analyze(df, threat_results)`
  - `analyze_single_message(message)`, `_estimate_tokens(text)`, `_empty_analysis()`

### `src/review/`
- **`ManualReviewManager(review_dir=None)`** — optional review_dir
  - `add_review(item_id, item_type, decision, notes="")` — positional args
  - `get_reviews_by_decision(decision)`, `get_reviews_by_type(item_type)`, `get_review_summary()`
  - `load_reviews(session_id)` — NOT `load_existing_reviews()`
- **`InteractiveReview(review_manager)`**
- **`WebReview(review_manager, forensic_recorder=None)`** — runs Flask in daemon thread; shutdown via `threading.Event`, NOT `os.kill(SIGINT)`

### `src/reporters/`
- **`ExcelReporter(forensic_recorder, config=None)`**
  - `generate_report(extracted_data, analysis_results, review_decisions, output_path)` → Path
  - Sheets: Overview, Findings Summary, Timeline, per-person chat tabs, Conversation Threads, Manual Review, Third Party Contacts
  - Person1 does NOT get a per-person tab; all mapped persons get sheets even with zero messages
- **`HtmlReporter(forensic_recorder, config=None)`**
  - `generate_report(extracted_data, analysis_results, review_decisions, output_path, pdf=True)` → Dict[str, Path]
- **`ChatReporter(forensic_recorder, config=None)`**
  - `generate_report(extracted_data, analysis_results, review_decisions, output_path)` → Dict[str, Path]

### `src/utils/`
- **`TimelineGenerator(forensic)`** — `create_timeline(df, output_path, raw_messages=None, extracted_data=None)` — NOT `generate_timeline()`
- **`ConversationThreader(default_gap_hours=2.0)`**
- **`RunManifest(forensic_recorder=None)`** — optional forensic_recorder
  - `add_input_file()`, `add_output_file()`, `generate_manifest(output_path=None)` → Path (not dict)
  - `add_operation()`, `validate_manifest()`, `add_extraction_summary()`, `add_analysis_summary()`, `add_report_summary()`
  - Files must exist on disk to be added
- **`LegalComplianceManager(config)`**
  - `generate_methodology_sections()` — returns list of structured section dicts (heading/level/blocks) for real heading rendering
  - `get_standards_compliance_statement()`, `validate_completeness(messages)`

## Developer Workflows

```bash
python3 run.py                          # Phases 1-4: extraction, analysis, review
python3 run.py --finalize               # Phases 5-8: post-review reporting
python3 run.py --resume                 # Resume interrupted review
python3 validate_before_run.py          # 8-check pre-run validation (spends AI credits)
python3 validate_before_run.py --no-ai  # Validate without AI spend
python3 -m pytest tests/ -v             # Full test suite
python3 -m pytest tests/test_integration.py -v
```

## Data Directories

```
~/workspace/data/forensic-message-analyzer/    ← .env, source_files/, review/, logs/
~/workspace/output/forensic-message-analyzer/  ← all analysis outputs
```

The `.env` file lives outside the repo. The system looks for it at the path above, then `DOTENV_PATH` env var, then local `.env`.

## Known Gotchas

- **Anthropic base_url**: Always pass `base_url="https://api.anthropic.com"` when creating Anthropic clients. VS Code injects `ANTHROPIC_BASE_URL=http://localhost:...` which causes 401 errors.
- **Batch API timeout**: Polling has a 4-hour max; raises `TimeoutError` instead of blocking forever.
- **Batch fallback guard**: If batch API fails AFTER submission, do NOT fall back to sync — that re-processes everything at full cost.
- **SentimentAnalyzer**: Returns `sentiment_polarity`, not `sentiment_label`.
- **CommunicationMetricsAnalyzer**: `analyze_messages()` takes a list of dicts, not a DataFrame.
- **compute_hash()**: Takes a `Path`, not bytes.
- **Chain of custody JSON**: Has `actions` key, NOT `hashes`.
- **ForensicAnalyzer**: Takes `Config`, not `ForensicRecorder`.
- **DataExtractor.extract_all()**: Returns a flat list of message dicts, not a dict keyed by source.
- **Config**: Has no `SOURCE_DIR` attribute.
- **ai_model removed**: Use `ai_batch_model` and `ai_summary_model` (since v4.4.0).

## Legal Defensibility

All processing maintains forensic integrity for FRE/Daubert:
- SHA-256 hash every source file before any processing; originals opened read-only
- Log all actions with UTC timestamps via `forensic.record_action()`
- Chain of custody document covers every action in the run
- Run manifest lists every input/output file with its hash and the exact configuration used
- Pattern detection uses YAML definitions in `patterns/analysis_patterns.yaml`
- AI is optional and used only for pre-review screening and executive summary drafting; human reviewer confirms everything before it reaches a final report

## Conventions

- Use `forensic.record_action()` for all significant operations
- Name output files with timestamps: `report_YYYYMMDD_HHMMSS.ext`
- New analyzers go in `src/analyzers/`; update `main.py` when adding phases
- Always use `python3` on macOS
- Write tests for new components; run `pytest tests/test_imports.py` first when debugging dependency issues
