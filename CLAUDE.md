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
- `src/extractors/` — iMessage, WhatsApp, email, Teams, screenshots, SMS backup (Android XML), call logs (iOS/Android), voicemail (iOS DB), location (Google Timeline/GPX/Apple plist); `base.py` provides `MessageExtractor`
- `src/analyzers/` — threats, sentiment, patterns, OCR, metrics, AI screening; attachment processor also runs EXIF / GPS / tamper-indicator scan
- `src/review/` — manual review (CLI + Flask web interface); `redaction_manager.py` tracks append-only span/regex redactions
- `src/reporters/` — Excel, Word, PDF, JSON, HTML, chat-bubble HTML; methodology now emits both DOCX and PDF
- `src/pipeline/` — per-phase runners (extraction, analysis, ai_batch, review, behavioral, reporting, documentation); `ForensicAnalyzer` in `src/main.py` is a thin orchestrator that delegates to these
- `src/utils/` — chain of custody, run manifest, timelines (detailed + events), threading, legal compliance, evidence preserver, contact auto-mapper, Ed25519 signing
- `src/forensic_utils.py` — forensic integrity, evidence validation, HMAC-chained tamper-evident log, Daubert compliance
- `src/config.py` — configuration, contact mapping, `snapshot()` for manifest embedding
- `src/third_party_registry.py` — unmapped contact tracking
- `src/schema.py` — TypedDicts for Message / Finding / ReviewRecord / analysis result shapes

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
  - `record_action(action, details, metadata=None)` — stores dict with key `details` (NOT `description`); every record now carries `seq`, `prev_hmac`, and `hmac` for a tamper-evident chain
  - `verify_log_chain(log_path=None, key=None)` → dict with `verified`, `records`, `error` — detects any edit/deletion/reorder in the persisted JSONL
  - Per-session HMAC key is written to `forensic_hmac_key_{session_id}.bin` (mode 0600) beside the log; archive it alongside the log for independent verification
  - `compute_hash(file_path)` — takes a `Path` object, not bytes
  - `generate_chain_of_custody(output_file=None)` — returns string path or None; chain JSON has `actions`, NOT `hashes`
  - `verify_integrity(file_path, expected_hash)`, `record_file_state(file_path, operation)`, `record_error(error_type, error_message, context)`
- **`ForensicIntegrity(forensic_recorder=None)`** — optional, creates default if None
  - `verify_read_only(file_path)`, `create_working_copy(source_path, dest_dir=None)`, `validate_extraction(source_path, extracted_data)`
- **`EvidenceValidator`** — evidence validation utilities

### `src/config.py`
- **`Config`** — configuration singleton; does NOT have `SOURCE_DIR`
  - `output_dir`, `review_dir`, `contact_mappings`, `ai_api_key`, `ai_endpoint`
  - `ai_tagging_model`, `ai_summary_model` (legacy `ai_model` removed in v4.4.0)
  - `email_source_dir`, `teams_source_dir`, `messages_db_path`, `whatsapp_source_dir`, `screenshot_source_dir`
  - `case_number` (newline-joined string), `case_numbers` (list), `case_name`, `examiner_name`, `organization`, `timezone`
  - `use_batch_api` — whether to use Anthropic's async Batch API protocol (cheaper/slower); `skip_ai_tagging` — set `SKIP_AI_TAGGING=true` to skip Phase 3 per-message AI tagging entirely while still running the Phase 6 executive summary
  - `tokens_per_minute`, `request_delay_ms`, `max_tokens_per_request`
  - `ai_contacts` (expanded set), `ai_contacts_specified` (raw set or None)
  - `contacts_vcard_dir` (optional; vCard auto-mapping source)
  - `examiner_signing_key` (optional; PEM path to long-lived Ed25519 key; per-run ephemeral key generated when absent)
  - `snapshot()` — returns a dict of every setting (api keys redacted) for embedding in the run manifest
  - `_parse_json_list()` now raises `ValueError` on malformed JSON instead of silently returning `[]`

### `src/main.py` + `src/pipeline/`
- **`ForensicAnalyzer(config=None)`** — takes **Config**, NOT ForensicRecorder. Thin orchestrator; all phase logic lives in `src/pipeline/`
  - Creates internally: `self.forensic`, `self.integrity`, `self.manifest`, `self.third_party_registry`, `self.evidence` (EvidencePreserver)
  - Each `run_*_phase` method is a one-line delegate to the matching module in `src/pipeline/`
  - `run_full_analysis()`, `run_finalize()`, `run_extraction_phase()`, `run_analysis_phase(data)`
  - `run_ai_batch_phase(data)`, `run_review_phase(analysis, data, resume_session_id=None)`, `run_behavioral_phase(data, analysis, review)`
  - `run_reporting_phase(data, analysis, review)`, `run_documentation_phase(data, analysis=None, review_decisions=None)`
  - `_sign_artifact(path)` — detached Ed25519 signature on manifest/chain/reports
- Phase modules (one function `run(analyzer, ...)` each): `src/pipeline/extraction.py`, `analysis.py`, `ai_batch.py`, `review.py`, `behavioral.py`, `reporting.py`, `documentation.py`
- **`EvidencePreserver(config, forensic, integrity, manifest=None)`** — `src/utils/evidence_preserver.py`
  - `hash_sources()`, `preserve_sources()`, `route_to_working_copies()`, `apply_contact_automapping()`

### `src/extractors/`
- **`MessageExtractor(source, forensic_recorder, forensic_integrity, config=None)`** — `src/extractors/base.py`; shared init + `_record()` helper; new extractors subclass this
- **`DataExtractor(forensic, third_party_registry=None)`** — takes ForensicRecorder
  - `extract_all(start_date=None, end_date=None)` — returns list of message dicts (not dict with source keys)
  - `validate_extraction(messages)` — returns dict
- **`IMessageExtractor(db_path, forensic_recorder, forensic_integrity, config=None)`** — 3-4 params
  - `extract_messages()`, `decode_attributed_body(blob)`, `extract_text_with_fallback(text, attributed_body)`
  - `_parse_edit_history(blob_data)`, `_compute_time_until_read(sent_ts, read_ts)`, `_parse_chat_properties(cursor)`
  - `_parse_rich_link(blob_data)`, `_get_recently_deleted_ids(cursor, placeholders, all_handles)`
  - `_recover_deleted_messages(cursor, message_ids, msg_cols, att_cols)`
  - `_discover_columns(cursor, table_name)` — raises `ValueError` for any table not in `_ALLOWED_SCHEMA_TABLES`
  - Alias: `iMessageExtractor` = `IMessageExtractor`
- **`WhatsAppExtractor(export_dir, forensic_recorder, forensic_integrity)`** — 3 params; `extract_all()`. ZIP extraction validates against `_MAX_UNCOMPRESSED_BYTES`, `_MAX_MEMBERS`, `_MAX_COMPRESSION_RATIO` and rejects path-traversal entries.
- **`EmailExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)`** — `extract_all()`
- **`TeamsExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)`** — `extract_all()`
- **`ScreenshotExtractor(screenshot_dir, forensic_recorder)`** — 2 params; `extract_screenshots()`
- **`SMSBackupExtractor(source, forensic_recorder, forensic_integrity, config=None)`** — Android "SMS Backup & Restore" XML; MMS attachments base64-decoded to sibling `mms_attachments/`
- **`CallLogsExtractor(source, forensic_recorder, forensic_integrity, config=None)`** — iOS CallHistory SQLite, Android call XML, generic CSV; direction mapped via `_IOS_TYPE` / `_ANDROID_TYPE`; contact auto-resolve against `config.contact_mappings`
- **`VoicemailExtractor(source, forensic_recorder, forensic_integrity, config=None)`** — iOS `voicemail.db` plus sibling `rowid.{amr,wav,m4a}` audio and optional transcripts
- **`LocationExtractor(source, forensic_recorder, forensic_integrity, config=None)`** — Google Takeout Records.json, Semantic Location History, Apple plist, GPX 1.1

### `src/analyzers/`
- **`ThreatAnalyzer(forensic)`** — `detect_threats(df)`, `generate_threat_summary(df)` — NOT `analyze()`
- **`SentimentAnalyzer(forensic)`** — requires forensic param
  - `analyze_sentiment(df)` — returns DataFrame with `sentiment_score`, `sentiment_polarity`, `sentiment_subjectivity` (NOT `sentiment_label`)
  - `generate_sentiment_summary(df)` — returns Dict
- **`BehavioralAnalyzer(forensic)`** — `analyze_patterns(df)`
- **`YamlPatternAnalyzer(forensic, patterns_file=None)`** — `analyze_patterns(df)`, `analyze_communication_frequency(df)`
- **`ScreenshotAnalyzer(forensic, third_party_registry=None)`** — `analyze_screenshots()` with NO params
- **`AttachmentProcessor(forensic)`** — `process_attachments(attachment_dir=None)` takes optional Path, NOT DataFrame
  - `extract_image_metadata(file_path)` returns a dict with `exif` (named tags), `gps` (decoded decimal lat/lon/alt), and `anomalies` (list of `geolocation_present`, `edited_by:<tool>`, `datetime_mismatch`, `exif_stripped`)
- **`CommunicationMetricsAnalyzer(forensic_recorder=None)`** — `analyze_messages(messages)` takes list of dicts, NOT DataFrame
  - Alias: `CommunicationMetrics` = `CommunicationMetricsAnalyzer`
- **`AIAnalyzer(forensic_recorder=None, config=None)`** — `analyze_messages(messages, batch_size=50)` — NOT `analyze(df, threat_results)`
  - `analyze_single_message(message)`, `_estimate_tokens(text)`, `_empty_analysis()`
  - Endpoint written to the forensic log is sanitized via `_sanitize_endpoint()` (strips userinfo, query, fragment) so embedded credentials never hit the chain of custody

### `src/review/`
- **`ManualReviewManager(review_dir=None, session_id=None, config=None, forensic_recorder=None)`**
  - `add_review(item_id, item_type, decision, notes="", reviewer=None, source="unknown", method="")` — `reviewer` required (falls back to `config.examiner_name`); notes required when decision is `not_relevant` or `uncertain`; refuses duplicate decisions on the same item_id (use `amend_review` instead). `source` is stamped into the record so reports can distinguish pattern-matched vs ai-screened findings.
  - `amend_review(item_id, decision, notes, reviewer=None)` — appends a new record marking the prior one `superseded_by`; notes mandatory; prior records never mutate
  - `reviewed_item_ids` — set of item_ids whose most recent decision is still active (not superseded)
  - `get_reviews_by_decision(decision)`, `get_reviews_by_type(item_type)`, `get_review_summary()`
  - `load_reviews(session_id)` — NOT `load_existing_reviews()`
- **`RedactionManager(review_dir=None, session_id=None, config=None, forensic_recorder=None)`** — `src/review/redaction_manager.py`
  - `redact(message_id, reason, authority, examiner=None, span=None, pattern=None, replacement=None)` — `reason` and `authority` (order/agreement citation) are required; pass either `span=(start,end)` or a regex `pattern`
  - `revoke(message_id, reason, examiner=None)` — appends a new record; prior redaction keeps `revoked_at`/`revoked_by` fields so the audit trail survives
  - `apply(message_id, content)` — returns content with active span redactions + regex redactions applied; called by `ForensicAnalyzer._apply_redactions_to_messages` before reporters render
- **`EventManager(review_dir=None, session_id=None, config=None, forensic_recorder=None)`** — `src/review/event_manager.py`
  - Examiner-authored events that span a message range (`start_message_id` → `end_message_id`). Categories: `incident`, `threat`, `escalation`, `de_escalation`, `pattern`, `milestone`.
  - `add_event(title, start_message_id, end_message_id, category='incident', severity='medium', description='', start_timestamp=None, end_timestamp=None, examiner=None)` → record dict; `title` + both message_ids required; `examiner` falls back to `config.examiner_name`.
  - `edit_event(event_id, *, title=..., category=..., severity=..., description=..., start_message_id=..., end_message_id=..., reason='', examiner=None)` — append-only; `reason` mandatory; prior record keeps `superseded_by` set.
  - `remove_event(event_id, reason, examiner=None)` — append-only; `reason` mandatory; prior record keeps `removed_at` set.
  - `active_events()` — most-recent non-removed record per event_id; used by `collect_events(manual_events=...)` in the events timeline.
  - `all_records()` — full append-only history, including superseded and removed entries (for auditors).
- **`InteractiveReview(review_manager, config=None)`** — prompts for reviewer name when `EXAMINER_NAME` is unset; prompts for a reason on every rejection
- **`WebReview(review_manager, forensic_recorder=None, config=None)`** — runs Flask in daemon thread; shutdown via `threading.Event`, NOT `os.kill(SIGINT)`. `SESSION_COOKIE_SAMESITE=Strict`, HttpOnly cookies, per-session random secret key. Attachment serving is constrained to `_attachment_bases` resolved paths plus a per-request allowlist from loaded messages.

### `src/reporters/`
- **`ExcelReporter(forensic_recorder, config=None)`**
  - `generate_report(extracted_data, analysis_results, review_decisions, output_path)` → Path
  - Sheets: Overview, Findings Summary, Timeline, per-person chat tabs, Conversation Threads, Manual Review, Third Party Contacts
  - Manual Review sheet column order: `timestamp, reviewer, item_id, item_type, source, method, decision, notes, amended, supersedes, superseded_by, session_id`
  - Person1 does NOT get a per-person tab; all mapped persons get sheets even with zero messages
- **`HtmlReporter(forensic_recorder, config=None)`**
  - `generate_report(extracted_data, analysis_results, review_decisions, output_path, pdf=True)` → Dict[str, Path]
  - Renders per-finding source badges (`pattern_matched`, `ai_screened`, `extracted`, `derived`) and a source legend so readers can distinguish deterministic from AI-screened findings
- **`ChatReporter(forensic_recorder, config=None)`**
  - `generate_report(extracted_data, analysis_results, review_decisions, output_path)` → Dict[str, Path]
- **`ForensicReporter(forensic_recorder, config=None)`**
  - `generate_comprehensive_report(extracted_data, analysis_results, review_decisions)` → Dict[str, Path] with keys `word`, `methodology`, `methodology_pdf`, `pdf`, `json`, `legal_summary` (when AI summary present)
  - `_generate_methodology_pdf(extracted_data, timestamp)` — PDF version of the standalone Methodology Statement, same source sections as the DOCX; signed if a signer is configured
  - Standards Compliance section in both formats is rendered via `LegalComplianceManager.generate_standards_compliance_sections()` — structured headings + bullets + term/definition pairs, not a flat text block

### `src/utils/`
- **`TimelineGenerator(forensic, config=None)`** — minute-level chronological HTML; `create_timeline(df, output_path, raw_messages=None, extracted_data=None)` — NOT `generate_timeline()`
- **`events_timeline` module** — `src/utils/events_timeline.py`; sparse executive-view timeline for court readers
  - `collect_events(extracted_data, analysis_results, review_decisions)` → list of big-picture events only (reviewer-confirmed threats, AI threats, coercive-control clusters, local pattern clusters, sentiment shifts). Period-boundary milestones are intentionally excluded.
  - `render_events_timeline(events, output_path, config=None, case_name='', case_number='')` → Path; emits a compact timeline HTML with source badges, chronological sort, and dates resolved via ISO parse → natural-language parse → quote-match against the message corpus
- **`ConversationThreader(default_gap_hours=2.0)`**
- **`RunManifest(forensic_recorder=None, config=None)`** — when `config` is provided, its `snapshot()` is embedded under `config_snapshot`; every `.yaml` under `patterns/` is hashed into `pattern_files` at init
  - `add_input_file()`, `add_output_file()`, `generate_manifest(output_path=None)` → Path (not dict); emitted manifest is signed via the shared `_sign_if_possible` helper, producing sibling `.sig` + `.sig.pub` files
  - `add_operation()`, `validate_manifest()`, `add_extraction_summary()`, `add_analysis_summary()`, `add_report_summary()`
  - Files must exist on disk to be added
- **`Signer(key_path=None, run_dir=None)`** — `src/utils/signing.py`; loads an existing Ed25519 PEM or generates one. When `key_path` is `None`, writes an ephemeral key to `run_dir/keys/examiner_ed25519.pem` (mode 0600).
  - `sign_file(file_path)` → `(sig_path, pub_path)` writes detached `<file>.sig` (raw 64-byte Ed25519 signature) and `<file>.sig.pub` (PEM public key)
  - `verify_file(file_path)` → bool; uses the sibling `.sig` and `.sig.pub`
  - `is_ephemeral` — True when the key was generated this run
- **`contact_automapper` module** — `src/utils/contact_automapper.py`
  - `parse_vcard_file(path)`, `vcards_to_mapping(paths)`, `load_vcards_from_dir(source_dir)`, `merge_into_config(config, mapping, default_person_slot=None)`
- **`LegalComplianceManager(config)`**
  - `generate_methodology_sections()` — returns list of structured section dicts (heading/level/blocks) for real heading rendering
  - `generate_standards_compliance_sections()` — structured form of the standards statement in the same block-dict shape; used by reporters for real headings / bullets / definitions
  - `get_standards_compliance_statement()` — legacy flat-string form, retained for callers that need a plain-text block
  - `validate_completeness(messages)`

### `src/schema.py`
- TypedDicts documenting the contract between extractors, analyzers, review, reporters
- `Message`, `Finding`, `ReviewRecord`, `ThreatDetails`, `SentimentDetails`, `AnalysisResults`
- `FindingSource` Literal: `"pattern_matched" | "ai_screened" | "extracted" | "derived" | "unknown"`
- `ReviewDecision` Literal: `"relevant" | "not_relevant" | "uncertain"`
- `Message` key fields: `sender` (mapped display name), `sender_raw` (raw protocol identifier — phone/email/handle — for the sender; `None` for PERSON1), `recipient_raw` (same for recipient). All extractors populate these; reporters render `"Name (identifier)"` inline when `sender_raw` is present.
- These are documentation + type-checker hints; runtime code still uses `dict.get()` with defaults

## Developer Workflows

```bash
python3 run.py --env /path/to/.env                # Phases 1-4: extraction, analysis, review
python3 run.py --env /path/to/.env --finalize     # Phases 5-8: post-review reporting
python3 run.py --env /path/to/.env --resume       # Resume interrupted review
python3 validate_before_run.py --env /path/to/.env          # 8-check pre-run validation (spends AI credits)
python3 validate_before_run.py --env /path/to/.env --no-ai  # Validate without AI spend
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
- **Chain of custody JSON**: Has `actions` key, NOT `hashes`. Every action now carries `seq`, `prev_hmac`, `hmac`.
- **Forensic log HMAC sidecar**: `forensic_hmac_key_{session}.bin` must be archived alongside the log for independent verification. Without it the chain still validates internally but cannot be re-verified by a third party.
- **ForensicAnalyzer**: Takes `Config`, not `ForensicRecorder`. Phase methods are thin delegates to `src/pipeline/`.
- **DataExtractor.extract_all()**: Returns a flat list of message dicts, not a dict keyed by source.
- **Config**: Has no `SOURCE_DIR` attribute.
- **Config._parse_json_list**: Raises `ValueError` on malformed JSON (used to silently return `[]`). Fix your env var.
- **ai_model removed**: Use `ai_tagging_model` and `ai_summary_model` (since v4.4.0).
- **ManualReviewManager.add_review**: Requires `reviewer` (falls back to `config.examiner_name`); requires `notes` when decision is `not_relevant` or `uncertain`; raises on duplicate item_ids — use `amend_review()` to change a prior decision.
- **Working copies**: Extractors read from `run_dir/working_copies/`, NOT originals. `Config.messages_db_path` and every source directory are rewritten in place during Phase 1 to point at the verified copy.
- **PRAGMA whitelist**: `IMessageExtractor._discover_columns` refuses any table not in `_ALLOWED_SCHEMA_TABLES`. Add to the set if you need a new table.
- **Signed outputs**: Manifest, chain of custody, and every report get sibling `.sig` + `.sig.pub`. Tampering with the file breaks the signature even if the hash is recomputed.
- **SKIP_AI_TAGGING vs USE_BATCH_API**: These are different flags. `USE_BATCH_API` controls whether the Anthropic async Batch API protocol is used (cheaper/slower submissions). `SKIP_AI_TAGGING=true` skips Phase 3 per-message AI tagging entirely (threat/coercive-control classification) while still running the Phase 6 executive summary after review.
- **sender_raw / recipient_raw**: Raw protocol identifiers (phone number, email address, iMessage handle) stored on every message dict by each extractor. `None` for PERSON1's own messages. Reporters display `"Name (identifier)"` inline. Never use `sender` alone in court-facing displays — always show the raw identifier alongside the mapped name.

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
