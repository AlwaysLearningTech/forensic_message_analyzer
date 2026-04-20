# Changelog

All notable changes to the Forensic Message Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.6.0] - 2026-04-19

Event-span UI, paired DOCX/PDF for every document, app-directory .env default.

### Added
- **Examiner-authored event timeline UI.** New `src/review/event_manager.py` persists named incidents that span a message range (start_message_id → end_message_id) with title, category, severity, description, and examiner. Append-only semantics: edits and removals write new records; prior records keep their state plus `superseded_by` / `removed_at` markers so the audit trail survives. Categories: `incident`, `threat`, `escalation`, `de_escalation`, `pattern`, `milestone`.
- **Web review Events tab.** `/api/events` GET/POST/PUT/DELETE endpoints in `src/review/web_review.py` with a dedicated "Events Timeline" tab (inline form for add/edit, per-row edit/remove buttons, reason required on edits + removals, category-color badges matching the events_timeline renderer).
- **Events timeline merges manual events with auto-detected findings.** `collect_events()` takes an optional `manual_events=` list; rendered items with `authored_by_examiner` get a purple "NAMED BY EXAMINER" badge and show the full `msg-xxx → msg-yyy` range.
- **`tests/test_event_manager.py`** — 5 tests covering add / list / edit / remove, mandatory reason on edits, category + severity validation, and examiner-identity enforcement.
- **Paired DOCX + PDF for every document.** `READ_ME_FIRST` and `legal_team_summary` now emit both formats from a shared content source. `_build_cover_sheet_content` is consumed by both `_render_cover_sheet_docx` and `_render_cover_sheet_pdf`; `_generate_legal_summary_pdf` renders the narrative via reportlab using `_markdown_to_paragraphs` and `_legal_summary_report_rows` helpers shared with the DOCX version.
- **`--env PATH` CLI flag on `run.py`.** Config now accepts `env_path=` and searches `explicit-arg → DOTENV_PATH → project-root .env → cwd .env`. The project-root `.env` is the new default; users keep a per-case `.env` elsewhere with `--env`.
- **README signing-key section.** Step-by-step OpenSSL commands for generating the examiner Ed25519 keypair, exporting the public half, wiring `EXAMINER_SIGNING_KEY`, and verifying signatures.

### Changed
- **README trimmed.** Testing section, verbose directory tree, and the developer-API pointer moved to `DEVELOPER.md` (which now hosts Directory Structure, Data Flow, Testing, and System Readiness). README lists each document once as "`*` (.docx / .pdf)" instead of split entries.
- **Stale dated model IDs replaced with API aliases.** README, `forensic_reporter.py`, and `test_bugfixes.py` now reference `claude-haiku-4-5` and `claude-sonnet-4-6` instead of `claude-haiku-4-20250506` / `claude-sonnet-4-20250514`.
- **`generate_cover_sheet` returns `{'docx': Path, 'pdf': Path}`** instead of a single Path. Pipeline caller updated.
- **`generate_sample_output.py` mirrors a real run.** Produces events timeline + manual event, detailed timeline, legal summary (DOCX + PDF), READ ME FIRST (DOCX + PDF), chat-bubble HTML, all-messages CSV + XLSX, run manifest + signed artifacts — 18 signed files, all with `.sig` + `.sig.pub` siblings.

## [4.5.0] - 2026-04-19

Security, legal-defensibility, and feature-breadth push.

### Added
- **Detached Ed25519 signing** (`src/utils/signing.py`): every manifest, chain of custody, and final report gets sibling `<file>.sig` + `<file>.sig.pub`. Tampering breaks the signature even if the hash is recomputed. Set `EXAMINER_SIGNING_KEY=path/to/key.pem` for a long-lived examiner key; otherwise a per-run ephemeral key is generated under `run_dir/keys/` (mode 0600).
- **HMAC-chained forensic log**: every `record_action` entry now carries `seq`, `prev_hmac`, and `hmac` (SHA-256 HMAC over the canonical JSON of the record). Any edit, deletion, or reorder breaks the chain at the first affected line. `ForensicRecorder.verify_log_chain(log_path, key)` walks a persisted JSONL and reports the first break. Per-session key lives beside the log as `forensic_hmac_key_{session}.bin` (mode 0600).
- **Events timeline** (`src/utils/events_timeline.py`): sparse executive-view chronology for court readers, showing only reviewer-confirmed moments the case turns on. Replaces the minute-level drill-down as the default legal-team timeline (the detailed `TimelineGenerator` remains for analysts). Event dates resolve via ISO parse → natural-language parse → quote-match against the message corpus.
- **Redaction workflow** (`src/review/redaction_manager.py`): append-only span + regex redactions with required `reason`, `authority`, and `examiner` fields. Prior redactions never mutate; `revoke()` records a new entry with `revoked_at` + `revoked_by`. Applied in `run_reporting_phase` before reporters render; raw `extracted_data` JSON preserves the unredacted content for discovery challenges.
- **`source` + `method` stamping on every finding**: `items_for_review` entries now carry `source` in {pattern_matched, ai_screened, extracted, derived} and a `method` label (`yaml_patterns`, `claude-haiku-4-5`, `email_import`, etc.). Excel Manual Review sheet, HTML report, and web review UI all render a badge/column so readers can weight deterministic vs AI-screened findings.
- **DARVO + extended gaslighting patterns** in `patterns/analysis_patterns.yaml`: `darvo_deny`, `darvo_attack`, `darvo_reverse`, `gaslighting_extended`, `minimization`, each with empirical citations (Freyd 1997; Harsey & Freyd 2020; Abramson 2014; Sweet 2019).
- **EXIF / GPS / tamper-indicator scanner** in `AttachmentProcessor.extract_image_metadata`: decodes GPSInfo IFD to decimal lat/lon/alt; returns an `anomalies` list (`geolocation_present`, `edited_by:<tool>`, `datetime_mismatch`, `exif_stripped`).
- **Contact auto-mapping** (`src/utils/contact_automapper.py`): parses `.vcf` exports, merges identifiers into `config.contact_mappings` before extraction. Opt in via `CONTACTS_VCARD_DIR`.
- **Methodology PDF**: `_generate_methodology_pdf` emits `methodology_<timestamp>.pdf` alongside the `.docx`, using the same structured section source.
- **Structured Standards Compliance rendering**: `LegalComplianceManager.generate_standards_compliance_sections()` returns heading/bullet/definition blocks (previously a flat text block); reporters use the same `_render_methodology_to_*` helpers, producing real headings and structured lists in DOCX and PDF.
- **New extractors, all subclassing `MessageExtractor` (`src/extractors/base.py`)**:
  - `SMSBackupExtractor` — Android "SMS Backup & Restore" XML (sms + mms with base64-decoded attachments).
  - `CallLogsExtractor` — iOS `CallHistory.storedata`, Android call XML, generic CSV.
  - `VoicemailExtractor` — iOS `voicemail.db` + sibling `rowid.{amr,wav,m4a}` audio; surfaces on-device transcriptions.
  - `LocationExtractor` — Google Takeout Records.json, Semantic Location History, Apple plist, GPX 1.1.
- **Per-phase runner split**: `src/pipeline/{extraction,analysis,ai_batch,review,behavioral,reporting,documentation}.py`. `ForensicAnalyzer` becomes a thin delegate; `src/main.py` drops from 1435 to ~740 lines.
- **`EvidencePreserver`** (`src/utils/evidence_preserver.py`): hashing, archiving, working-copy routing, and contact auto-mapping extracted out of `ForensicAnalyzer`.
- **Working copies for all sources** (FRE 1002 best-evidence): `EvidencePreserver.route_to_working_copies` copies every configured source into `run_dir/working_copies/` and repoints `config` attributes in place. Extractors never read originals.
- **Config snapshot + pattern-file hash in manifest**: `Config.snapshot()` (api keys redacted) is embedded under `config_snapshot`; every `.yaml` under `patterns/` is hashed into `pattern_files` — proves the exact settings and rule set in force.
- **Required reviewer identity + required notes on rejection**: `ManualReviewManager.add_review` demands a named reviewer (falls back to `EXAMINER_NAME`) and refuses empty notes on `not_relevant` / `uncertain`. Re-deciding an item raises `ValueError`; use `amend_review()` which appends a superseding record without mutating the prior one.
- **TypedDict schema** (`src/schema.py`): `Message`, `Finding`, `ReviewRecord`, `ThreatDetails`, `SentimentDetails`, `AnalysisResults`, plus Literal types for `FindingSource` and `ReviewDecision`.
- **DST / Apple-epoch tests** (`tests/test_timezone_dst.py`): 11 tests covering UTC↔local round-trip across zones, spring-forward rejection, fall-back disambiguation, and Cocoa-reference-date conversion.
- **ROADMAP.md**: captures explicitly deferred work (redaction UI, Signal + Telegram extractors).

### Changed
- **Methodology section 7 expanded** with component-level Daubert disclosures: separate subsections for pattern matching, sentiment analysis, attributedBody decoding, OCR, EXIF extraction, and AI screening — each naming deterministic vs non-deterministic behavior and known failure modes.
- **`src/main.py` print() calls converted to `logger`**: 161 sites; `run.py` configures `logging.basicConfig` to stdout at INFO so user experience is unchanged. Library code no longer owns stdout.
- **`Config._parse_json_list` raises `ValueError`** on malformed JSON in `PERSON*_MAPPING`, `AI_CONTACTS`, etc. Previously silently returned `[]`, which made mapping typos invisible.
- **WhatsApp ZIP extraction hardened**: caps on uncompressed size, member count, per-member compression ratio; absolute paths and parent-directory traversal rejected. Guards against zip bombs and zip-slip.
- **`IMessageExtractor._discover_columns` whitelists table names** against `_ALLOWED_SCHEMA_TABLES` before interpolating into a PRAGMA statement.
- **Flask web-review cookies**: `SameSite=Strict`, `HttpOnly=True`, per-session random `SECRET_KEY`. Attachment serving constrained to a fixed set of base directories plus a per-request allowlist from loaded messages.
- **AI endpoint sanitization**: `_sanitize_endpoint` strips userinfo, query, and fragment before writing the endpoint to the forensic log. Embedded credentials (`https://user:token@host`) never reach chain of custody.
- **`requirements-lock.txt` added**: exact pinned versions for reproducible installs. `requirements.txt` retains `>=` constraints as a dev guide.
- **ExcelReporter Manual Review sheet column order**: `timestamp, reviewer, item_id, item_type, source, method, decision, notes, amended, supersedes, superseded_by, session_id`.
- **`RunManifest(forensic_recorder=None, config=None)`**: config is optional but recommended; when absent, `config_snapshot` is `None`.
- **`ManualReviewManager` constructor** now accepts `config` and `forensic_recorder` kwargs.
- **`WebReview` constructor** now accepts `config`.

### Fixed
- **Events timeline date resolution**: AI-flagged threats with no date field no longer render with an empty date. Dates resolve via ISO parse → natural-language parse ("early September 4") → quote-match against the message corpus.
- **Events timeline chronological sort**: previously lexicographic on mixed date formats, which placed "early September 4" after `2025-09-04T16:00:00`. Resolved ISO dates now sort correctly; undated entries sink to the end.
- **Events timeline filler removed**: period-start/period-end milestones are no longer rendered. An executive timeline should show only turning points.
- **Sample output**: `generate_sample_output.py` now emits the events timeline, methodology PDF, run manifest, and signed artifacts so the sample matches what a real run produces.

## [4.4.0] - 2026-04-19

### Added
- **One-page READ ME FIRST cover sheet** (`READ_ME_FIRST_<timestamp>.docx`): generated last in the reporting phase and references every other file by actual filename. Tells a non-technical reader which document answers which question — methodology challenges → methodology doc; plain-English findings → legal team summary; full record → forensic report PDF; transcripts → chat report; chronology → timeline; sortable data → Excel; technical audit trail → chain of custody. New `ForensicReporter.generate_cover_sheet(reports, timestamp)` method.
- **Multi-case-number support**: `CASE_NUMBER` accepts a single value OR a JSON array of strings; `CASE_NUMBERS` (plural) is also accepted as a JSON array. Each case number renders on its own line in Word, PDF, HTML, Excel, JSON, chain-of-custody, and the methodology document. New `Config.case_numbers` (list) and `Config.case_number` (newline-joined string) attributes.
- **Standalone Methodology document** (`methodology_<timestamp>.docx`): The eight-phase pipeline now emits a separate methodology document so the legal team can review the methodology in isolation. Lay-friendly, judge-readable, with a point-by-point map of how each FRE / Daubert factor is satisfied.
- **Empirical citations in `analysis_patterns.yaml`**: Comprehensive header citing the academic literature behind every pattern family (Stark 2007, Johnson 2008, Sweet 2019, Campbell 2003, Logan & Walker 2017, Woodlock 2017, Hardesty 2015, Strutzenberg 2017) plus a `citation` field on each individual threat / behavioural pattern. Patterns are now defensible as drawn from peer-reviewed sources rather than ad-hoc.
- **Cost-estimate model comparison table**: `validate_before_run.py` now prints a side-by-side table of every model in `pricing.yaml` (batch role $, summary role $, combined $) so you can compare alternatives without re-running the validator. Current selections are starred.
- **`--no-ai` flag for `validate_before_run.py`**: Skips the live AI sample test (the cost-estimate comparison table still runs). Previously referenced in instructions but not actually implemented.
- **`certifi` dependency** for SSL verification on the pricing rate lookup.
- **`DEVELOPER.md`**: New file holding the public Python API reference (every class, method, signature, usage example) that previously lived as code samples in `README.md`.

### Changed
- **`AI_MODEL` env var removed**: The two-model setup (`AI_BATCH_MODEL` + `AI_SUMMARY_MODEL`) replaces it. `Config.ai_model` attribute is gone; downstream code reads `ai_summary_model` (preferred) or `ai_batch_model`. **Action required:** remove `AI_MODEL` from your `.env` and confirm both `AI_BATCH_MODEL` and `AI_SUMMARY_MODEL` are set.
- **Methodology statement greatly expanded**: `LegalComplianceManager.generate_methodology_statement()` now produces a ~9 KB plain-language walkthrough of all eight phases plus an explicit "how each FRE / Daubert factor is satisfied" section, scope limitations, and reproducibility statement. Previously was ~1 KB of generic text.
- **Standards-compliance statement rewritten** in plain language with concrete "how each standard was satisfied" explanations.
- **Forensic-report timestamps are now human-readable**: Word/PDF "High Priority Threats" entries and the Chain-of-Custody session-start use `compliance.convert_to_local()` (timezone-aware, no raw ISO/`isoformat()`).
- **AI-Detected Threats subsection removed from forensic report**: Word and PDF no longer carve out a separate "AI-Detected Threats" block; the dedicated section heading and the "AI-assisted findings are supplementary" preamble are gone. All flagged items go through the same manual-review process; the report addresses review findings, not the source of the flag. Excel "AI-Identified Threat" rows are now plain "Threat" rows.
- **`pricing.yaml` is editable by hand**: The auto-generated header now explicitly says manual edits ARE the intended fallback when the live fetch is unavailable, instead of the previous "do not edit by hand" warning. Also applies to the existing cached file.
- **README slimmed**: API code samples and individual-component reference moved to [`DEVELOPER.md`](DEVELOPER.md); `README.md` now points there.

### Fixed
- **SSL errors on macOS pricing rate lookup**: `_fetch_pricing_page` now uses a `certifi`-backed SSL context, fixing `CERTIFICATE_VERIFY_FAILED` errors on macOS Python installs and corporate proxies. Failures are logged at info level (no scary traceback in normal output).
- **Tests**: `test_bugfixes.test_accepts_config` and `test_batch_model_default` updated to reflect the new model-resolution rules (no more `AI_MODEL` fallback). All tests in `test_bugfixes.py`, `test_forensic_utils.py`, `test_core_functionality.py`, `test_teams_extractor.py`, and `test_third_party_registry.py` pass.

## [4.3.1] - 2026-03-04

### Changed
- **Legal team summary output format**: Upgraded from plain `.txt` to formatted `.docx` Word document with case header, Calibri 11pt body, and compliance footer. More professional for attorney distribution.
- **README phase descriptions**: Updated to accurately reflect the 8-phase pipeline (Phases 1-4 in `run.py`, Phases 5-8 in `run.py --finalize`), added `--finalize` and `--resume` usage examples.

## [4.3.0] - 2026-03-02

### Added
- **iMessage edit history extraction**: Parses `message_summary_info` BLOB (iOS 16+ binary plist) to recover original text and intermediate edits before the final version. Each edit event includes timestamp and decoded content. Forensically critical for detecting post-hoc message editing (e.g., editing a threatening message to appear benign)
- **Recently deleted message recovery**: Queries `chat_recoverable_message_join` table (iOS 16+) to identify and recover messages deleted within ~30 days. Flags messages already in the main extraction as `is_recently_deleted` and separately recovers orphaned deleted messages not in the primary query
- **URL preview / rich link metadata**: Extracts `payload_data` BLOB from messages with `URLBalloonProvider` balloon type. Parses `richLinkMetadata` binary plist for URL, title, summary, site name, and original URL
- **Shared location extraction**: Detects shared locations within rich link metadata via `specialization2.address` presence. Extracts location name, address, city, state, postal code, country, and street from `addressComponents`
- **Per-chat properties BLOB parsing**: Parses `chat.properties` binary plist column for per-chat settings: `chat_read_receipts_enabled` (whether read receipts are on/off for this specific chat) and `chat_force_sms` (whether iMessage was disabled forcing SMS)
- **Time-until-read computation**: Calculates human-readable delay between message sent and read timestamps ('2m 30s', '1h 15m', '2d 3h'). Enables forensic analysis of response latency patterns
- **Edit history display in reports**: Chat-bubble and HTML reports render edit history below edited messages, showing "Original" text with timestamp and any intermediate edits. Excel report adds `edit_history_text` column
- **Deleted message badge**: Red "Deleted" badge in chat-bubble and HTML reports for recently deleted messages
- **URL preview rendering**: Blue-bordered URL preview blocks in chat-bubble and HTML reports showing title, site name, and URL
- **Shared location rendering**: Green-bordered location blocks in chat-bubble and HTML reports showing location name and address

### Changed
- **IMessageExtractor constructor**: Now accepts optional `config` parameter (`config=None`) for access to contact mappings
- **Forensic logging**: Extraction metadata now includes `edit_history_count`, `deleted_count`, and `sos_count` alongside existing `tapback_count`, `edited_count`, and `retracted_count`
- **Schema-safe table discovery**: Extractor queries `sqlite_master` to check for `chat_recoverable_message_join` table existence before attempting deleted message recovery

## [4.2.0] - 2026-03-02

### Added
- **Chat-bubble HTML reporter**: New iMessage-style `ChatReporter` with left/right aligned message bubbles, per-person sections, inline attachment images, and threat/sentiment indicators (`src/reporters/chat_reporter.py`)
- **Excel Findings Summary sheet**: Rewritten with verifiable timestamps, confirmed threats, AI-identified risk indicators, pattern detections, and recommendations
- **Excel Timeline sheet**: Chronological case event timeline including threats, SOS messages, pattern detections, sentiment shifts, email communications, and third-party email corroboration
- **Legal appendices in HTML report**: Appendix A (Methodology Statement), Appendix B (Completeness Validation with gap detection and one-sided conversation flags), Appendix C (Limitations)
- **Case chronology timelines**: Both HTML interactive timeline and Excel Timeline sheet now include all email messages alongside flagged events — emails between mapped persons labeled "Email", emails involving unmapped contacts (counselors, attorneys, family) labeled "Third-Party Email" with distinct visual styling
- **All mapped persons get output**: Every mapped person gets a tab/section in Excel, HTML, and chat-bubble reports even when they have zero messages (documents absence of communication for legal completeness)
- **Attachment preservation with hash verification**: Original attachments copied with SHA-256 verification per FRE 1002 Best Evidence Rule
- **Per-run output isolation**: Each analysis run creates a timestamped subdirectory to prevent file comingling across runs
- **Expanded integration tests**: 50+ synthetic messages covering iMessage, WhatsApp, email (mapped and third-party), with images, tapbacks, emoji, SOS, unsent, and edge cases; legal appendix and person3 coverage assertions

### Changed
- **Preserve original image format**: HTML report inlines images in their original format (PNG, HEIC, etc.) instead of converting all to JPEG
- **Validation pipeline flow**: Data now flows phase-to-phase without re-running analysis; `validate_before_run.py` generates reports from ALL messages instead of 5-message AI sample
- **Timeline generator signature**: `create_timeline()` and `generate_html_timeline()` now accept optional `extracted_data` parameter for email event inclusion
- **.env.example synced**: All env vars read by `config.py` now documented in `.env.example`
- **Non-capturing groups in threat patterns**: Suppresses pandas FutureWarning about regex capture groups

### Fixed
- **Excel Date Range bug**: Overview sheet date range calculation corrected
- **Per-run .jsonl file leak**: Forensic recorder log files now written inside per-run output directory instead of repo root
- **HTML image compression**: Fixed quality degradation from aggressive JPEG recompression
- **Test file leaks**: All tests now use `tmp_path` fixture for output, preventing leftover files in repo directory
- **ManualReviewManager leak in validation**: Validation script passes `forensic_recorder` to prevent orphaned log files

## [4.1.1] - 2026-02-24

### Added
- **RunManifest pipeline integration**: `main.py` now calls `add_operation()` and `add_output_file()` for extraction, analysis, review, and reporting phases so the run manifest captures actual pipeline data
- **AI notable_quotes deduplication**: Deduplicates notable quotes across batch boundaries in `ai_analyzer.py`, and merges them properly in `_merge_batch_results`
- **Missing dependencies**: Added `jinja2` and `weasyprint` to `requirements.txt` (imported by `html_reporter.py` but previously unlisted)

### Changed
- **Config propagation**: All reporter, timeline, and review constructors now receive the pipeline's `Config` instance instead of creating their own via module-level singletons
- **Shared forensic recorder**: `ManualReviewManager` accepts an optional `forensic_recorder` parameter so review actions appear in the same chain-of-custody log as the rest of the pipeline
- **Timezone-aware timestamps**: All `datetime.fromtimestamp()` calls across `forensic_utils.py`, `run_manifest.py`, and `legal_compliance.py` now pass `tz=timezone.utc` to produce timezone-aware ISO strings
- **Local timezone display**: All UTC timestamps in reports, Excel sheets, and HTML output are converted to the configured local timezone for human-readable display
- **Excel report tabs**: Person 1 no longer gets a redundant tab since every other tab already shows their conversations with each mapped contact
- **Conversation threading performance**: `get_threaded_export()` computes conversations once and passes precomputed data to `detect_threads()` and `generate_conversation_summaries()`, eliminating 3x redundant grouping and 2x redundant thread detection
- **Legal compliance hashing**: `legal_compliance.py` now uses `self.forensic.compute_hash()` instead of a private `_compute_sha256()` method, so all hashes are logged in the chain of custody

### Fixed
- **JSON serialization failures**: Added `default=str` to `json.dumps()` in `ForensicRecorder.record_action()` and `json.dump()` in `generate_chain_of_custody()` and `create_evidence_package()` to handle non-serializable types (datetime, Path, etc.)
- **Relative imports in manual_review_manager**: Changed `from src.forensic_utils` to `from ..forensic_utils` (and same for config) for proper package resolution
- **Web review None serialization**: Moved `serialized.append(s)` inside the `if s:` block in both `_api_browse_page` and `_api_search_page` to prevent `None` entries in JSON responses
- **message_id type mismatch**: Normalized `message_id` comparisons in `conversation_threading.py` to `str()` on both sides, fixing int (iMessage) vs str (timeline_generator) mismatch that caused context lookups to always fail
- **Variable shadowing in forensic_reporter**: Renamed loop variable `sources` to `entry_sources` in both Word and PDF generation methods to avoid shadowing the outer `sources` set tracking message data sources
- **Validation log contamination**: `validate_before_run.py` now uses a temp directory for its `ForensicRecorder` instead of the production output directory
- **Module-level Config singletons**: Removed `Config()` instantiation at import time in `json_reporter.py` and `html_reporter.py` which caused crashes when `.env` was absent
- **UTC timestamp display**: Fixed attachment_processor and forensic_reporter showing raw UTC timestamps instead of local timezone
- **Screenshot timestamps**: Reverted screenshot timestamps to display in local time rather than UTC

## [4.1.0] - 2026-02-23

### Added
- **End-to-end pipeline validation**: Test 8 in `validate_before_run.py` runs auto-review, filtering, and report generation against temp data
- **Interactive cleanup prompt**: Validation script now shows temp directory path and asks before deleting, so test output can be reviewed
- **Batch polling timeout**: 4-hour max wait on batch API polling loop prevents infinite blocking
- **Sync fallback guard**: Detects batch failures that occur after submission (timeout, partial) and refuses to re-run via sync, preventing double billing
- **Sentiment overall computation**: Computes overall sentiment (positive/neutral/negative) from accumulated scores across batches
- **Key topics deduplication**: Deduplicates topics across batch boundaries
- **Empty extraction abort**: Pipeline aborts before AI analysis if zero messages were extracted, preventing waste of API credits
- **Empty dataset guard in legal summary**: Skips AI-generated legal summary when there are no messages, saving API credits

### Changed
- **WebReview shutdown**: Flask now runs in a daemon thread with `threading.Event`-based shutdown instead of `os.kill(SIGINT)`, which was killing the entire parent pipeline
- **Attachment serving**: `/attachments/` route now uses an allowlist built from actual message attachments instead of serving arbitrary filesystem paths
- **Email message IDs**: Fallback IDs use deterministic SHA-256 hash of filename + date + subject instead of non-reproducible `id(msg)` memory addresses
- **Email timestamp sorting**: Normalizes all timestamps to UTC via `pd.to_datetime(utc=True)` before sorting, preventing TypeError on mixed tz-aware/naive datetimes
- **WhatsApp message parsing**: Uses `finditer` with continuation-line capture between message boundaries instead of `findall`, preserving multiline message content
- **Teams timestamp parsing**: Converts raw ISO 8601 strings to proper datetime objects via `pd.to_datetime(utc=True)`, fixing cross-source sorting

### Fixed
- **Anthropic API 401 authentication**: VS Code injects `ANTHROPIC_BASE_URL=http://localhost:...` which the SDK reads even with explicit `api_key`. Fixed by always passing `base_url="https://api.anthropic.com"` in both `ai_analyzer.py` and `forensic_reporter.py`
- **iMessage timestamps off by UTC offset**: SQL query had `'localtime'` modifier converting UTC to local time, then Python re-interpreted as UTC. Removed `'localtime'` so timestamps stay in UTC
- **SQLite connection leak in iMessage extractor**: Wrapped processing in `try/finally` to ensure `conn.close()` is called
- **Empty contact mappings crash**: Added guard against empty `IN ()` clause in iMessage SQL query
- **Excel tz_localize TypeError**: Changed `dt.tz_localize(None)` to `dt.tz_convert(None)` for already tz-aware columns
- **PDF crash on special characters**: Added `html.escape()` to all user content in ReportLab `Paragraph()` calls, preventing XML parse errors from `<`, `>`, `&` in messages
- **Excel NaN column width**: Added `pd.isna()` guard for column width calculation when DataFrame has NaN values
- **JSON report unprotected**: Wrapped JSON report generation in try/except
- **Chain of custody None handling**: Added null guard so `None` return from `generate_chain_of_custody()` doesn't corrupt result dict
- **Timeline XSS**: HTML-escaped all user content (sender names, message text) in `timeline_generator.py`
- **BehavioralAnalyzer ZeroDivisionError**: Added `len(df) == 0` guard in `_analyze_communication_style` and `_comprehensive_threat_assessment`
- **Path traversal vulnerability**: `/attachments/<path:filename>` route in `web_review.py` could serve any file on disk; now restricted to allowlist of actual message attachments

### Security
- **Path traversal in web review**: Replaced open filesystem access with allowlist-based attachment serving
- **XSS in timeline HTML**: All user content now escaped before insertion into HTML output

## [4.0.0] - 2026-02-22

### Added
- **Anthropic Claude AI Analysis**: Switched from Azure OpenAI to Anthropic Claude Opus 4.6 with Batch API (50% cost discount) and prompt caching
- **Report Filtering by Review Decisions**: Analysis reports (Word, PDF, HTML, Excel, JSON) now only include threats and risk indicators that were explicitly approved during manual review. Unreviewed and rejected findings are cleared before reports are generated. Forensic all-messages export (CSV/Excel) remains unfiltered for chain of custody.
- **HTML/PDF Report Generation**: New Jinja2-based HTML reporter with WeasyPrint PDF conversion, inline base64 images, overview cards, per-person message tables, conversation threads, and legal compliance footer
- **iMessage Attachment Extraction**: Query message_attachment_join + attachment tables for image paths, resolve macOS ~ paths, attach first image per message for inline display
- **WhatsApp Attachment Detection**: Detect `<attached: FILENAME>` pattern in messages, resolve file paths relative to chat export directory
- **Web Review Attachment Display**: New `/attachments/` route serves both iMessage and WhatsApp images inline in the chat UI
- **Interactive Review Photo Display**: CLI review shows `PHOTO: /path` for messages with image attachments
- **Batch API with Prompt Caching**: System prompt cached with `cache_control: ephemeral` across all API calls; batch and sync modes both benefit
- **AI Contact Filtering**: `AI_CONTACTS` config limits which conversations are sent for AI analysis (reduces cost)
- **Third-Party Contact Registry**: Tracks contacts discovered in emails/screenshots not in configured person mappings, with O(1) dedup
- **Email Extractor**: Extract messages from email source files with third-party contact detection
- **Teams Extractor**: Extract messages from Microsoft Teams exports with third-party contact detection
- **Pre-Run Validation Script**: `validate_before_run.py` checks config, data sources, and estimates cost before committing to a full run
- **Unedited Forensic Export**: CSV + Excel export of all messages prior to any filtering, for chain of custody
- **WhatsApp ZIP Auto-Extraction**: Automatically extracts ZIP files in WhatsApp source directory
- **Recipient Tracking**: All messages include both sender and recipient fields
- **attributedBody Binary Decoding**: Modern iMessage format with binary-encoded messages properly decoded
- **WhatsApp Timestamp Formats**: 12 timestamp formats including seconds (e.g., "3/8/22, 4:12:34 PM")

### Changed
- **AI Model**: Azure OpenAI → Anthropic Claude Opus 4.6 (direct API)
- **AI Processing Mode**: Default to Batch API with server-side rate limiting; sync mode as fallback with configurable client-side rate limits
- **Batch Pricing**: Corrected from Opus 4.0 rates ($7.50/$37.50) to Opus 4.6 rates ($2.50/$12.50 per MTok)
- **Rate Limit Configuration**: `MAX_REQUESTS_PER_MINUTE`, `TOKENS_PER_MINUTE`, `REQUEST_DELAY_MS` now configurable via .env (previously hardcoded); only apply to sync fallback mode
- **Batch Size**: Default 50 messages per analysis request (batch API submits all in single HTTP call, no rate-limiting reason for smaller batches)
- **MAX_TOKENS_PER_REQUEST**: Increased from 2048 to 4096 — actual AI output averaged ~1,600 tokens/batch, 2048 caused truncation and JSON parse failures
- **'Me' Normalization**: Extractors assign 'Me' for device owner; `data_extractor.py` normalizes to PERSON1_NAME in one place
- **WhatsApp Recipient Detection**: Uses first-pass sender scan instead of filename parsing
- **Excel Report Structure**: Individual tabs per configured person with integrated threat/sentiment columns
- **Output Directory**: ForensicRecorder uses configured output directory instead of ./output/ in repository
- **Version**: Updated to 4.0.0 across run_manifest, forensic_utils, and __init__

### Fixed
- **AI Analyzer Pricing**: Cost estimates were using Opus 4.0/4.1 batch rates (3x too high)
- **AI Merge KeyError**: `_init_analysis_results` initialized `behavioral_patterns` and `threat_assessment` as empty dicts `{}` instead of having subkeys (`patterns`, `anomalies`, `details`). This caused `_merge_analysis` to crash with `KeyError: 'patterns'` on every batch result, wasting all API spend.
- **AI Output Token Estimate**: Was 385 tokens/batch (4x too low); actual averaged ~1,600. Cost estimates showed $7.68 when actual was $20.81. Corrected in both ai_analyzer.py and validate_before_run.py.
- **AI Error Swallowing**: `_analyze_batch` silently caught exceptions and returned `{}`, so the sync loop couldn't detect API failures. Now returns `{"_error": ...}` and errors appear in processing_stats and validation output.
- **Review Phase Contact Filtering**: Threat review queue included messages from unmapped phone numbers. Added `_is_mapped()` filter matching the same contact logic as AI analysis.
- **Reports Ignoring Review Decisions**: All four reporters (Excel, Word/PDF, HTML, JSON) included all analysis findings regardless of review decisions. Reports now only include human-verified findings.
- **Cache Token Tracking**: `cache_creation_input_tokens` was incorrectly added to `cache_read_tokens` counter; now tracked separately with correct per-type pricing
- **Threat Analyzer Performance**: Replaced `iterrows()` loop with vectorized `str.contains()` using pre-compiled regex per category
- **Sentiment Analyzer**: Fixed `www.\S+` regex (missing backslash), added `dropna()` guard for `idxmax()`/`idxmin()` on empty series
- **Behavioral Analyzer**: Fixed `mode()[0]` crash when series is empty
- **Excel Column Naming**: Fixed overflow beyond column Z (chr(65+i) only works for A-Z); replaced with proper base-26 conversion
- **Data Extractor Null Guards**: Added `if self.imessage:` / `if self.whatsapp:` etc. guards and `or []` coalescing on extractor returns
- **WhatsApp Recipient**: Person1's messages had recipient=Person1 instead of Person2
- **Contact Filter**: Require BOTH parties mapped (AND not OR)
- **Timezone Handling**: Fixed tz-naive vs tz-aware datetime comparison crashes in communication metrics and participant analysis
- **Token Counting**: Fixed estimated token counts for cost reporting

### Removed
- **QUICK_START.md**: Outdated (referenced Azure OpenAI, missing files, wrong paths)
- **debug_pairs.py**: Debug script no longer needed
- **debug_sources.py**: Debug script no longer needed
- **Dead Code**: Removed unused `import re` and `_PHONE_RE` from third_party_registry.py

## [1.0.0] - Initial Release

### Core Features
- Multi-phase workflow: Extraction → Analysis → Review → Reporting → Documentation
- iMessage extraction with modern format support
- WhatsApp export processing
- Screenshot OCR analysis with Tesseract
- Threat detection with configurable patterns
- Sentiment analysis
- Behavioral pattern analysis
- Communication metrics calculation
- Manual review workflow
- Multiple report formats (Excel, Word, PDF, JSON, HTML timeline)
- Forensic integrity (SHA-256 hashing, chain of custody)
- Legal compliance (FRE 901/1002/803, Daubert factors)
- Contact mapping with automatic phone number normalization
- Data separation (code vs. data directories)
- Comprehensive configuration via .env files

### Reports Generated
- Excel: Multi-tab reports with statistics and analysis
- Word: Comprehensive forensic report with executive summary
- PDF: Court-ready document with full analysis
- JSON: Raw data and analysis results
- HTML: Interactive timeline visualization
- Chain of Custody: Complete audit trail
- Run Manifest: Process documentation

### Legal Defensibility
- FRE 901 (Authentication): SHA-256 hashing, timestamps, chain of custody
- FRE 1002 (Best Evidence): Metadata preservation, working copies
- FRE 803 (Business Records): Creation metadata retention
- Daubert Factors: Testing, peer review, error rates, standards, acceptance
- SWGDE/NIST guidelines compliance

---
