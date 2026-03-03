# Changelog

All notable changes to the Forensic Message Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **WhatsApp Recipient**: David's messages had recipient=David instead of Marcia
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
