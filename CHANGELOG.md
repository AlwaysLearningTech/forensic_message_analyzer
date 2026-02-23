# Changelog

All notable changes to the Forensic Message Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

For detailed technical changes, see [IMPROVEMENTS_LOG.md](IMPROVEMENTS_LOG.md).
For code review findings, see [CODE_REVIEW.md](CODE_REVIEW.md).
