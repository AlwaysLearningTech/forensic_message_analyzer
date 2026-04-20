# Forensic Message Analyzer

A comprehensive digital forensics tool for analyzing message data from multiple sources, designed for legal defensibility and evidence integrity.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Data Separation Strategy](#data-separation-strategy)
- [Usage](#usage)
- [Legal Defensibility](#legal-defensibility)
- [Architecture](#architecture)
- [Testing](#testing)
- [Output Files](#output-files)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Forensic Message Analyzer is a multi-phase digital evidence processor designed for legal use. It extracts, analyzes, and reports on message data from iMessage, WhatsApp, email, Microsoft Teams, and screenshots while maintaining a complete chain of custody for court admissibility.

## Features

### Data Extraction
- **iMessage**: Direct extraction from macOS Messages database with `attributedBody` decoding
  - Extracts modern binary message format (NSAttributedString)
  - Maps contacts to configured person names
  - Includes sender and recipient tracking for conversation analysis
  - Filters tapbacks and system messages (associated_message_type 2000-3007)
  - **Edit history recovery** (iOS 16+): Parses `message_summary_info` BLOB to extract original text and intermediate edits before the final version
  - **Recently deleted message recovery** (iOS 16+): Queries `chat_recoverable_message_join` to recover messages deleted within ~30 days
  - **URL previews / rich links**: Extracts link metadata (title, summary, URL, site name) from `payload_data` BLOB
  - **Shared locations**: Detects and extracts shared location details (name, address, city, state) from rich link metadata
  - **Per-chat properties**: Parses `chat.properties` BLOB for per-chat read receipt settings and SMS force flags
  - **Time-until-read**: Computes human-readable delay between message sent and read timestamps
  - **Forensic timestamps**: Extracts `date_read`, `date_delivered`, `date_edited`, `date_retracted` with Apple epoch nanosecond conversion
- **WhatsApp**: Automatic ZIP extraction and import from exported chat files
  - Auto-extracts ZIP archives (e.g., WhatsApp_SourceFiles.zip)
  - Supports multiple timestamp formats (with/without seconds)
  - Maps participants to configured person names
  - Includes recipient field for conversation filtering
- **Email**: MIME-based extraction from `.eml` and `.mbox` files
  - Full MIME parsing with header extraction (From, To, Subject, Date)
  - Automatic contact resolution against configured person mappings
  - Third-party contact detection for unmapped senders/recipients
  - Support for multipart messages and text/plain content extraction
- **Microsoft Teams**: Personal export TAR archive processing
  - Parses `messages.json` from Teams personal data exports
  - Sender identification via userId and displayName fields
  - Mapped-persons-only conversation filtering (same approach as iMessage)
  - HTML tag stripping from RichText/Html messages
  - Filters out system messages (ThreadActivity, Event/Call)
  - Infers senders in 1:1 conversations where identity is not explicit
- **Screenshots**: Catalog and OCR processing with contact extraction
- **Attachments**: Full metadata preservation plus EXIF / GPS / tamper-indicator scanning (flags `geolocation_present`, `edited_by:<tool>`, `datetime_mismatch`, `exif_stripped`)
- **SMS backup (Android)**: Parses the "SMS Backup & Restore" XML format (SMS + MMS); MMS attachments base64-decoded for hashing and EXIF scanning
- **Call logs**: iOS `CallHistory.storedata` (SQLite), Android call XML, and generic CSV with direction and contact auto-resolution
- **Voicemail**: iOS `voicemail.db` plus sibling audio files and on-device transcriptions
- **Location data**: Google Takeout Records.json + Semantic Location History, Apple plist, and GPX 1.1 (unified point-record shape for cross-referencing against message timestamps)

### Analysis Capabilities
- **Threat Detection**: Pattern- and keyword-based threat identification with configurable thresholds
- **Pattern Analysis**: YAML-based configurable patterns for behavioral detection
- **Sentiment Analysis**: Message tone and emotion detection using TextBlob
- **Behavioral Analysis**: Communication pattern identification and profiling
- **Communication Metrics**: Frequency, volume, timing, and response pattern analysis
- **Manual Review**: Every flagged item is reviewed and confirmed by a human examiner before it appears in the final reports

### Optional AI Assistance

The analyzer can optionally use Anthropic Claude (configurable via `.env`) to:

- Pre-screen messages for threat indicators during the local analysis phase, surfacing additional candidates for the examiner's manual review queue. The examiner — not the model — decides what is included in the final reports.
- Draft the executive summary narrative and legal-team reading guide *after* manual review is complete, working only from the messages the examiner confirmed.

AI is one tool in the workflow; nothing reaches a final report without human confirmation. The methodology document distributed with each run describes exactly how AI was used (model, phase, inputs, reviewer override). To run the pipeline without AI, leave `AI_API_KEY` unset — the local analyzers, manual review, and reporting all run without it.

### Legal Compliance
- **Chain of Custody**: Complete audit trail with SHA-256 hashing; forensic JSONL log is HMAC-chained (`seq` + `prev_hmac` + `hmac` on every record) so edits, deletions, or reorders break the chain. Per-session HMAC key written to a `0600` sidecar file for independent verification.
- **Evidence Integrity**: Every source is copied to `run_dir/working_copies/` with hash verification before extraction reads it. Originals are never opened during analysis.
- **Signed outputs**: Manifest, chain of custody, and every final report get detached Ed25519 signatures (`<file>.sig` + `<file>.sig.pub`). Set `EXAMINER_SIGNING_KEY` for a long-lived examiner key, or let the analyzer generate a per-run ephemeral key.
- **Reviewer accountability**: Manual review requires a named reviewer (configurable via `EXAMINER_NAME`); rejections and uncertainty decisions require explanatory notes; prior decisions are append-only (amendments preserve the original record).
- **Source provenance on every finding**: Reports stamp each item with `source` in {`pattern_matched`, `ai_screened`, `extracted`, `derived`} and a `method` label so readers can distinguish deterministic findings from AI-screened ones.
- **Manifest reproducibility**: Full config snapshot (API keys redacted) and SHA-256 hash of every pattern YAML are embedded in the run manifest.
- **Redaction workflow**: Court-ready exhibits can carry span- or regex-based redactions with required `reason`, `authority`, and `examiner` fields; raw extracted JSON preserves the unredacted content for discovery.
- **FRE Compliance**: Meets Federal Rules of Evidence requirements (FRE 901, 803, 1001-1008, 106).
- **Daubert Standards**: Testable, reproducible, documented methodology with component-level error-rate disclosures.
- **Conversation Filtering**: Reports show only legally relevant parties (configured in .env).

### Reporting
- **Excel Reports**: Organized by person with integrated threat/sentiment data
  - Separate tabs for each configured person
  - Each tab combines messages, threats, and sentiment in one view
  - Excludes conversations with non-relevant parties
- **Word/PDF Reports**: Comprehensive analysis with:
  - Legal team summary (plain-language narrative for attorneys)
  - Executive summary
  - Data extraction statistics
  - Threat analysis with high-priority examples
  - Sentiment distribution (Positive/Neutral/Negative)
  - Manual review breakdown
  - Chain of custody reference
- **Forensic Export**: Unedited, unfiltered CSV and Excel export of all messages for court admissibility
- **HTML/PDF Reports**: Inline base64 images, per-person message tables, conversation threads, risk indicators, legal compliance footer, legal appendices (Methodology, Completeness Validation, Limitations), edit history display for edited messages, URL preview and shared location rendering, deleted message flags (PDF via WeasyPrint)
- **Chat-Bubble Reports**: iMessage-style chat-bubble HTML report with left/right aligned message bubbles, per-person sections, inline attachments, threat/sentiment indicators, edit history display, URL preview and shared location blocks, deleted message badges
- **Timelines**: Two formats. A sparse "events timeline" for court readers — shows only reviewer-confirmed moments the case turns on (confirmed threats, coercive-control clusters, sentiment shifts, pattern clusters) with category badges and chronological order. A minute-level detailed timeline for analyst drill-down — every flagged event plus all email correspondence including third-party corroboration (counselors, attorneys, family).
- **Methodology PDF + DOCX**: Standalone Methodology Statement in both formats with structured standards-compliance rendering (headings, bulleted list of standards, term/definition pairs for how each is satisfied) — not a flat text block.
- **Manual Review**: Structured decision tracking with required reviewer identity, mandatory notes on rejections, and append-only amendments.
- **Run Manifest**: Complete documentation of analysis process, embedded config snapshot, pattern-file hashes, signed with detached Ed25519.

## Installation

### Prerequisites
- Python 3.8 or higher
- macOS (for iMessage extraction)
- Tesseract OCR (for screenshot text extraction)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/AlwaysLearningTech/forensic-message-analyzer.git
cd forensic-message-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install Tesseract OCR:
```bash
# macOS
brew install tesseract

# Ubuntu/Debian
sudo apt-get install tesseract-ocr

# Windows
# Download from: https://github.com/UB-Mannheim/tesseract/wiki
```

## Configuration

The `.env` file is stored **outside the repository** for security. The system looks for it in:
1. `~/workspace/data/forensic-message-analyzer/.env` (primary location)
2. Path specified in `DOTENV_PATH` environment variable
3. Local `.env` in the project directory (not recommended)

### Setting Up Configuration

1. Create the data directory structure:
```bash
mkdir -p ~/workspace/data/forensic-message-analyzer
```

2. Copy the example configuration to the data directory:
```bash
cp .env.example ~/workspace/data/forensic-message-analyzer/.env
```

3. Edit `~/workspace/data/forensic-message-analyzer/.env` with your settings:
```bash
# Anthropic Claude API key (optional — enables pre-review screening and AI executive summary)
AI_API_KEY=your-api-key
# Two-model setup (the legacy single AI_MODEL was removed in v4.4.0):
AI_BATCH_MODEL=claude-haiku-4-20250506      # cheap; per-message classification
AI_SUMMARY_MODEL=claude-sonnet-4-20250514   # higher quality; executive summary

# Case identification — single value OR JSON array for consolidated runs.
# CASE_NUMBERS (plural) is also accepted as a JSON array.
CASE_NUMBER='["2024-FL-12345","2024-FL-67890"]'
EXAMINER_NAME="Jane Doe"
CASE_NAME="Smith v. Smith"

# Contact Mapping - Define names for reports and their identifiers
PERSON1_NAME="First Last"
PERSON1_MAPPING='["+12345678901","email@example.com","FirstName","Full Name"]'
PERSON2_NAME="Another Person"
PERSON2_MAPPING='["+19876543210","another@example.com","AnotherName"]'
PERSON3_NAME="Third Person"
PERSON3_MAPPING='["third@example.com","ThirdName","Nickname"]'

# Data Sources (comment out or remove any you don't have)
MESSAGES_DB_PATH=~/Library/Messages/chat.db
WHATSAPP_SOURCE_DIR=~/workspace/data/forensic-message-analyzer/source_files/whatsapp/
SCREENSHOT_SOURCE_DIR=~/workspace/data/forensic-message-analyzer/source_files/screenshots/
EMAIL_SOURCE_DIR=~/workspace/data/forensic-message-analyzer/source_files/email/
TEAMS_SOURCE_DIR=~/workspace/data/forensic-message-analyzer/source_files/microsoft_teams_personal/
```

## Data Separation Strategy

### Security Architecture

The project implements a strict separation between code and data to prevent sensitive information from being accidentally committed to version control:

```
Repository (GitHub)              Local Data Storage
├── src/                        ~/workspace/data/forensic-message-analyzer/
├── tests/                      ├── .env (configuration with keys)
├── patterns/                   ├── source_files/
├── .env.example                │   ├── whatsapp/
└── README.md                   │   ├── screenshots/
                               │   ├── email/
                               │   └── microsoft_teams_personal/
                               ├── review/ (manual review decisions)
                               └── logs/

                               ~/workspace/output/forensic-message-analyzer/
                               └── [all analysis outputs]
```

### Key Principles

1. **Code Repository** (`/workspace/repos/forensic-message-analyzer/`):
   - Contains only source code, tests, and documentation
   - `.env.example` provides template without sensitive data
   - `.gitignore` excludes all data directories

2. **Data Storage** (`/workspace/data/forensic-message-analyzer/`):
   - Holds actual `.env` with credentials
   - Contains source files for analysis
   - Stores review decisions and logs
   - Never tracked in version control

3. **Output Storage** (`/workspace/output/forensic-message-analyzer/`):
   - All analysis results and reports
   - Chain of custody documents
   - Separate from both code and input data

### Setting Up Data Directories

```bash
# Create data directory structure
mkdir -p ~/workspace/data/forensic-message-analyzer/{source_files,review,logs}
mkdir -p ~/workspace/data/forensic-message-analyzer/source_files/{whatsapp,screenshots,email,microsoft_teams_personal}
mkdir -p ~/workspace/output/forensic-message-analyzer

# Copy and configure .env
cp .env.example ~/workspace/data/forensic-message-analyzer/.env
# Edit the .env file with your actual configuration
```

## Usage

### Pre-Run Validation and Cost Estimation

Before running the full analysis (which incurs AI API costs), use the validation script to verify your configuration, test all analysis phases, and get a cost estimate:

```bash
# Full validation with 5-message AI test (~$0.01)
python3 validate_before_run.py

# Just show extraction stats and cost estimate ($0 cost)
python3 validate_before_run.py --estimate

# Skip AI test entirely ($0 cost)
python3 validate_before_run.py --no-ai

# Test with a custom number of messages
python3 validate_before_run.py --ai-sample 10
```

The script runs 8 checks:
1. **Config validation** - Verifies .env settings
2. **Contact mappings** - Confirms person identifiers are configured
3. **Data extraction** - Extracts from all sources (free, local-only)
4. **Mapped-contact filter** - Shows how many messages will be sent to AI vs skipped
5. **Non-AI analysis** - Runs threat, sentiment, behavioral, and pattern analyzers
6. **Cost estimate** - Calculates expected Batch API cost for your configured models AND prints a comparison table for every model in `pricing.yaml` so you can see what swapping models would cost without re-running the validator
7. **AI test** - Sends a small sample to Claude to verify token counting works
8. **End-to-end pipeline** - Runs auto-review, filtering, and report generation with temp data; prompts before cleanup so you can inspect output

### Full Analysis Pipeline

The analysis runs in two steps. First, extract, analyze, and review:
```bash
python3 run.py
```

This executes Phases 1-4 (extraction through review):
1. **Data Extraction**: Collects messages from all sources (iMessage, WhatsApp, email, Teams, screenshots)
   - Automatically extracts ZIP files (e.g., WhatsApp_SourceFiles.zip) and TAR archives (Teams exports)
   - Decodes modern iMessage binary format (attributedBody)
   - Parses email MIME format (.eml, .mbox) with header extraction
   - Processes Microsoft Teams personal export JSON with sender identification
   - Maps all participants to configured person names
   - Adds sender and recipient fields to all messages
   - Detects and tracks third-party contacts not in person mappings
2. **Local Analysis**: Runs all configured non-AI analyzers
   - Threat detection with pattern matching
   - Sentiment analysis (polarity and subjectivity)
   - YAML-based pattern analysis
   - Communication metrics
3. **Optional AI Pre-Screening**: If configured, submits messages to Claude to surface additional review candidates
4. **Manual Review**: Examiner reviews and confirms every flagged item before it can appear in the final reports

Then run `python3 run.py --finalize` for Phases 5-8 (post-review):
5. **Behavioral Analysis**: Post-review behavioral pattern analysis
6. **Executive Summary**: Generates narrative summary from the reviewer-confirmed messages (uses Claude when configured; otherwise produces a deterministic statistical summary)
7. **Report Generation**: Creates comprehensive reports
   - Excel: Separate tabs per person with integrated threat/sentiment data, plus Findings Summary, Timeline, Conversation Threads, and Third Party Contacts sheets
   - Word: Complete analysis with all sections
   - PDF: Matches Word content for legal distribution
   - JSON: Raw data for additional processing
   - HTML/PDF: Per-person message tables, inline images, legal appendices (Methodology, Completeness Validation, Limitations)
   - Chat-bubble HTML: iMessage-style conversation view with aligned message bubbles
   - Timeline: Interactive HTML visualization with case chronology (flagged events + email communications)
8. **Documentation**: Generates chain of custody and manifest

After completing manual review, generate reports and documentation:
```bash
# Auto-detect the latest run directory
python3 run.py --finalize

# Or specify a run directory explicitly
python3 run.py --finalize ~/workspace/output/forensic-message-analyzer/run_20260304_120000
```

To resume an interrupted review session:
```bash
python3 run.py --resume
```

### Expected Output

**Message Extraction:**
- iMessages: Extracted from macOS Messages database
- WhatsApp: Automatically extracted from ZIP archives
- Email: Parsed from .eml and .mbox files with MIME decoding
- Teams: Extracted from personal export TAR archives (mapped conversations only)
- Total: Combined dataset with sender, recipient, content, timestamp, source

**Excel Report Structure:**
```
forensic-message-analyzer/
└── output/
    └── report_YYYYMMDD_HHMMSS.xlsx
        ├── Overview (summary statistics)
        ├── Findings Summary (executive summary, confirmed threats, patterns, recommendations)
        ├── Timeline (chronological events: threats, SOS, patterns, emails, third-party emails)
        ├── Person 2 (filtered conversations with chat data)
        ├── Person 3 (filtered conversations with chat data)
        ├── Conversation Threads (thread summaries with participants, time ranges)
        ├── Manual Review (if applicable)
        └── Third Party Contacts (unmapped contacts discovered during extraction)
```

Note: Person 1 does not get a separate tab because every other person's tab already shows their conversations with Person 1. All mapped persons get tabs even with zero messages to document absence of communication.

Each person tab includes:
- Message details (timestamp, sender, recipient, content, source)
- Threat information (threat_detected, threat_categories, threat_confidence)
- Sentiment data (sentiment_score, sentiment_polarity, sentiment_subjectivity)

### Embedding the analyzer in your own code

Public Python API documentation — every class, method, and signature
with usage examples — lives in [`DEVELOPER.md`](DEVELOPER.md). It is
intended for developers integrating the analyzer into another tool or
writing custom extractors / reporters; end-users do not need it.


## Legal Defensibility

### Federal Rules of Evidence Compliance

#### Authentication (FRE 901)
- SHA-256 hashing of all source files and outputs
- Precise timestamp logging via `ForensicRecorder`
- Read-only access to original evidence
- Complete audit trail in chain of custody

#### Best Evidence Rule (FRE 1002)
- Full metadata preservation
- Deterministic, reproducible extractions
- Unaltered content export alongside analysis

#### Business Records Exception (FRE 803(6))
- Retains original message metadata
- Documents regular course of communication
- No content modification during processing

### Daubert Standards

#### Testability
- Comprehensive unit and integration tests
- Deterministic processing (same input → same output)
- Hash verification for reproducibility

#### Peer Review
- Uses established libraries (pandas, Pillow, pytesseract)
- Open-source for community review
- Documented methodology in reports

#### Error Rate
- Logs all extraction/analysis anomalies
- Validation statistics in metrics
- Documented limitations in reports

#### Standards and Controls
- SWGDE/NIST-aligned workflow
- Configurable via `.env`
- No hidden state or processing

#### General Acceptance
- Standard output formats (JSON, XLSX, DOCX, PDF)
- Verifiable logs and hashes
- Industry-standard tools and methods

## Architecture

### Directory Structure
```
forensic-message-analyzer/
├── src/
│   ├── extractors/                 # Data extraction modules
│   │   ├── base.py                 # MessageExtractor base class (shared init + _record helper)
│   │   ├── data_extractor.py       # Unified extraction orchestrator
│   │   ├── imessage_extractor.py   # iMessage database extraction
│   │   ├── whatsapp_extractor.py   # WhatsApp export parsing (zip-bomb + zip-slip guards)
│   │   ├── email_extractor.py      # Email .eml/.mbox extraction
│   │   ├── teams_extractor.py      # Microsoft Teams export extraction
│   │   ├── screenshot_extractor.py # Screenshot cataloging
│   │   ├── sms_backup_extractor.py # Android SMS Backup & Restore XML
│   │   ├── call_logs_extractor.py  # iOS CallHistory + Android call XML + CSV
│   │   ├── voicemail_extractor.py  # iOS voicemail.db + audio + transcripts
│   │   └── location_extractor.py   # Google Takeout + Apple plist + GPX
│   ├── analyzers/                  # Analysis engines
│   │   ├── ai_analyzer.py          # Anthropic Claude AI analysis (batch + sync)
│   │   ├── threat_analyzer.py      # Threat detection
│   │   ├── sentiment_analyzer.py   # Sentiment analysis
│   │   ├── behavioral_analyzer.py  # Behavioral patterns
│   │   ├── yaml_pattern_analyzer.py # YAML-defined patterns (DARVO, gaslighting, coercive control)
│   │   ├── communication_metrics.py # Statistical metrics
│   │   ├── screenshot_analyzer.py  # OCR processing
│   │   └── attachment_processor.py # Attachment cataloging + EXIF / GPS / tamper scanning
│   ├── pipeline/                   # Per-phase runners (delegated from ForensicAnalyzer)
│   │   ├── extraction.py           # Phase 1
│   │   ├── analysis.py             # Phase 2
│   │   ├── ai_batch.py             # Phase 3
│   │   ├── review.py               # Phase 4
│   │   ├── behavioral.py           # Phase 5
│   │   ├── reporting.py            # Phase 7
│   │   └── documentation.py        # Phase 8 (includes events_timeline)
│   ├── review/                     # Manual review management
│   │   ├── manual_review_manager.py # Review decision tracking (required reviewer, append-only amendments)
│   │   ├── redaction_manager.py    # Append-only span / regex redaction workflow
│   │   ├── interactive_review.py   # CLI-based message review
│   │   └── web_review.py           # Flask-based web review UI (hardened cookies, scoped attachments)
│   ├── reporters/                  # Report generation
│   │   ├── forensic_reporter.py    # Main reporter (Word + PDF + methodology DOCX + methodology PDF + JSON)
│   │   ├── excel_reporter.py       # Standalone Excel report with multiple sheets
│   │   ├── html_reporter.py        # HTML/PDF report with inline images, source badges, legal appendices
│   │   ├── chat_reporter.py        # iMessage-style chat-bubble HTML report
│   │   └── json_reporter.py        # JSON output
│   ├── utils/                      # Utilities and helpers
│   │   ├── conversation_threading.py # Thread detection and grouping
│   │   ├── legal_compliance.py     # Legal standards + structured methodology/compliance rendering
│   │   ├── timeline_generator.py   # Detailed minute-level HTML timeline
│   │   ├── events_timeline.py      # Sparse executive-view timeline
│   │   ├── run_manifest.py         # Run documentation (config snapshot, pattern hashes, signed)
│   │   ├── evidence_preserver.py   # Hashing, archiving, working-copy routing, contact auto-map
│   │   ├── signing.py              # Ed25519 detached signatures
│   │   ├── contact_automapper.py   # vCard → contact_mappings merger
│   │   └── pricing.py              # AI model pricing lookup
│   ├── forensic_utils.py           # Chain of custody and integrity (HMAC-chained log)
│   ├── third_party_registry.py     # Unmapped contact tracking
│   ├── config.py                   # Configuration + snapshot() for manifest
│   ├── schema.py                   # TypedDicts for Message / Finding / ReviewRecord
│   └── main.py                     # Thin orchestrator; phase logic lives in src/pipeline/
├── tests/                          # Unit and integration tests
│   ├── test_imports.py             # Dependency verification
│   ├── test_core_functionality.py  # Core component tests
│   ├── test_integration.py         # End-to-end tests
│   ├── test_forensic_utils.py      # Forensic utilities tests
│   ├── test_teams_extractor.py     # Microsoft Teams extractor tests
│   ├── test_third_party_registry.py # Third-party contact registry tests
│   ├── test_timezone_dst.py        # DST + Apple-epoch round-trip coverage
│   └── run_all_tests.sh            # Test runner script
├── patterns/                       # YAML pattern definitions (with empirical citations)
│   └── analysis_patterns.yaml
├── .github/
│   └── copilot-instructions.md     # Development guidelines
├── validate_before_run.py          # Pre-run validation and cost estimation
├── check_readiness.py              # System readiness checker
├── generate_sample_output.py       # Regenerates sample_output/ from anonymized fixtures
├── run.py                          # Main entry point
├── ROADMAP.md                      # Deferred work (redaction UI, Signal/Telegram)
├── requirements.txt                # Supported minimum versions
├── requirements-lock.txt           # Pinned versions for reproducible installs
└── .env.example                    # Configuration template
```

### Data Flow
```
Source Data → Extraction → Analysis → Review → Reporting → Documentation
     ↓            ↓           ↓         ↓          ↓            ↓
  [Hashed]    [Hashed]    [Logged]  [Tracked]  [Hashed]   [Manifest]
```

## Testing

### Run All Tests
```bash
# Run all test suites
./tests/run_all_tests.sh

# Or use pytest directly
python3 -m pytest tests/ -v
```

### Run Specific Test Suite
```bash
# Import tests
python3 -m pytest tests/test_imports.py -v

# Core functionality tests
python3 -m pytest tests/test_core_functionality.py -v

# Integration tests
python3 -m pytest tests/test_integration.py -v

# Forensic utilities tests
python3 -m pytest tests/test_forensic_utils.py -v

# Test with coverage
python3 -m pytest --cov=src tests/
```

### Check System Readiness
```bash
# Verify configuration and dependencies
python3 check_readiness.py
```

## Output Files

All outputs are timestamped and stored in the configured `OUTPUT_DIR` (default: `~/workspace/output/forensic-message-analyzer/`):

### Analysis Outputs
- `extracted_data_YYYYMMDD_HHMMSS.json` - Raw extracted messages with sender, recipient, content, timestamp
- `analysis_results_YYYYMMDD_HHMMSS.json` - Analysis findings (threats, sentiment, patterns, metrics)
- `manual_review_summary_YYYYMMDD_HHMMSS.json` - Review decisions (if manual review performed)

### Reports
- `report_YYYYMMDD_HHMMSS.xlsx` - Excel report with person-organized tabs:
  - **Overview**: Summary statistics (message count, date range, threats, reviews)
  - **[Person Name]**: Individual tabs for each configured person
    - Contains only messages where that person is a sender or recipient
    - Includes integrated threat and sentiment columns
    - Columns: timestamp, sender, recipient, content, source, threat_detected, threat_categories, 
      threat_confidence, harmful_content, sentiment_score, sentiment_polarity, sentiment_subjectivity
  - **Manual Review**: Review decisions (if applicable)
  - Note: Random phone numbers and chat IDs are excluded (only shows legally relevant parties)

- `READ_ME_FIRST_YYYYMMDD_HHMMSS.docx` - **One-page reading guide for the legal team**
  - Open this first. Tells the reader, in one page, which file in the
    package answers which question (methodology challenges → open the
    methodology document; plain-English findings → open the legal team
    summary; full record → open the forensic report PDF; etc.)
  - References every other file in the package by actual filename so
    attorneys / paralegals can navigate without guessing

- `forensic_report_YYYYMMDD_HHMMSS.docx` - Word document report with:
  - Legal team summary (plain-language narrative explaining findings and output files)
  - Executive summary
  - Data extraction statistics (total messages, date range, sources, screenshots)
  - Threat analysis (count and high-priority examples)
  - Sentiment analysis (positive/neutral/negative distribution)
  - Manual review breakdown
  - Chain of custody reference
  
- `forensic_report_YYYYMMDD_HHMMSS.pdf` - PDF report for court submission
  - Contains same content as Word document
  - Formatted for legal distribution and printing

- `methodology_YYYYMMDD_HHMMSS.docx` / `methodology_YYYYMMDD_HHMMSS.pdf` - **Standalone Methodology Statement** (both formats)
  - Plain-language, judge-readable walkthrough of every analysis phase
  - Explicitly maps each FRE / Daubert factor to how it was satisfied
  - Component-level error-rate and known-failure-mode disclosures (pattern matching, sentiment, attributedBody decoding, OCR, EXIF, AI screening)
  - Empirical citations for every threat / behavioural pattern matched (Stark 2007, Sweet 2019, Campbell 2003, Freyd 1997 / Harsey & Freyd 2020 for DARVO, etc.)
  - Structured Standards Compliance section with real headings, bulleted list of standards, and term/definition pairs
  - Included as separate documents so the legal team can review the methodology without wading through case-specific findings; PDF form exists for court exhibits and readers without Office

- `forensic_analysis_YYYYMMDD_HHMMSS.html` - HTML report with inline images
  - Overview cards, per-person message tables, conversation threads
  - Inline base64 attachment images (iMessage and WhatsApp)
  - Risk indicators, executive summary, legal compliance footer
  - Legal appendices: Appendix A (Methodology), Appendix B (Completeness Validation), Appendix C (Limitations)

- `forensic_analysis_YYYYMMDD_HHMMSS.pdf` - PDF conversion of HTML report (via WeasyPrint)

- `events_timeline_YYYYMMDD_HHMMSS.html` - **Big-picture events timeline** (court-facing)
  - Sparse, executive-view chronology of the moments the case turns on
  - Shows only reviewer-confirmed events: pattern-matched threats, AI-screened threats, coercive-control pattern clusters, sentiment shifts
  - Category badges (THREAT / PATTERN / ESCALATION / DE-ESCALATION / MILESTONE) with per-event provenance reference
  - Dates resolve against the message corpus even when the AI summary omits them

- `timeline_YYYYMMDD_HHMMSS.html` - Detailed minute-level timeline (analyst drill-down)
  - Chronological message view with filtering
  - Threat highlighting and sentiment indicators
  - Email communications with subject lines (purple border for mapped persons, pink for third-party)
  - Third-party emails (counselors, attorneys, family) provide corroborating evidence context

- `chat_report_YYYYMMDD_HHMMSS.html` - iMessage-style chat-bubble report
  - Per-person conversation sections with left/right aligned message bubbles
  - Inline attachment images, threat/sentiment visual indicators, conversation threading
  - Edit history display for edited messages (original text and intermediate edits)
  - Deleted message badges, URL preview blocks, shared location blocks

- `legal_team_summary_YYYYMMDD_HHMMSS.docx` - Narrative summary for attorneys
  - Explains key findings in plain language
  - Describes how to use each output file
  - Includes recommended next steps for the legal team

- `all_messages_YYYYMMDD_HHMMSS.csv` - Complete unedited message record (CSV)
  - All messages from all sources in chronological order
  - No filtering or enrichment — raw forensic data
  - SHA-256 hashed for chain of custody

- `all_messages_YYYYMMDD_HHMMSS.xlsx` - Complete unedited message record (Excel)
  - Same data as CSV, formatted for court readability
  - Single "All Messages" sheet with auto-sized columns

### Documentation
- `chain_of_custody_YYYYMMDD_HHMMSS.json` - Complete audit trail with:
  - Session metadata (start time, duration, session ID)
  - All operations performed (with timestamps, details, and per-record HMAC chain)
  - System information (platform, Python version, analyzer version)
  - Legal notice for FRE 901 compliance
  - Sibling `<file>.sig` + `<file>.sig.pub` detached Ed25519 signature

- `forensic_log_YYYYMMDD_HHMMSS.jsonl` - Tamper-evident append-only JSONL log
  - Every action carries `seq`, `prev_hmac`, `hmac`; `ForensicRecorder.verify_log_chain()` reports any break
  - Sibling `forensic_hmac_key_YYYYMMDD_HHMMSS.bin` (mode 0600) — archive with the log for independent verification

- `run_manifest_YYYYMMDD_HHMMSS.json` - Analysis process documentation with:
  - Input files processed (with paths and hashes)
  - Output files generated (with paths and hashes)
  - `config_snapshot` — every setting used (API keys redacted)
  - `pattern_files` — SHA-256 of each YAML under `patterns/`
  - Sibling `<file>.sig` + `<file>.sig.pub` detached Ed25519 signature

- `preserved_sources.zip` - Hash-verified archive of every source file as extracted
- `working_copies/` - The copies the extractors actually read (originals never opened)
- `keys/examiner_ed25519.pem` - Per-run ephemeral signing key (unless `EXAMINER_SIGNING_KEY` points to a long-lived one)

### Example Output Structure
```
~/workspace/output/forensic-message-analyzer/run_YYYYMMDD_HHMMSS/
├── extracted_data_YYYYMMDD_HHMMSS.json
├── analysis_results_YYYYMMDD_HHMMSS.json
├── ai_batch_results_YYYYMMDD_HHMMSS.json
├── review_results_YYYYMMDD_HHMMSS.json
├── pipeline_state.json
├── report_YYYYMMDD_HHMMSS.xlsx
├── forensic_report_YYYYMMDD_HHMMSS.docx
├── forensic_report_YYYYMMDD_HHMMSS.pdf
├── methodology_YYYYMMDD_HHMMSS.docx
├── methodology_YYYYMMDD_HHMMSS.pdf
├── report_YYYYMMDD_HHMMSS.html
├── report_YYYYMMDD_HHMMSS_chat.html
├── events_timeline_YYYYMMDD_HHMMSS.html
├── timeline_YYYYMMDD_HHMMSS.html
├── legal_team_summary_YYYYMMDD_HHMMSS.docx
├── all_messages_YYYYMMDD_HHMMSS.csv
├── all_messages_YYYYMMDD_HHMMSS.xlsx
├── chain_of_custody_YYYYMMDD_HHMMSS.json (+ .sig + .sig.pub)
├── run_manifest_YYYYMMDD_HHMMSS.json (+ .sig + .sig.pub)
├── forensic_log_YYYYMMDD_HHMMSS.jsonl
├── forensic_hmac_key_YYYYMMDD_HHMMSS.bin
├── preserved_sources.zip
├── working_copies/
│   └── {imessage,email,teams,whatsapp,screenshots}/...
└── keys/
    └── examiner_ed25519.pem
```

## Contributing

We welcome contributions that enhance the forensic capabilities while maintaining legal defensibility:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Ensure all tests pass (`pytest tests/`)
4. Add tests for new functionality
5. Update documentation as needed
6. Submit a pull request

### Development Guidelines

- Maintain evidence integrity - never modify source data
- Add forensic logging for all operations
- Ensure deterministic, reproducible processing
- Follow existing patterns for analyzers/extractors
- Document legal compliance considerations

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed to assist in digital forensic analysis for legal proceedings. Users are responsible for:
- Ensuring compliance with applicable laws and regulations
- Obtaining necessary legal authority for data access
- Maintaining proper chain of custody procedures
- Validating findings through appropriate review processes

The authors and contributors make no warranties about the suitability of this software for any particular legal proceeding.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review existing documentation and code comments
- Check logs in the output directory for debugging

## Acknowledgments

- Built with consideration for Federal Rules of Evidence
- Follows SWGDE and NIST digital forensics guidelines
- Uses industry-standard libraries and methods

---

**For Legal Teams**: The system produces reports suitable for court proceedings with complete documentation of methodology, limitations, and chain of custody. All processing is transparent, reproducible, and defensible under Daubert standards.

**For Technical Teams**: The modular architecture allows easy extension of extractors and analyzers. All components follow consistent patterns with comprehensive logging and error handling.