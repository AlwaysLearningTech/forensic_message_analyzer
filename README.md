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
- **Attachments**: Full metadata preservation

### Analysis Capabilities
- **Threat Detection**: AI-powered threat identification with configurable thresholds
- **Pattern Analysis**: YAML-based configurable patterns for behavioral detection
- **Sentiment Analysis**: Message tone and emotion detection using TextBlob
- **Behavioral Analysis**: Communication pattern identification and profiling
- **Communication Metrics**: Frequency, volume, timing, and response pattern analysis
- **AI Analysis**: Anthropic Claude integration with batch API support and prompt caching
  - Threat detection and risk assessment with severity classification
  - Emotional escalation tracking across conversations
  - Behavioral pattern recognition (control, isolation, harassment)
  - Legal team summary: narrative guide explaining findings and how to use the outputs
  - Conversation summary written in plain language for attorneys

### Legal Compliance
- **Chain of Custody**: Complete audit trail with SHA-256 hashing
- **Evidence Integrity**: Read-only processing, no source modification
- **FRE Compliance**: Meets Federal Rules of Evidence requirements (FRE 901, 803)
- **Daubert Standards**: Testable, reproducible, documented methodology
- **Conversation Filtering**: Reports show only legally relevant parties (configured in .env)

### Reporting
- **Excel Reports**: Organized by person with integrated threat/sentiment data
  - Separate tabs for each configured person
  - Each tab combines messages, threats, and sentiment in one view
  - Excludes conversations with non-relevant parties
- **Word/PDF Reports**: Comprehensive analysis with:
  - Legal team summary (AI-generated narrative for attorneys)
  - Executive summary
  - Data extraction statistics
  - Threat analysis with high-priority examples
  - Sentiment distribution (Positive/Neutral/Negative)
  - Manual review breakdown
  - Chain of custody reference
- **Forensic Export**: Unedited, unfiltered CSV and Excel export of all messages for court admissibility
- **HTML/PDF Reports**: Inline base64 images, per-person message tables, conversation threads, risk indicators, legal compliance footer, legal appendices (Methodology, Completeness Validation, Limitations), edit history display for edited messages, URL preview and shared location rendering, deleted message flags (PDF via WeasyPrint)
- **Chat-Bubble Reports**: iMessage-style chat-bubble HTML report with left/right aligned message bubbles, per-person sections, inline attachments, threat/sentiment indicators, edit history display, URL preview and shared location blocks, deleted message badges
- **Timeline Visualization**: Interactive HTML timelines with case chronology — combines flagged events (threats, patterns, SOS) with all email communications including third-party corroboration (counselors, attorneys, family)
- **Manual Review**: Structured decision tracking
- **Run Manifest**: Complete documentation of analysis process

## Installation

### Prerequisites
- Python 3.8 or higher
- macOS (for iMessage extraction)
- Tesseract OCR (for screenshot text extraction)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/AlwaysLearningTech/forensic_message_analyzer.git
cd forensic_message_analyzer
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
1. `~/workspace/data/forensic_message_analyzer/.env` (primary location)
2. Path specified in `DOTENV_PATH` environment variable
3. Local `.env` in the project directory (not recommended)

### Setting Up Configuration

1. Create the data directory structure:
```bash
mkdir -p ~/workspace/data/forensic_message_analyzer
```

2. Copy the example configuration to the data directory:
```bash
cp .env.example ~/workspace/data/forensic_message_analyzer/.env
```

3. Edit `~/workspace/data/forensic_message_analyzer/.env` with your settings:
```bash
# Anthropic Claude API key (required for AI analysis)
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
WHATSAPP_SOURCE_DIR=~/workspace/data/forensic_message_analyzer/source_files/whatsapp/
SCREENSHOT_SOURCE_DIR=~/workspace/data/forensic_message_analyzer/source_files/screenshots/
EMAIL_SOURCE_DIR=~/workspace/data/forensic_message_analyzer/source_files/email/
TEAMS_SOURCE_DIR=~/workspace/data/forensic_message_analyzer/source_files/microsoft_teams_personal/
```

## Data Separation Strategy

### Security Architecture

The project implements a strict separation between code and data to prevent sensitive information from being accidentally committed to version control:

```
Repository (GitHub)              Local Data Storage
├── src/                        ~/workspace/data/forensic_message_analyzer/
├── tests/                      ├── .env (configuration with keys)
├── patterns/                   ├── source_files/
├── .env.example                │   ├── whatsapp/
└── README.md                   │   ├── screenshots/
                               │   ├── email/
                               │   └── microsoft_teams_personal/
                               ├── review/ (manual review decisions)
                               └── logs/

                               ~/workspace/output/forensic_message_analyzer/
                               └── [all analysis outputs]
```

### Key Principles

1. **Code Repository** (`/workspace/repos/forensic_message_analyzer/`):
   - Contains only source code, tests, and documentation
   - `.env.example` provides template without sensitive data
   - `.gitignore` excludes all data directories

2. **Data Storage** (`/workspace/data/forensic_message_analyzer/`):
   - Holds actual `.env` with credentials
   - Contains source files for analysis
   - Stores review decisions and logs
   - Never tracked in version control

3. **Output Storage** (`/workspace/output/forensic_message_analyzer/`):
   - All analysis results and reports
   - Chain of custody documents
   - Separate from both code and input data

### Setting Up Data Directories

```bash
# Create data directory structure
mkdir -p ~/workspace/data/forensic_message_analyzer/{source_files,review,logs}
mkdir -p ~/workspace/data/forensic_message_analyzer/source_files/{whatsapp,screenshots,email,microsoft_teams_personal}
mkdir -p ~/workspace/output/forensic_message_analyzer

# Copy and configure .env
cp .env.example ~/workspace/data/forensic_message_analyzer/.env
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
3. **AI Batch Analysis**: Submits messages to Claude for classification (pre-review)
4. **Manual Review**: Flags items from local and AI analysis for human review

Then run `python3 run.py --finalize` for Phases 5-8 (post-review):
5. **Behavioral Analysis**: Post-review behavioral pattern analysis
6. **AI Executive Summary**: Generates narrative summary incorporating review decisions
7. **Report Generation**: Creates comprehensive reports
   - Excel: Separate tabs per person with integrated threat/sentiment data, plus Findings Summary, Timeline, AI Analysis, Conversation Threads, and Third Party Contacts sheets
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
python3 run.py --finalize ~/workspace/output/forensic_message_analyzer/run_20260304_120000
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
forensic_message_analyzer/
└── output/
    └── report_YYYYMMDD_HHMMSS.xlsx
        ├── Overview (summary statistics)
        ├── Findings Summary (confirmed threats, AI findings, patterns, recommendations)
        ├── AI Analysis (risk indicators, AI-detected threats)
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
forensic_message_analyzer/
├── src/
│   ├── extractors/              # Data extraction modules
│   │   ├── data_extractor.py    # Unified extraction orchestrator
│   │   ├── imessage_extractor.py # iMessage database extraction
│   │   ├── whatsapp_extractor.py # WhatsApp export parsing
│   │   ├── email_extractor.py   # Email .eml/.mbox extraction
│   │   ├── teams_extractor.py   # Microsoft Teams export extraction
│   │   └── screenshot_extractor.py # Screenshot cataloging
│   ├── analyzers/               # Analysis engines
│   │   ├── ai_analyzer.py      # Anthropic Claude AI analysis (batch + sync)
│   │   ├── threat_analyzer.py   # Threat detection
│   │   ├── sentiment_analyzer.py # Sentiment analysis
│   │   ├── behavioral_analyzer.py # Behavioral patterns
│   │   ├── yaml_pattern_analyzer.py # YAML-defined patterns
│   │   ├── communication_metrics.py # Statistical metrics
│   │   ├── screenshot_analyzer.py # OCR processing
│   │   └── attachment_processor.py # Attachment cataloging
│   ├── review/                  # Manual review management
│   │   ├── manual_review_manager.py # Review decision tracking
│   │   ├── interactive_review.py # CLI-based message review
│   │   └── web_review.py       # Flask-based web review UI
│   ├── reporters/               # Report generation
│   │   ├── forensic_reporter.py # Main reporter (Excel, Word, PDF)
│   │   ├── excel_reporter.py    # Standalone Excel report with multiple sheets
│   │   ├── html_reporter.py    # HTML/PDF report with inline images and legal appendices
│   │   ├── chat_reporter.py    # iMessage-style chat-bubble HTML report
│   │   └── json_reporter.py    # JSON output
│   ├── utils/                   # Utilities and helpers
│   │   ├── conversation_threading.py # Thread detection and grouping
│   │   ├── legal_compliance.py  # Legal standards documentation
│   │   ├── timeline_generator.py # HTML timeline creation
│   │   └── run_manifest.py      # Run documentation
│   ├── forensic_utils.py        # Chain of custody and integrity
│   ├── third_party_registry.py  # Unmapped contact tracking
│   ├── config.py                # Configuration management
│   └── main.py                  # Main orchestration
├── tests/                       # Unit and integration tests
│   ├── test_imports.py          # Dependency verification
│   ├── test_core_functionality.py # Core component tests
│   ├── test_integration.py      # End-to-end tests
│   ├── test_forensic_utils.py   # Forensic utilities tests
│   ├── test_teams_extractor.py  # Microsoft Teams extractor tests
│   ├── test_third_party_registry.py # Third-party contact registry tests
│   └── run_all_tests.sh         # Test runner script
├── patterns/                    # YAML pattern definitions
│   └── analysis_patterns.yaml
├── .github/
│   └── copilot-instructions.md  # Development guidelines
├── validate_before_run.py       # Pre-run validation and cost estimation
├── check_readiness.py           # System readiness checker
├── run.py                       # Main entry point
└── .env.example                 # Configuration template
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

All outputs are timestamped and stored in the configured `OUTPUT_DIR` (default: `~/workspace/output/forensic_message_analyzer/`):

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
  
- `forensic_report_YYYYMMDD_HHMMSS.docx` - Word document report with:
  - Legal team summary (AI-generated narrative explaining findings and output files)
  - Executive summary
  - Data extraction statistics (total messages, date range, sources, screenshots)
  - Threat analysis (count and high-priority examples)
  - Sentiment analysis (positive/neutral/negative distribution)
  - Manual review breakdown
  - Chain of custody reference
  
- `forensic_report_YYYYMMDD_HHMMSS.pdf` - PDF report for court submission
  - Contains same content as Word document
  - Formatted for legal distribution and printing

- `methodology_YYYYMMDD_HHMMSS.docx` - **Standalone Methodology Statement**
  - Plain-language, judge-readable walkthrough of every analysis phase
  - Explicitly maps each FRE / Daubert factor to how it was satisfied
  - Empirical citations for every threat / behavioural pattern matched
  - Included as a separate document so the legal team can review the
    methodology without wading through case-specific findings; this is
    the document to read first if the methodology is ever challenged

- `forensic_analysis_YYYYMMDD_HHMMSS.html` - HTML report with inline images
  - Overview cards, per-person message tables, conversation threads
  - Inline base64 attachment images (iMessage and WhatsApp)
  - Risk indicators, AI summary, legal compliance footer
  - Legal appendices: Appendix A (Methodology), Appendix B (Completeness Validation), Appendix C (Limitations)

- `forensic_analysis_YYYYMMDD_HHMMSS.pdf` - PDF conversion of HTML report (via WeasyPrint)

- `timeline_YYYYMMDD_HHMMSS.html` - Interactive timeline visualization (case chronology)
  - Chronological message view with filtering
  - Threat highlighting and sentiment indicators
  - Email communications with subject lines (purple border for mapped persons, pink for third-party)
  - Third-party emails (counselors, attorneys, family) provide corroborating evidence context

- `chat_report_YYYYMMDD_HHMMSS.html` - iMessage-style chat-bubble report
  - Per-person conversation sections with left/right aligned message bubbles
  - Inline attachment images, threat/sentiment visual indicators, conversation threading
  - Edit history display for edited messages (original text and intermediate edits)
  - Deleted message badges, URL preview blocks, shared location blocks

- `legal_team_summary_YYYYMMDD_HHMMSS.docx` - AI-generated narrative summary for attorneys
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
  - All operations performed (with timestamps and details)
  - System information (platform, Python version, analyzer version)
  - Legal notice for FRE 901 compliance
  
- `run_manifest_YYYYMMDD_HHMMSS.json` - Analysis process documentation with:
  - Input files processed (with paths and hashes)
  - Output files generated (with paths and hashes)
  - Processing steps and configuration used
  
### Example Output Structure
```
~/workspace/output/forensic_message_analyzer/
├── extracted_data_20251006_011535.json
├── analysis_results_20251006_011542.json
├── report_20251006_011549.xlsx
├── forensic_report_20251006_011543.docx
├── forensic_report_20251006_011543.pdf
├── forensic_analysis_20251006_011543.html
├── forensic_analysis_20251006_011543.pdf
├── chat_report_20251006_011543.html
├── timeline_20251006_011545.html
├── legal_team_summary_20251006_011545.docx
├── all_messages_20251006_011545.csv
├── all_messages_20251006_011545.xlsx
├── chain_of_custody_20251006_011530.json
└── run_manifest_20251006_011545.json
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