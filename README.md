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
- **AI Analysis**: Anthropic Claude (Opus 4.6) integration with batch API support and prompt caching
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
  - Separate tabs for each configured person (e.g., Marcia Snyder, Kiara Snyder)
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
- **Timeline Visualization**: Interactive HTML timelines
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
git clone https://github.com/yourusername/forensic_message_analyzer.git
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
AI_MODEL=claude-opus-4-6

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

### Full Analysis Pipeline

Run the complete forensic analysis:
```bash
python3 run.py
```

This executes five phases:
1. **Data Extraction**: Collects messages from all sources (iMessage, WhatsApp, email, Teams, screenshots)
   - Automatically extracts ZIP files (e.g., WhatsApp_SourceFiles.zip) and TAR archives (Teams exports)
   - Decodes modern iMessage binary format (attributedBody)
   - Parses email MIME format (.eml, .mbox) with header extraction
   - Processes Microsoft Teams personal export JSON with sender identification
   - Maps all participants to configured person names
   - Adds sender and recipient fields to all messages
   - Detects and tracks third-party contacts not in person mappings
2. **Automated Analysis**: Runs all configured analyzers
   - Threat detection with pattern matching
   - Sentiment analysis (polarity and subjectivity)
   - Behavioral pattern analysis
   - Communication metrics
3. **Manual Review**: Flags items for human review
4. **Report Generation**: Creates comprehensive reports
   - Excel: Separate tabs per person with integrated threat/sentiment data
   - Word: Complete analysis with all sections
   - PDF: Matches Word content for legal distribution
   - JSON: Raw data for additional processing
   - Timeline: Interactive HTML visualization
5. **Documentation**: Generates chain of custody and manifest

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
        ├── Marcia Snyder (filtered conversations)
        ├── Kiara Snyder (filtered conversations)
        ├── David Snyder (filtered conversations)
        └── Manual Review (if applicable)
```

Each person tab includes:
- Message details (timestamp, sender, recipient, content, source)
- Threat information (threat_detected, threat_categories, threat_confidence)
- Sentiment data (sentiment_score, sentiment_polarity, sentiment_subjectivity)

### Individual Components

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
# Note: IMessageExtractor requires (db_path, forensic_recorder, forensic_integrity)
# Returns: list of message dicts with sender, recipient, content, timestamp, source
db_path = config.messages_db_path
imessage_extractor = IMessageExtractor(db_path, recorder, integrity)
imessages = imessage_extractor.extract_messages()  # Returns list, not DataFrame

# Extract WhatsApp
# Note: WhatsAppExtractor requires (export_dir, forensic_recorder, forensic_integrity)
# Automatically extracts ZIP files in the directory
# Returns: list of message dicts
export_dir = config.whatsapp_source_dir
whatsapp_extractor = WhatsAppExtractor(export_dir, recorder, integrity)
whatsapp_messages = whatsapp_extractor.extract_all()  # Returns list, not DataFrame

# Combine messages into DataFrame
all_messages = imessages + whatsapp_messages
combined_df = pd.DataFrame(all_messages)

# Analyze for threats
# Note: detect_threats() adds columns to DataFrame, returns same DataFrame
# Note: generate_threat_summary() takes DataFrame, returns dict
threat_analyzer = ThreatAnalyzer(recorder)
threats_df = threat_analyzer.detect_threats(combined_df)
threat_summary = threat_analyzer.generate_threat_summary(threats_df)

# Analyze sentiment
# Note: analyze_sentiment() adds sentiment_* columns to DataFrame
# Requires forensic_recorder parameter in __init__
sentiment_analyzer = SentimentAnalyzer(recorder)
sentiment_df = sentiment_analyzer.analyze_sentiment(threats_df)

# Analyze behavioral patterns
# Note: analyze_patterns() returns dict, NOT DataFrame
behavioral_analyzer = BehavioralAnalyzer(recorder)
behavior_results = behavioral_analyzer.analyze_patterns(sentiment_df)

# Generate reports
# Note: Reports are filtered to only show configured persons from .env
reporter = ForensicReporter(recorder)
reports = reporter.generate_comprehensive_report(
    extracted_data={'messages': all_messages, 'screenshots': []},
    analysis_results={'threats': threat_summary, 'sentiment': sentiment_df.to_dict('records')},
    review_decisions={}
)
```

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
│   │   ├── threat_analyzer.py   # Threat detection
│   │   ├── sentiment_analyzer.py # Sentiment analysis
│   │   ├── behavioral_analyzer.py # Behavioral patterns
│   │   ├── yaml_pattern_analyzer.py # YAML-defined patterns
│   │   ├── communication_metrics.py # Statistical metrics
│   │   ├── screenshot_analyzer.py # OCR processing
│   │   └── attachment_processor.py # Attachment cataloging
│   ├── review/                  # Manual review management
│   │   └── manual_review_manager.py
│   ├── reporters/               # Report generation
│   │   ├── forensic_reporter.py # Main reporter (Excel, Word, PDF)
│   │   └── json_reporter.py     # JSON output
│   ├── utils/                   # Utilities and helpers
│   │   ├── timeline_generator.py # HTML timeline creation
│   │   └── run_manifest.py      # Run documentation
│   ├── forensic_utils.py        # Chain of custody and integrity
│   ├── config.py                # Configuration management
│   └── main.py                  # Main orchestration
├── tests/                       # Unit and integration tests
│   ├── test_imports.py          # Dependency verification
│   ├── test_core_functionality.py # Core component tests
│   ├── test_integration.py      # End-to-end tests
│   ├── test_forensic_utils.py   # Forensic utilities tests
│   └── run_all_tests.sh         # Test runner script
├── patterns/                    # YAML pattern definitions
│   └── analysis_patterns.yaml
├── .github/
│   └── copilot-instructions.md  # Development guidelines
├── check_readiness.py           # System readiness checker
├── run.py                       # Main entry point
└── .env.example                 # Configuration template
```

### Core Classes and Their Methods

#### Forensic Utilities
- **ForensicRecorder()**: Records all actions with timestamps and hashes
  - `record_action(action, details, metadata=None)`: Log forensic action
  - `compute_hash(file_path)`: SHA-256 hash of file (takes Path object)
  - `generate_chain_of_custody()`: Create chain of custody JSON

- **ForensicIntegrity(recorder)**: Ensures evidence integrity
  - `verify_read_only()`: Verify source is read-only
  - `create_working_copy(source, dest)`: Create hashed working copy

#### Extractors
- **IMessageExtractor(db_path, forensic_recorder, forensic_integrity)**
  - `extract_messages()`: Extract from iMessage database

- **WhatsAppExtractor(export_dir, forensic_recorder, forensic_integrity)**
  - `extract_all()`: Parse WhatsApp export files

- **EmailExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)**
  - `extract_all()`: Parse .eml and .mbox email files

- **TeamsExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)**
  - `extract_all()`: Parse Microsoft Teams personal export TAR archives

- **DataExtractor(forensic_recorder, third_party_registry=None)**: Coordinates all extraction
  - `extract_all()`: Returns list of message dicts from all sources

#### Analyzers
- **ThreatAnalyzer(forensic_recorder)**
  - `detect_threats(df)`: Returns DataFrame with threat_detected column
  - `generate_threat_summary(df)`: Returns threat summary dict

- **SentimentAnalyzer(forensic_recorder)**
  - `analyze_sentiment(df)`: Returns DataFrame with sentiment_polarity, sentiment_subjectivity

- **BehavioralAnalyzer(forensic_recorder)**
  - `analyze_patterns(df)`: Returns dict with behavioral analysis

- **YamlPatternAnalyzer(forensic_recorder, patterns_file=None)**
  - `analyze_patterns(df)`: Returns DataFrame with patterns_detected, pattern_score

- **CommunicationMetricsAnalyzer(forensic_recorder=None)**
  - `analyze_messages(messages)`: Takes list of dicts, returns metrics dict

#### Utilities
- **TimelineGenerator(forensic_recorder)**
  - `create_timeline(df, output_path)`: Create HTML timeline

- **ManualReviewManager()**
  - `add_review(item_id, item_type, decision, notes)`: Add review decision
  - `get_reviews_by_decision(decision)`: Retrieve reviews by decision type

- **RunManifest(forensic_recorder)**
  - `add_input_file(path)`: Add input file to manifest
  - `add_output_file(path)`: Add output file to manifest
  - `generate_manifest()`: Returns Path to manifest JSON

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
  - **[Person Name]**: Individual tabs for each configured person (e.g., "Marcia Snyder")
    - Contains only messages where that person is the recipient
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
  
- `timeline_YYYYMMDD_HHMMSS.html` - Interactive timeline visualization
  - Chronological message view with filtering
  - Threat highlighting and sentiment indicators

- `legal_team_summary_YYYYMMDD_HHMMSS.txt` - AI-generated narrative summary for attorneys
  - Explains key findings in plain language
  - Describes how to use each output file
  - Includes recommended next steps for the legal team

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
├── timeline_20251006_011545.html
├── legal_team_summary_20251006_011545.txt
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