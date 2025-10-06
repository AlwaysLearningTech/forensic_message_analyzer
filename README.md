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

The Forensic Message Analyzer is a multi-phase digital evidence processor designed for legal use. It extracts, analyzes, and reports on message data from iMessage, WhatsApp, and screenshots while maintaining a complete chain of custody for court admissibility.

## Features

### Data Extraction
- **iMessage**: Direct extraction from macOS Messages database
- **WhatsApp**: Import from exported chat files
- **Screenshots**: Catalog and OCR processing
- **Attachments**: Full metadata preservation

### Analysis Capabilities
- **Threat Detection**: AI-powered threat identification with configurable thresholds
- **Pattern Analysis**: YAML-based configurable patterns for behavioral detection
- **Sentiment Analysis**: Message tone and emotion detection using TextBlob
- **Behavioral Analysis**: Communication pattern identification and profiling
- **OCR Processing**: Text extraction from screenshots using Tesseract
- **Communication Metrics**: Frequency, volume, timing, and response pattern analysis
- **AI Analysis**: Optional Azure OpenAI integration with rate limiting (2000 tokens/min default)

### Legal Compliance
- **Chain of Custody**: Complete audit trail with SHA-256 hashing
- **Evidence Integrity**: Read-only processing, no source modification
- **FRE Compliance**: Meets Federal Rules of Evidence requirements
- **Daubert Standards**: Testable, reproducible, documented methodology

### Reporting
- **Multi-format**: Excel, Word, PDF reports
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
# Azure OpenAI (optional, for AI analysis)
AZURE_OPENAI_ENDPOINT=your-endpoint
AZURE_OPENAI_API_KEY=your-key
AZURE_OPENAI_DEPLOYMENT_NAME=your-deployment

# Contact Mapping - Define names for reports and their identifiers
# PERSON(x)_NAME: The name used in all reports (e.g., "David Snyder")
# PERSON(x)_MAPPING: List of identifiers to match (phones, emails, aliases)
# IMPORTANT: Use single quotes around the JSON array to avoid parsing issues
# NOTE: Phone numbers are automatically expanded to match common formats:
#   - "+12345678901" also matches "234-567-8901" and "(234) 567-8901"
#   - You only need to list each phone number ONCE in any format
PERSON1_NAME="First Last"
PERSON2_NAME="Another Person"
PERSON3_NAME="Third Person"

PERSON1_MAPPING='["+12345678901","email@example.com","FirstName","Full Name"]'
PERSON2_MAPPING='["+19876543210","another@example.com","AnotherName"]'
PERSON3_MAPPING='["third@example.com","ThirdName","Nickname"]'

# Data Sources (paths to source files)
MESSAGES_DB_PATH=~/Library/Messages/chat.db
WHATSAPP_SOURCE_DIR=~/workspace/data/forensic_message_analyzer/source_files/whatsapp/
SCREENSHOT_SOURCE_DIR=~/workspace/data/forensic_message_analyzer/source_files/screenshots/

# Rate Limiting (for Azure OpenAI API)
TOKENS_PER_MINUTE=2000
REQUEST_DELAY_MS=500
MAX_TOKENS_PER_REQUEST=150

# Output and Review Directories
OUTPUT_DIR=~/workspace/output/forensic_message_analyzer
REVIEW_DIR=~/workspace/data/forensic_message_analyzer/review
LOG_DIR=~/workspace/data/forensic_message_analyzer/logs
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
└── README.md                   │   └── screenshots/
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
mkdir -p ~/workspace/data/forensic_message_analyzer/source_files/{whatsapp,screenshots}
mkdir -p ~/workspace/output/forensic_message_analyzer

# Copy and configure .env
cp .env.example ~/workspace/data/forensic_message_analyzer/.env
# Edit the .env file with your actual configuration
```

## Usage

### Full Analysis Pipeline

Run the complete forensic analysis:
```bash
python run.py
```

This executes five phases:
1. **Data Extraction**: Collects messages from all sources
2. **Automated Analysis**: Runs all configured analyzers
3. **Manual Review**: Flags items for human review
4. **Report Generation**: Creates comprehensive reports
5. **Documentation**: Generates chain of custody and manifest

### Individual Components

```python
from src.forensic_utils import ForensicRecorder, ForensicIntegrity
from src.extractors.imessage_extractor import IMessageExtractor
from src.extractors.whatsapp_extractor import WhatsAppExtractor
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.analyzers.sentiment_analyzer import SentimentAnalyzer
from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
from src.reporters.forensic_reporter import ForensicReporter
import pandas as pd

# Initialize forensic tracking
recorder = ForensicRecorder()
integrity = ForensicIntegrity(recorder)

# Extract iMessages (requires db_path, forensic_recorder, forensic_integrity)
db_path = "~/Library/Messages/chat.db"
imessage_extractor = IMessageExtractor(db_path, recorder, integrity)
imessages_df = imessage_extractor.extract_messages()

# Extract WhatsApp (requires export_dir, forensic_recorder, forensic_integrity)
export_dir = "~/workspace/data/forensic_message_analyzer/source_files/whatsapp/"
whatsapp_extractor = WhatsAppExtractor(export_dir, recorder, integrity)
whatsapp_df = whatsapp_extractor.extract_messages()

# Combine messages
combined_df = pd.concat([imessages_df, whatsapp_df], ignore_index=True)

# Analyze for threats (returns DataFrame with threat_detected column)
threat_analyzer = ThreatAnalyzer(recorder)
threats_df = threat_analyzer.detect_threats(combined_df)
threat_summary = threat_analyzer.generate_threat_summary(threats_df)

# Analyze sentiment (returns DataFrame with sentiment columns)
sentiment_analyzer = SentimentAnalyzer(recorder)
sentiment_df = sentiment_analyzer.analyze_sentiment(threats_df)

# Analyze behavioral patterns (returns dict)
behavioral_analyzer = BehavioralAnalyzer(recorder)
behavior_results = behavioral_analyzer.analyze_patterns(sentiment_df)

# Generate report
reporter = ForensicReporter(recorder)
reporter.generate_report(sentiment_df, 'forensic_report')
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
  - `extract_messages()`: Parse WhatsApp export files

- **DataExtractor(forensic_recorder)**: Coordinates all extraction
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

All outputs are timestamped and stored in the configured `OUTPUT_DIR`:

### Analysis Outputs
- `extracted_data_YYYYMMDD_HHMMSS.json` - Raw extracted messages
- `analysis_results_YYYYMMDD_HHMMSS.json` - Analysis findings
- `manual_review_summary_YYYYMMDD_HHMMSS.json` - Review decisions

### Reports
- `forensic_report_YYYYMMDD_HHMMSS.xlsx` - Excel report with multiple sheets
- `forensic_report_YYYYMMDD_HHMMSS.docx` - Word document report
- `forensic_report_YYYYMMDD_HHMMSS.pdf` - PDF report for court submission
- `timeline_YYYYMMDD_HHMMSS.html` - Interactive timeline visualization

### Documentation
- `chain_of_custody_YYYYMMDD_HHMMSS.json` - Complete audit trail
- `run_manifest_YYYYMMDD_HHMMSS.json` - Analysis process documentation

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