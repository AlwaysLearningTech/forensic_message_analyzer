# Copilot Instructions for Forensic Message Analyzer

## CRITICAL RULES
1. **LOOK AT THE ACTUAL FILES** - Don't create scripts to check things, just read the files directly!
2. **NO UNNECESSARY SCRIPTS** - Stop creating diagnostic/fix scripts. Just fix the actual code!
3. **CHECK METHOD NAMES IN SOURCE** - Always look at the actual source file, not guess!
4. **BASH SCRIPTS GO IN EDITOR** - When creating bash scripts, output them to a new editor file, NOT to the terminal!
5. **NO GUESSING ALLOWED** - You MUST check the actual source files or documentation. Never guess method names, parameters, or return types. If you're not sure, look at the file!

## Project Architecture
- The system is a multi-phase digital evidence processor for legal use, written in Python.
- Major components:
  - `src/extractors/`: Data extraction from iMessage, WhatsApp, and screenshots
  - `src/analyzers/`: Automated analysis including threats, sentiment, patterns, OCR, metrics, and AI-powered analysis
  - `src/review/`: Manual review management and decision tracking
  - `src/reporters/`: Report generation (Excel, Word, PDF, JSON)
  - `src/utils/`: Chain of custody, run manifest, timeline creation
  - `src/forensic_utils.py`: Core forensic integrity and Daubert compliance
  - `src/config.py`: Configuration management with flexible contact mapping
- Contact Mapping System:
  - `PERSON1_NAME`, `PERSON2_NAME`, `PERSON3_NAME`: Names used in all reports (e.g., "John Doe")
  - `PERSON1_MAPPING`, `PERSON2_MAPPING`, `PERSON3_MAPPING`: JSON lists of identifiers (phones, emails, names, aliases)
  - Phone numbers automatically expand to match common formats (e.g., +12345678901 → also matches 234-567-8901, (234) 567-8901, 2345678901)
  - Only need to list each phone number ONCE in any format - variations generated automatically
  - Config creates `contact_mappings` dict mapping display names to expanded identifier lists
- Data flows: extraction → analysis → manual review → reporting → documentation
- All processing maintains forensic integrity and chain of custody.

## Core Classes and Their CORRECT Method Names (ACTUALLY VERIFIED BY LOOKING)
- **ForensicRecorder()**: `src/forensic_utils.py` - No parameters
  - Methods: `record_action(action, details, metadata=None)`, `compute_hash(file_path)`, `generate_chain_of_custody()`
  - Note: `record_action()` stores dict with keys: timestamp, action, details (NOT description), metadata, session_id
  - Note: `compute_hash()` takes a Path object, not bytes!
  - Note: `generate_chain_of_custody()` returns a string path, chain data has 'actions' but NOT 'hashes'
- **ForensicIntegrity(recorder)**: `src/forensic_utils.py` - Takes ForensicRecorder
  - Methods: `verify_read_only()`, `create_working_copy()`
- **Config**: `src/config.py` - Configuration singleton
  - Attributes: `output_dir`, `review_dir`, `contact_mappings`, etc (NOT SOURCE_DIR)
- **ForensicAnalyzer(forensic)**: `src/main.py` - Main workflow orchestrator
- **DataExtractor(forensic)**: `src/extractors/data_extractor.py` - Takes ForensicRecorder
  - Method: `extract_all()` returns list of dicts with messages from all sources
  - Note: Internally creates ForensicIntegrity and initializes iMessage/WhatsApp extractors with proper params
- **IMessageExtractor(db_path, forensic_recorder, forensic_integrity)**: `src/extractors/imessage_extractor.py`
  - Takes 3 parameters: db_path, forensic_recorder, forensic_integrity
  - Alias: iMessageExtractor (lowercase i) = IMessageExtractor
- **WhatsAppExtractor(export_dir, forensic_recorder, forensic_integrity)**: `src/extractors/whatsapp_extractor.py`
  - Takes 3 parameters: export_dir, forensic_recorder, forensic_integrity
- **ThreatAnalyzer(forensic)**: `src/analyzers/threat_analyzer.py` - Takes ForensicRecorder
  - Methods: `detect_threats(df)` and `generate_threat_summary(df)` - NOT analyze() or analyze_threats()!
- **SentimentAnalyzer(forensic)**: `src/analyzers/sentiment_analyzer.py` - Takes ForensicRecorder parameter!
  - Method: `analyze_sentiment(df)` - Returns DataFrame with columns: sentiment_score, sentiment_polarity, sentiment_subjectivity (NOT sentiment_label)
- **BehavioralAnalyzer(forensic)**: `src/analyzers/behavioral_analyzer.py` - Takes ForensicRecorder
  - Method: `analyze_patterns(df)` - Returns dict with behavioral analysis results
- **YamlPatternAnalyzer(forensic, patterns_file=None)**: `src/analyzers/yaml_pattern_analyzer.py` - Takes ForensicRecorder
  - Method: `analyze_patterns(df)` - Returns DataFrame with patterns_detected and pattern_score columns
- **ScreenshotAnalyzer(forensic)**: `src/analyzers/screenshot_analyzer.py` - Takes ForensicRecorder
  - Method: `process_screenshots(screenshot_paths)`
- **AttachmentProcessor(forensic)**: `src/analyzers/attachment_processor.py` - Takes ForensicRecorder
  - Method: `process_attachments(df)`
- **CommunicationMetricsAnalyzer(forensic_recorder=None)**: `src/analyzers/communication_metrics.py` - Optional ForensicRecorder
  - Method: `analyze_messages(messages)` - Takes list of message dicts (NOT DataFrame), returns dict
  - Alias: CommunicationMetrics = CommunicationMetricsAnalyzer
- **AIAnalyzer(forensic)**: `src/analyzers/ai_analyzer.py` - Takes ForensicRecorder (optional, requires API key)
  - Method: `analyze(df, threat_results)`
- **ManualReviewManager()**: `src/review/manual_review_manager.py` - No parameters
  - Method: `add_review(item_id, item_type, decision, notes)` - Takes positional arguments
  - Method: `get_reviews_by_decision(decision)` - Gets reviews by decision type
  - Note: Does NOT have `load_existing_reviews()` method!
- **TimelineGenerator(forensic)**: `src/utils/timeline_generator.py` - Takes ForensicRecorder
  - Method: `create_timeline(df, output_path)` - NOT generate_timeline()!
  - Note: Requires DataFrame and output path
- **RunManifest(recorder)**: `src/utils/run_manifest.py` - Takes ForensicRecorder
  - Methods: `add_input_file()`, `add_output_file()`, `generate_manifest()`
  - Note: `generate_manifest()` returns a Path object, not a dict!
  - Note: Files must exist to be added properly

## IMPORTANT: Verified Method Names and Signatures
- ThreatAnalyzer uses `detect_threats()` and `generate_threat_summary()` - NOT analyze() or analyze_threats()
- SentimentAnalyzer uses `analyze_sentiment()` NOT analyze() - returns DataFrame with sentiment_polarity NOT sentiment_label
- SentimentAnalyzer REQUIRES `forensic` parameter in __init__
- BehavioralAnalyzer uses `analyze_patterns()` NOT analyze()
- YamlPatternAnalyzer uses `analyze_patterns()` NOT analyze_with_patterns()
- CommunicationMetricsAnalyzer uses `analyze_messages(messages)` NOT analyze() or calculate_metrics() - takes list NOT DataFrame
- TimelineGenerator uses `create_timeline(df, output_path)` NOT generate_timeline()
- ManualReviewManager uses `add_review()` with positional arguments, NO `load_existing_reviews()` method
- ForensicRecorder.record_action(action, details, metadata) creates dict with 'details' NOT 'description'
- ForensicRecorder.compute_hash() takes a Path object, not bytes
- ForensicRecorder.generate_chain_of_custody() returns string path, chain JSON has 'actions' but NOT 'hashes'
- RunManifest.generate_manifest() returns a Path, not a dict
- RunManifest only adds files that exist
- DataExtractor.extract_all() returns list of message dicts, not dict with source keys
- IMessageExtractor requires (db_path, forensic_recorder, forensic_integrity) - 3 params!
- WhatsAppExtractor requires (export_dir, forensic_recorder, forensic_integrity) - 3 params!
- Always look at the actual source code files - DON'T CREATE SCRIPTS TO CHECK!
- NEVER GUESS - if unsure, read the actual file!

## Developer Workflows
- **Run full analysis:** `python3 run.py`
- **Run all tests:** `python3 -m pytest tests/ -v`
- **Run specific tests:** `python3 -m pytest tests/test_integration.py -v`
- **Install dependencies:** `pip install -r requirements.txt`
- **Configure environment:** 
  1. Copy `.env.example` to `.env`
  2. Edit `.env` with your configuration
  3. Ensure data directories exist
- **Check imports:** `python3 tests/test_imports.py`

## Data Separation Strategy
```
Repository (code only)          Local Data Storage
├── src/                        ~/workspace/data/forensic_message_analyzer/
├── tests/                      ├── .env (actual configuration)
├── patterns/                   │   Example:
├── .env.example               │   PERSON1_NAME="John Doe"
└── README.md                  │   PERSON1_MAPPING='["+12345678901","john@example.com","John"]'
                               │   (phone numbers auto-expand to all common formats)
                               ├── source_files/
                               │   ├── whatsapp/
                               │   └── screenshots/
                               ├── review/
                               └── logs/
                               
                               ~/workspace/output/forensic_message_analyzer/
                               └── [all analysis outputs]
```

## Project-Specific Patterns
- **Read-only processing**: Originals are never modified
- **Hashing**: Every file and step is SHA-256 hashed
- **Logging**: All actions logged via `forensic.record_action()`
- **Manual review**: Decisions persisted in JSON files
- **Pattern detection**: Uses YAML definitions in `patterns/analysis_patterns.yaml`
- **OCR**: Screenshots analyzed with Tesseract via `pytesseract`
- **Attachments**: Cataloged with `python-magic` and `Pillow`
- **Reports**: Multiple formats for different audiences (legal, technical)

## Legal Defensibility (FRE/Daubert)
### Authentication (FRE 901)
- Compute SHA-256 hashes for all files
- Log timestamps and actions
- Maintain chain of custody
- Never alter originals

### Best Evidence (FRE 1002)
- Preserve full metadata
- Ensure deterministic extraction
- Export unaltered content
- Create working copies for analysis

### Business Records (FRE 803)
- Retain creation metadata
- Document regular course of communication
- Avoid content editing
- Track all processing steps

### Daubert Factors
- **Testing**: Comprehensive unit and integration tests
- **Peer review**: Uses established libraries (pandas, Pillow, etc.)
- **Error rates**: Logs all anomalies and validation stats
- **Standards**: Follows SWGDE/NIST guidelines
- **Acceptance**: Standard formats and verifiable processes

## Common Issues and Solutions
1. **Import errors**: Check that all required packages are installed
2. **Config validation fails**: Ensure `.env` file exists with required settings in `~/workspace/data/forensic_message_analyzer/`
3. **No data extracted**: Check source file paths in `.env`
4. **Tests failing**: Run `pytest tests/test_imports.py` first to check dependencies
5. **Method not found**: Look at the actual file - DON'T CREATE SCRIPTS!
6. **Config has no SOURCE_DIR**: Use config attributes that actually exist
7. **Wrong method names in tests**: Read the actual source file directly
8. **SentimentAnalyzer needs forensic param**: Pass ForensicRecorder to SentimentAnalyzer()
9. **compute_hash needs Path**: Pass Path object, not bytes to compute_hash()
10. **Chain of custody has no 'hashes' key**: It only has 'actions', not 'hashes'
11. **SentimentAnalyzer returns sentiment_polarity**: Not sentiment_label
12. **CommunicationMetricsAnalyzer takes list**: analyze_messages() takes list of dicts, NOT DataFrame
13. **TimelineGenerator needs df and path**: create_timeline(df, output_path) requires both parameters
14. **DataExtractor needs config paths**: Extractors are None if config doesn't have paths set
15. **Extractors need 3 params**: IMessageExtractor and WhatsAppExtractor need (path, forensic, integrity)

## Key Files Reference
- **Main workflow**: `src/main.py`
- **Configuration**: `src/config.py`, `.env.example`
- **Forensic utilities**: `src/forensic_utils.py`
- **Tests**: `tests/test_integration.py`, `tests/test_imports.py`
- **Documentation**: `README.md`, this file

## Conventions
- Use `forensic.record_action()` for all significant operations
- Name output files with timestamps: `report_YYYYMMDD_HHMMSS.ext`
- Place new analyzers in `src/analyzers/`
- Update `main.py` when adding new analysis phases
- Write tests for new components
- Document legal compliance in code comments
- Always use python3 on macOS, not python
- ALWAYS look at actual files - DON'T CREATE DIAGNOSTIC SCRIPTS!
- Output bash scripts to editor files, NOT terminal!
- NEVER GUESS method names or return types - READ THE FILE!

---
For legal questions, refer to README.md and chain of custody documentation. For technical issues, check logs in `output/` directory.
