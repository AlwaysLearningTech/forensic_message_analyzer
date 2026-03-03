# Copilot Instructions for Forensic Message Analyzer

## CRITICAL RULES
1. **LOOK AT THE ACTUAL FILES** - Don't create scripts to check things, just read the files directly!
2. **NO UNNECESSARY SCRIPTS** - Stop creating diagnostic/fix scripts. Just fix the actual code!
3. **CHECK METHOD NAMES IN SOURCE** - Always look at the actual source file, not guess!
4. **BASH SCRIPTS GO IN EDITOR** - When creating bash scripts, output them to a new editor file, NOT to the terminal!
5. **NO GUESSING ALLOWED** - You MUST check the actual source files or documentation. Never guess method names, parameters, or return types. If you're not sure, look at the file!
6. **COMMIT AND PUSH EVERY CHANGE** - After every code change, immediately `git add`, `git commit` with a descriptive message, and `git push`. Do not batch changes or wait for the user to ask.

## Project Architecture
- The system is a multi-phase digital evidence processor for legal use, written in Python.
- Major components:
  - `src/extractors/`: Data extraction from iMessage, WhatsApp, email, Microsoft Teams, and screenshots
  - `src/analyzers/`: Automated analysis including threats, sentiment, patterns, OCR, metrics, and AI-powered analysis
  - `src/review/`: Manual review management, interactive review, and web-based review interface
  - `src/reporters/`: Report generation (Excel, Word, PDF, JSON, HTML, chat-bubble HTML)
  - `src/utils/`: Chain of custody, run manifest, timeline creation, conversation threading, legal compliance
  - `src/forensic_utils.py`: Core forensic integrity, evidence validation, and Daubert compliance
  - `src/config.py`: Configuration management with flexible contact mapping
  - `src/third_party_registry.py`: Third-party tool tracking for forensic provenance
- Contact Mapping System:
  - `PERSON1_NAME`, `PERSON2_NAME`, `PERSON3_NAME`: Names used in all reports (e.g., "John Doe")
  - `PERSON1_MAPPING`, `PERSON2_MAPPING`, `PERSON3_MAPPING`: JSON lists of identifiers (phones, emails, names, aliases)
  - Phone numbers automatically expand to match common formats (e.g., +12345678901 → also matches 234-567-8901, (234) 567-8901, 2345678901)
  - Only need to list each phone number ONCE in any format - variations generated automatically
  - Config creates `contact_mappings` dict mapping display names to expanded identifier lists
  - `AI_CONTACTS`: JSON array of person names whose conversations to send to AI (e.g., `'["Jane Doe"]'`)
    - Two-tier filter: at least one party must be in `ai_contacts_specified` (the raw AI_CONTACTS names),
      AND both parties must be in `ai_contacts` (expanded set including PERSON1_NAME)
    - `ai_contacts_specified` = set from AI_CONTACTS (e.g. {"Jane Doe"}), or None if unset (all mapped)
    - `ai_contacts` = ai_contacts_specified + PERSON1_NAME. If AI_CONTACTS unset, defaults to ALL mapped persons
    - Note: 'Me' is normalized to PERSON1_NAME during extraction (in DataExtractor.extract_all()),
      so downstream code never sees 'Me' as a sender/recipient
    - This ensures only conversations WITH the specified person are analyzed, not all conversations OF the user
    - This controls cost: analyzing only one person's conversations instead of all can reduce AI spend by 50%+
- Data flows: extraction → analysis → manual review → reporting → documentation
- All processing maintains forensic integrity and chain of custody.

## Core Classes and Their CORRECT Method Names (ACTUALLY VERIFIED BY LOOKING)
- **ForensicRecorder(output_dir=None)**: `src/forensic_utils.py` - Optional output_dir parameter
  - Methods: `record_action(action, details, metadata=None)`, `compute_hash(file_path)`, `generate_chain_of_custody(output_file=None)`
  - Methods: `verify_integrity(file_path, expected_hash)`, `record_file_state(file_path, operation)`, `record_error(error_type, error_message, context)`
  - Note: `record_action()` stores dict with keys: timestamp, action, details (NOT description), metadata, session_id
  - Note: `compute_hash()` takes a Path object, not bytes!
  - Note: `generate_chain_of_custody()` returns a string path (or None), chain data has 'actions' but NOT 'hashes'
- **ForensicIntegrity(forensic_recorder=None)**: `src/forensic_utils.py` - Optional ForensicRecorder (creates default if None)
  - Methods: `verify_read_only(file_path)`, `create_working_copy(source_path, dest_dir=None)`, `validate_extraction(source_path, extracted_data)`
- **EvidenceValidator**: `src/forensic_utils.py` - Evidence validation utilities
- **Config**: `src/config.py` - Configuration singleton
  - Attributes: `output_dir`, `review_dir`, `contact_mappings`, `ai_api_key`, `ai_model`, `ai_endpoint`
  - Attributes: `email_source_dir`, `teams_source_dir`, `messages_db_path`, `whatsapp_source_dir`, `screenshot_source_dir`
  - Attributes: `case_number`, `case_name`, `examiner_name`, `organization`, `timezone`
  - Attributes: `use_batch_api`, `tokens_per_minute`, `request_delay_ms`, `max_tokens_per_request`
  - Attributes: `ai_contacts` (expanded set including Me/PERSON1), `ai_contacts_specified` (raw AI_CONTACTS set or None)
  - Note: Does NOT have SOURCE_DIR attribute
- **ForensicAnalyzer(config=None)**: `src/main.py` - Main workflow orchestrator, takes **Config** (NOT ForensicRecorder!)
  - Creates internally: `self.forensic`, `self.integrity`, `self.manifest`, `self.third_party_registry`
  - Methods: `run_full_analysis()`, `run_extraction_phase()`, `run_analysis_phase(data)`, `run_review_phase(analysis, data)`, `run_behavioral_phase(data, analysis, review)`, `run_reporting_phase(data, analysis, review)`, `run_documentation_phase(data, analysis)`
  - Reporting phase calls: ForensicReporter, ExcelReporter, HtmlReporter, ChatReporter, JSONReporter
  - Documentation phase generates: chain of custody, timeline (with email events), run manifest
- **ThirdPartyRegistry(forensic_recorder, config=None)**: `src/third_party_registry.py` - Tracks third-party tools for forensic provenance
- **DataExtractor(forensic, third_party_registry=None)**: `src/extractors/data_extractor.py` - Takes ForensicRecorder
  - Method: `extract_all(start_date=None, end_date=None)` returns list of dicts with messages from all sources
  - Method: `validate_extraction(messages)` returns dict
  - Note: Internally creates ForensicIntegrity and initializes iMessage/WhatsApp/Email/Teams extractors with proper params
- **IMessageExtractor(db_path, forensic_recorder, forensic_integrity, config=None)**: `src/extractors/imessage_extractor.py`
  - Takes 3-4 parameters: db_path, forensic_recorder, forensic_integrity, optional config
  - Methods: `extract_messages()`, `decode_attributed_body(blob)`, `extract_text_with_fallback(text, attributed_body)`
  - Methods: `_parse_edit_history(blob_data)` — parses `message_summary_info` BLOB (iOS 16+ binary plist) to extract edit history as list of `{'timestamp': datetime, 'content': str}` dicts
  - Methods: `_compute_time_until_read(sent_ts, read_ts)` — returns human-readable read latency string ('2m 30s', '1h 15m', '2d 3h')
  - Methods: `_parse_chat_properties(cursor)` — parses per-chat `properties` BLOB for read receipt settings and SMS force flags
  - Methods: `_parse_rich_link(blob_data)` — extracts URL previews and shared locations from `payload_data` BLOB
  - Methods: `_get_recently_deleted_ids(cursor, placeholders, all_handles)` — queries `chat_recoverable_message_join` (iOS 16+) for deleted message ROWIDs
  - Methods: `_recover_deleted_messages(cursor, message_ids, msg_cols, att_cols)` — constructs full message dicts for orphaned deleted messages
  - Message dict fields include: `edit_history`, `time_until_read`, `date_edited`, `date_retracted`, `date_read`, `date_delivered`, `is_read`, `is_recently_deleted`, `chat_read_receipts_enabled`, `chat_force_sms`, `rich_link_url`, `rich_link_title`, `rich_link_summary`, `rich_link_site_name`, `rich_link_original_url`, `is_shared_location`, `location_name`, `location_address`, `location_city`, `location_state`, `location_postal_code`, `location_country`, `location_street`
  - Alias: iMessageExtractor (lowercase i) = IMessageExtractor
- **WhatsAppExtractor(export_dir, forensic_recorder, forensic_integrity)**: `src/extractors/whatsapp_extractor.py`
  - Takes 3 parameters: export_dir, forensic_recorder, forensic_integrity
  - Method: `extract_all()` returns list
- **EmailExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)**: `src/extractors/email_extractor.py`
  - Method: `extract_all()` returns List[Dict]
- **TeamsExtractor(source_dir, forensic_recorder, forensic_integrity, third_party_registry=None)**: `src/extractors/teams_extractor.py`
  - Method: `extract_all()`
- **ScreenshotExtractor(screenshot_dir, forensic_recorder)**: `src/extractors/screenshot_extractor.py`
  - Method: `extract_screenshots()` returns List[Dict]
- **ThreatAnalyzer(forensic)**: `src/analyzers/threat_analyzer.py` - Takes ForensicRecorder
  - Methods: `detect_threats(df)` and `generate_threat_summary(df)` - NOT analyze() or analyze_threats()!
- **SentimentAnalyzer(forensic)**: `src/analyzers/sentiment_analyzer.py` - Takes ForensicRecorder parameter!
  - Method: `analyze_sentiment(df)` - Returns DataFrame with columns: sentiment_score, sentiment_polarity, sentiment_subjectivity (NOT sentiment_label)
  - Method: `generate_sentiment_summary(df)` - Returns Dict
- **BehavioralAnalyzer(forensic)**: `src/analyzers/behavioral_analyzer.py` - Takes ForensicRecorder
  - Method: `analyze_patterns(df)` - Returns dict with behavioral analysis results
- **YamlPatternAnalyzer(forensic, patterns_file=None)**: `src/analyzers/yaml_pattern_analyzer.py` - Takes ForensicRecorder
  - Method: `analyze_patterns(df)` - Returns DataFrame with patterns_detected and pattern_score columns
  - Method: `analyze_communication_frequency(df)` - Returns Dict
- **ScreenshotAnalyzer(forensic, third_party_registry=None)**: `src/analyzers/screenshot_analyzer.py` - Takes ForensicRecorder
  - Method: `analyze_screenshots()` - NO parameters! NOT process_screenshots()!
- **AttachmentProcessor(forensic)**: `src/analyzers/attachment_processor.py` - Takes ForensicRecorder
  - Method: `process_attachments(attachment_dir=None)` - Takes optional **Path**, NOT DataFrame!
  - Methods: `process_single_attachment(file_path)`, `categorize_file_type(mime_type)`, `extract_image_metadata()`, `generate_attachment_summary()`
- **CommunicationMetricsAnalyzer(forensic_recorder=None)**: `src/analyzers/communication_metrics.py` - Optional ForensicRecorder
  - Method: `analyze_messages(messages)` - Takes list of message dicts (NOT DataFrame), returns dict
  - Alias: CommunicationMetrics = CommunicationMetricsAnalyzer
- **AIAnalyzer(forensic_recorder=None)**: `src/analyzers/ai_analyzer.py` - Optional ForensicRecorder (requires API key)
  - Method: `analyze_messages(messages, batch_size=50)` - Takes list of dicts, NOT analyze(df, threat_results)!
  - Methods: `analyze_single_message(message)`, `_estimate_tokens(text)`, `_empty_analysis()`
- **ManualReviewManager(review_dir=None)**: `src/review/manual_review_manager.py` - Optional review_dir parameter
  - Method: `add_review(item_id, item_type, decision, notes="")` - Takes positional arguments
  - Method: `get_reviews_by_decision(decision)` - Gets reviews by decision type
  - Method: `get_reviews_by_type(item_type)`, `get_review_summary()`, `load_reviews(session_id)`
  - Note: Does NOT have `load_existing_reviews()` method! But DOES have `load_reviews(session_id)`
- **InteractiveReview(review_manager)**: `src/review/interactive_review.py` - Takes ManualReviewManager
- **WebReview(review_manager, forensic_recorder=None)**: `src/review/web_review.py` - Web-based review interface
- **TimelineGenerator(forensic)**: `src/utils/timeline_generator.py` - Takes ForensicRecorder
  - Method: `create_timeline(df, output_path, raw_messages=None, extracted_data=None)` - NOT generate_timeline()!
  - Method: `generate_html_timeline(df, raw_messages=None, extracted_data=None)`
  - Note: Requires DataFrame and output path; raw_messages and extracted_data are optional
  - Note: When extracted_data is provided, all email messages are included on the timeline as "email" or "third-party-email" events
- **ConversationThreader(default_gap_hours=2.0)**: `src/utils/conversation_threading.py` - Used by TimelineGenerator
- **RunManifest(forensic_recorder=None)**: `src/utils/run_manifest.py` - Optional ForensicRecorder
  - Methods: `add_input_file()`, `add_output_file()`, `generate_manifest(output_path=None)`
  - Methods: `add_operation()`, `validate_manifest()`, `add_extraction_summary()`, `add_analysis_summary()`, `add_report_summary()`
  - Note: `generate_manifest()` returns a Path object, not a dict!
  - Note: Files must exist to be added properly
- **ExcelReporter(forensic_recorder, config=None)**: `src/reporters/excel_reporter.py` - Standalone Excel report generator
  - Method: `generate_report(extracted_data, analysis_results, review_decisions, output_path)` - Returns Path
  - Sheets produced: Overview, Findings Summary, AI Analysis, Timeline, per-person chat tabs, Conversation Threads, Manual Review, Third Party Contacts
  - Note: Person1 does NOT get a per-person tab (every other tab already shows their conversations)
  - Note: All mapped persons get sheets even if they have zero messages (documents absence of communication)
  - Note: Timeline sheet includes email events labeled "Email" or "Third-Party Email"
- **HtmlReporter(forensic_recorder, config=None)**: `src/reporters/html_reporter.py` - HTML/PDF report with inline images
  - Method: `generate_report(extracted_data, analysis_results, review_decisions, output_path, pdf=True)` - Returns Dict[str, Path]
  - Includes: overview cards, per-person message tables, conversation threads, risk indicators, AI summary
  - Includes: Legal appendices (Appendix A: Methodology, Appendix B: Completeness Validation, Appendix C: Limitations)
  - Inline base64 attachment images, forensic status indicators (SOS, Unsent, Edited, Deleted, SMS, Tapback)
  - Edit history display below edited messages (original text with timestamps)
  - URL preview rendering (title, site name, URL) and shared location display (name, address)
  - PDF via WeasyPrint (degrades gracefully if WeasyPrint unavailable)
- **ChatReporter(forensic_recorder, config=None)**: `src/reporters/chat_reporter.py` - iMessage-style chat-bubble HTML report
  - Method: `generate_report(extracted_data, analysis_results, review_decisions, output_path)` - Returns Dict[str, Path]
  - Per-person chat sections with left/right aligned message bubbles
  - Inline attachment images, threat/sentiment indicators, conversation threading
  - Edit history rendering below message bubbles (original and intermediate edits with timestamps)
  - Recently deleted message badge (red "Deleted" flag)
  - URL preview display (blue border) and shared location display (green border)

## IMPORTANT: Verified Method Names and Signatures
- ForensicAnalyzer takes **Config** (NOT ForensicRecorder!) - `ForensicAnalyzer(config=None)`
- ThreatAnalyzer uses `detect_threats()` and `generate_threat_summary()` - NOT analyze() or analyze_threats()
- SentimentAnalyzer uses `analyze_sentiment()` NOT analyze() - returns DataFrame with sentiment_polarity NOT sentiment_label
- SentimentAnalyzer REQUIRES `forensic` parameter in __init__
- BehavioralAnalyzer uses `analyze_patterns()` NOT analyze()
- YamlPatternAnalyzer uses `analyze_patterns()` NOT analyze_with_patterns()
- CommunicationMetricsAnalyzer uses `analyze_messages(messages)` NOT analyze() or calculate_metrics() - takes list NOT DataFrame
- AIAnalyzer uses `analyze_messages(messages, batch_size=50)` NOT analyze(df, threat_results)!
- ScreenshotAnalyzer uses `analyze_screenshots()` with NO params - NOT process_screenshots(paths)!
- AttachmentProcessor.process_attachments takes optional **Path** - NOT DataFrame!
- TimelineGenerator uses `create_timeline(df, output_path, raw_messages=None, extracted_data=None)` NOT generate_timeline()
- ManualReviewManager uses `add_review()` with positional arguments, NO `load_existing_reviews()` method but HAS `load_reviews(session_id)`
- ForensicRecorder has optional `output_dir` param - `ForensicRecorder(output_dir=None)`
- ForensicRecorder.record_action(action, details, metadata) creates dict with 'details' NOT 'description'
- ForensicRecorder.compute_hash() takes a Path object, not bytes
- ForensicRecorder.generate_chain_of_custody(output_file=None) returns string path or None, chain JSON has 'actions' but NOT 'hashes'
- ForensicIntegrity has **optional** forensic_recorder param (creates default if None)
- ManualReviewManager has optional `review_dir` param
- RunManifest has optional `forensic_recorder` param - NOT required
- RunManifest.generate_manifest(output_path=None) returns a Path, not a dict
- RunManifest only adds files that exist
- DataExtractor has optional `third_party_registry` param, `extract_all()` has optional date filters
- DataExtractor.extract_all() returns list of message dicts, not dict with source keys
- IMessageExtractor requires (db_path, forensic_recorder, forensic_integrity, config=None) - 3-4 params!
- WhatsAppExtractor requires (export_dir, forensic_recorder, forensic_integrity) - 3 params!
- EmailExtractor requires (source_dir, forensic_recorder, forensic_integrity, third_party_registry=None) - 3-4 params
- TeamsExtractor requires (source_dir, forensic_recorder, forensic_integrity, third_party_registry=None) - 3-4 params
- ScreenshotExtractor requires (screenshot_dir, forensic_recorder) - 2 params
- Always look at the actual source code files - DON'T CREATE SCRIPTS TO CHECK!
- NEVER GUESS - if unsure, read the actual file!

## Developer Workflows
- **Run full analysis:** `python3 run.py`
- **Pre-run validation:** `python3 validate_before_run.py` (runs 8 checks including end-to-end pipeline test; prompts before cleaning temp output)
- **Validate without AI spend:** `python3 validate_before_run.py --no-ai` or `python3 validate_before_run.py --estimate`
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
                               │   ├── screenshots/
                               │   ├── email/
                               │   └── microsoft_teams_personal/
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
15. **Extractors need 3+ params**: IMessageExtractor needs (path, forensic, integrity, config=None) and WhatsAppExtractor needs (path, forensic, integrity)
16. **Anthropic base_url override**: Always pass `base_url="https://api.anthropic.com"` when creating Anthropic clients. VS Code injects `ANTHROPIC_BASE_URL=http://localhost:...` which hijacks the SDK and causes 401 errors.
17. **Batch API timeout**: Batch polling has a 4-hour max wait. If a batch doesn't complete in time, it raises TimeoutError instead of blocking forever.
18. **Sync fallback guard**: If batch API fails AFTER submission (timeout, partial failure), do NOT fall back to sync — that would re-process everything at full price.
19. **WebReview runs Flask in daemon thread**: `start_review()` uses `threading.Event` for shutdown, NOT `os.kill(SIGINT)`. This prevents killing the parent pipeline when the user clicks "Complete Review".

## Key Files Reference
- **Main workflow**: `src/main.py`
- **Configuration**: `src/config.py`, `.env.example`
- **Forensic utilities**: `src/forensic_utils.py`
- **Reporters**: `src/reporters/excel_reporter.py`, `src/reporters/html_reporter.py`, `src/reporters/chat_reporter.py`, `src/reporters/forensic_reporter.py`, `src/reporters/json_reporter.py`
- **Timeline**: `src/utils/timeline_generator.py`
- **Legal compliance**: `src/utils/legal_compliance.py`
- **Tests**: `tests/test_integration.py`, `tests/test_core_functionality.py`, `tests/test_forensic_utils.py`, `tests/test_imports.py`, `tests/test_teams_extractor.py`, `tests/test_third_party_registry.py`
- **Documentation**: `README.md`, `CHANGELOG.md`, this file

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
