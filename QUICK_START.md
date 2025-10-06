# Quick Start Guide

## First-Time Setup

### 1. Install Dependencies
```bash
cd ~/workspace/repos/forensic_message_analyzer
pip3 install -r requirements.txt

# Install Tesseract OCR (for screenshot text extraction)
brew install tesseract  # macOS
```

### 2. Create Data Directories
```bash
# Create the data directory structure (outside the repository)
mkdir -p ~/workspace/data/forensic_message_analyzer/{source_files,review,logs}
mkdir -p ~/workspace/data/forensic_message_analyzer/source_files/{whatsapp,screenshots}
mkdir -p ~/workspace/output/forensic_message_analyzer
```

### 3. Configure Environment
```bash
# Copy the example configuration to the data directory
cp .env.example ~/workspace/data/forensic_message_analyzer/.env

# Edit the configuration file
nano ~/workspace/data/forensic_message_analyzer/.env
```

**Required Settings:**
- Define `PERSON1_NAME`, `PERSON2_NAME`, `PERSON3_NAME` - these are the names that will appear in all reports
- Define `PERSON1_MAPPING`, `PERSON2_MAPPING`, `PERSON3_MAPPING` - lists of identifiers (phone numbers, emails, names, aliases) to match each person
- Verify `MESSAGES_DB_PATH` points to your iMessage database (macOS default: `~/Library/Messages/chat.db`)
- Set `WHATSAPP_SOURCE_DIR` if analyzing WhatsApp exports
- Set `SCREENSHOT_SOURCE_DIR` if analyzing screenshots

**Contact Mapping Example:**
   ```bash
   # Contact Mapping - Define names for reports and their identifiers
   PERSON1_NAME="John Doe"
   # Phone numbers auto-expand: +12345678901 also matches 234-567-8901 and (234) 567-8901
   # Use single quotes around the JSON array to avoid parsing issues
   PERSON1_MAPPING='["+12345678901","john@example.com","John","JD"]'
   
   PERSON2_NAME="Jane Smith"
   PERSON2_MAPPING='["+19876543210","jane@example.com","Jane"]'
   
   PERSON3_NAME="Bob Johnson"
   PERSON3_MAPPING='["bob@example.com","Bob"]'
   ```
This will identify any message from "+1234567890", "john@example.com", "John", or "Johnny" as coming from "John Doe" in reports.

**Optional Settings:**
- Add Azure OpenAI credentials for AI-powered analysis
- Adjust thresholds and analysis settings

### 4. Verify Setup
```bash
# Check that everything is configured correctly
python3 check_readiness.py
```

### 5. Run Tests
```bash
# Verify all components are working
./tests/run_all_tests.sh
```

## Running Analysis

### Full Analysis Pipeline
```bash
python3 run.py
```

This will:
1. Extract messages from configured sources
2. Run all automated analyzers
3. Flag items for manual review
4. Generate comprehensive reports
5. Create chain of custody documentation

### Output Files

All outputs are saved to `~/workspace/output/forensic_message_analyzer/`:

- `extracted_data_YYYYMMDD_HHMMSS.json` - Raw extracted messages with sender, recipient, content, timestamp
- `analysis_results_YYYYMMDD_HHMMSS.json` - Analysis findings (threats, sentiment, patterns, metrics)
- `report_YYYYMMDD_HHMMSS.xlsx` - Excel report with person-organized tabs (only configured persons, excludes random numbers)
- `forensic_report_YYYYMMDD_HHMMSS.docx` - Word report with full analysis
- `forensic_report_YYYYMMDD_HHMMSS.pdf` - PDF report for court submission
- `chain_of_custody_YYYYMMDD_HHMMSS.json` - Complete audit trail
- `run_manifest_YYYYMMDD_HHMMSS.json` - Analysis documentation
- `timeline_YYYYMMDD_HHMMSS.html` - Interactive timeline

**Excel Report Structure:**
- **Overview**: Summary statistics
- **[Person Name]**: Individual tabs for each configured person (e.g., "Marcia Snyder")
  - Only messages where that person is the recipient
  - Integrated threat and sentiment columns
- **All Messages**: Complete dataset filtered to only configured persons
- **Manual Review**: Review decisions (if applicable)

Note: The Excel report only includes conversations with legally relevant parties (configured persons). Random phone numbers and chat IDs are automatically excluded.

## Common Tasks

### Analyze Specific Date Range
Edit `~/workspace/data/forensic_message_analyzer/.env`:
```bash
START_DATE=2024-01-01
END_DATE=2024-12-31
```

### Export WhatsApp Data for Analysis

1. On your phone, open WhatsApp
2. Go to the chat you want to export
3. Tap the menu (⋮) → More → Export chat
4. Choose "Without Media" (or "With Media" if needed)
5. Save the exported file to:
   ```
   ~/workspace/data/forensic_message_analyzer/source_files/whatsapp/
   ```

### Add Screenshots for OCR Analysis

Place screenshot images in:
```
~/workspace/data/forensic_message_analyzer/source_files/screenshots/
```

Supported formats: PNG, JPG, JPEG

### Manual Review Process

After running analysis, review flagged items:
```bash
# Review decisions are stored in:
~/workspace/data/forensic_message_analyzer/review/manual_reviews.json
```

The system will guide you through items that need manual review.

## Troubleshooting

### "No .env file found"
- Make sure `.env` exists at `~/workspace/data/forensic_message_analyzer/.env`
- Check that you copied from `.env.example` and edited the values

### "No data sources configured"
- Edit `.env` and ensure at least one source is configured:
  - `MESSAGES_DB_PATH` for iMessage
  - `WHATSAPP_SOURCE_DIR` for WhatsApp
  - `SCREENSHOT_SOURCE_DIR` for screenshots

### Contact mapping not working
- Ensure JSON arrays are wrapped in single quotes: `PERSON1_MAPPING='["value1","value2"]'`
- Use dashes in phone numbers (555-123-4567) not parentheses ((555) 123-4567)
- Check that `PERSON1_NAME` and `PERSON1_MAPPING` are both set in `.env`

### "Permission denied" for iMessage database
- On macOS, grant Terminal "Full Disk Access" in System Preferences → Security & Privacy → Privacy

### Tests failing
```bash
# Check dependencies
python3 -m pytest tests/test_imports.py -v

# Run specific test suites
python3 -m pytest tests/test_core_functionality.py -v
python3 -m pytest tests/test_integration.py -v
```

## Data Separation

**IMPORTANT**: The project uses a strict separation between code and data:

- **Code** (in GitHub): `/workspace/repos/forensic_message_analyzer/`
- **Data** (local only): `/workspace/data/forensic_message_analyzer/`
- **Output** (local only): `/workspace/output/forensic_message_analyzer/`

This ensures:
- Sensitive information never goes to version control
- Clean separation of concerns
- Easy backup of analysis results separate from code

## Next Steps

1. Review the full [README.md](README.md) for detailed documentation
2. Check [.github/copilot-instructions.md](.github/copilot-instructions.md) for development guidelines
3. Explore the `patterns/analysis_patterns.yaml` file to customize pattern detection
4. Review generated reports to understand the output format

## Support

- Check logs in `~/workspace/data/forensic_message_analyzer/logs/`
- Review chain of custody for detailed action history
- See README.md for architecture and legal compliance information
