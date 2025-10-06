# Changelog

All notable changes to the Forensic Message Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **WhatsApp ZIP Auto-Extraction**: System now automatically extracts ZIP files in the WhatsApp source directory
- **Recipient Tracking**: All messages now include both sender and recipient fields for complete conversation tracking
- **Excel Filtering**: Excel reports now only show conversations with configured persons (excludes random phone numbers and chat IDs)
- **Enhanced PDF Reports**: PDF reports now include Screenshots, Threat Analysis, Sentiment Analysis, Manual Review sections, and Chain of Custody reference (matching Word document content)
- **attributedBody Binary Decoding**: Modern iMessage format with binary-encoded messages now properly decoded
- **WhatsApp Timestamp Formats**: Added 12 timestamp formats including seconds (e.g., "3/8/22, 4:12:34 PM")

### Changed
- **Output Directory**: Fixed ForensicRecorder to use configured output directory instead of creating ./output/ in repository
- **WhatsApp Regex Pattern**: Updated to match actual WhatsApp export format with optional seconds in timestamp
- **Excel Report Structure**: Now creates individual tabs for each configured person with integrated threat/sentiment columns
- **iMessage Extraction**: Added chat_identifier JOIN to SQL query for recipient determination
- **Contact Mapping**: Recipient names now mapped to configured person names from .env

### Fixed
- **Config Import in forensic_utils.py**: Changed from singleton pattern to class instantiation for proper dependency injection
- **WhatsApp Message Count**: Extraction now works correctly (0 → 33,808 messages in test case)
- **Excel Tab Explosion**: Reduced from 130+ tabs to only configured persons (3 in typical case)
- **PDF Content**: Now matches Word document with all sections included

### Technical Improvements
- Removed unused imports from main.py (IMessageExtractor, WhatsAppExtractor, AttachmentProcessor)
- Implemented proper dependency injection for Config class (created in run.py, passed to main)
- Added message enrichment logic to merge threat/sentiment data before Excel generation
- Enhanced Excel sheet name sanitization for invalid characters
- Comprehensive test coverage verified with targeted test scripts

### Documentation
- Updated README.md Features section with new capabilities
- Updated README.md Usage section with correct API examples and Expected Output
- Updated README.md Output Files section with detailed Excel structure
- Updated QUICK_START.md Output Files section
- Created IMPROVEMENTS_LOG.md with comprehensive session documentation
- Updated CODE_REVIEW.md with applied fixes and new grade (B+ → A-)
- Created this CHANGELOG.md for version tracking

### Testing
- Created test_excel_simple.py to verify Excel filtering
- Created test_excel_filter.py with comprehensive test scenarios
- Verified: Only mapped persons appear in Excel tabs (excludes unmapped recipients)
- All 25 existing tests still passing

## [1.0.0] - Initial Release

### Core Features
- Multi-phase workflow: Extraction → Analysis → Review → Reporting → Documentation
- iMessage extraction with modern format support
- WhatsApp export processing
- Screenshot OCR analysis with Tesseract
- Threat detection with configurable patterns (YAML-based)
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
- 26 unit and integration tests

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
For quick start guide, see [QUICK_START.md](QUICK_START.md).
