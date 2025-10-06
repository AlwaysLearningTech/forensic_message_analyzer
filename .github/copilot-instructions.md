# Copilot Instructions for Forensic Analyzer Python

## Project Architecture
- The system is a multi-phase digital evidence processor for legal use, written in Python.
- Major components:
  - `src/extractors/`: Data extraction from iMessage and WhatsApp backups
  - `src/analyzers/`: Automated review, threat detection, sentiment, pattern, screenshot OCR, metrics, and attachment analysis
  - `src/review/`: Manual review management and decision tracking
  - `src/reporters/`: Report generation (Excel, Word, PDF)
  - `src/utils/`: Chain of custody, run manifest, timeline creation
- Data flows from extraction → analysis → manual review → reporting → documentation.
- All processing is tracked for evidence integrity and chain of custody.

## Developer Workflows
- **Run full analysis:** `python run.py` (uses `src/main.py`)
- **Run tests:** `pytest tests/test_integration.py -v`
- **Install dependencies:** `pip install -r requirements.txt`
- **Configure environment:** Copy `.env.example` to `.env` and edit as needed.
- **Output files:** All reports and logs are written to the `output/` directory.

## Project-Specific Patterns
- All evidence processing is read-only; originals are never modified.
- Every file and processing step is hashed (SHA-256) and logged for audit.
- Manual review decisions are persisted in `output/manual_reviews.json` and summarized in `manual_review_summary_*.json`.
- Pattern detection uses YAML definitions in `patterns/analysis_patterns.yaml` (auto-generated if missing).
- Screenshot OCR uses Tesseract via `pytesseract` and `Pillow`.
- Attachments are cataloged with `python-magic` and image metadata via `Pillow`.
- Communication metrics and timeline visualizations are generated for legal review.

## Legal Best Practices & Defensibility
- Write in plain language for non-technical legal teams. When you cite a standard, also state how and why the code/process satisfies it.
- Authentication (FRE 901): Always compute and store SHA-256 hashes for source files and outputs; log precise timestamps and actors via `forensic.record_action()`; never alter originals (read-only access, work on copies).
- Best Evidence (FRE 1002): Preserve full metadata (timestamps, sender, ids); ensure extractions are deterministic and reproducible; export unaltered content alongside derived analyses.
- Hearsay exception (FRE 803 business records): Retain message creation metadata and extraction context; avoid content editing; document that data was collected in the regular course of communication.
- Reliability (Daubert factors):
  - Testing: Add/maintain unit and integration tests for extractors/analyzers; re-running the same input must yield identical outputs (verify with hashes).
  - Peer review/standards: Prefer widely used libraries (pandas, Pillow, pytesseract, python-magic); align implementations with documented methods in `README.md`.
  - Known/low error rates: Log extraction/analysis anomalies; surface validation stats (missing timestamps, duplicates) via metrics; document limitations in reports.
  - Standards/control: Follow SWGDE/NIST-aligned steps: extraction → analysis → review → reporting → manifest/custody; keep config in `.env` and avoid hidden state.
  - General acceptance: Use standard formats (JSON, XLSX, DOCX, PDF) and verifiable logs/hashes.
- Workflow to establish defensibility: Extraction → Analysis (threats/patterns/sentiment) → Manual Review (decisions persisted) → Reports (Excel/Word/PDF with methodology and limitations) → Chain of Custody + Run Manifest (hashes of inputs/outputs). Ensure each phase records actions and produces verifiable artifacts in `output/`.

## Integration Points & Dependencies
- Relies on `pandas`, `PyYAML`, `pytesseract`, `Pillow`, `python-magic` for core analysis.
- External message sources: iMessage (Mac/iPhone backup), WhatsApp (exported chat files), screenshots, attachments.
- Reports are generated in Excel, Word, PDF formats for legal teams.
- Chain of custody and run manifest files document all actions and file hashes.

## Conventions & Examples
- All new analyzers, extractors, and utilities should be placed in their respective subdirectories under `src/`.
- Use the logging system for all actions; record forensic actions with `forensic.record_action()`.
- When adding new analysis phases, update `src/main.py` to include them in the workflow.
- Example: To add a new pattern analyzer, create `src/analyzers/new_pattern_analyzer.py` and import/use in `main.py`.
- All output files should be written to `output/` and named with timestamps for traceability.

## Key Files
- `src/main.py`: Orchestrates the entire workflow
- `src/analyzers/threat_analyzer.py`: Example of threat detection logic
- `src/analyzers/screenshot_analyzer.py`: Example of OCR integration
- `src/review/manual_review_manager.py`: Example of manual review workflow
- `README.md`: Legal and technical overview for non-experts

---
For questions about legal standards or evidence integrity, refer to the README and chain of custody documentation. For technical issues, check logs in `output/` and `logs/`.
