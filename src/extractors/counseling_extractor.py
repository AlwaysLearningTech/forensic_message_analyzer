#!/usr/bin/env python3
"""
Counseling records extraction module.
Extracts session records from a structured YAML metadata file,
with optional PDF text extraction for linked documents.
"""

import hashlib
import logging
from pathlib import Path
from typing import List, Dict
import pandas as pd
import yaml

from ..config import Config
from ..forensic_utils import ForensicRecorder, ForensicIntegrity

logger = logging.getLogger(__name__)


class CounselingExtractor:
    """
    Extracts counseling session records from a YAML metadata file.
    Optionally extracts text from linked PDF documents.

    The YAML file (counseling_sessions.yaml) should contain:
        sessions:
          - date: "2024-03-15"
            topic: "Session topic"
            notes: "Session notes..."
            pdf_file: "optional_linked.pdf"
            provider: "Dr. Smith"
    """

    def __init__(self, source_dir: str, forensic_recorder: ForensicRecorder, forensic_integrity: ForensicIntegrity,
                 config: Config = None):
        """
        Initialize counseling extractor.

        Args:
            source_dir: Directory containing counseling_sessions.yaml and optional PDFs
            forensic_recorder: ForensicRecorder instance
            forensic_integrity: ForensicIntegrity instance
            config: Config instance. If None, creates a new one.
        """
        self.config = config if config is not None else Config()
        self.source_dir = Path(source_dir) if source_dir else None
        self.forensic = forensic_recorder
        self.integrity = forensic_integrity

        if self.source_dir and not self.source_dir.exists():
            raise FileNotFoundError(f"Counseling source directory not found: {self.source_dir}")

    def extract_all(self) -> List[Dict]:
        """
        Extract all counseling session records from the YAML metadata file.

        Returns:
            List of session dictionaries compatible with the message pipeline.
        """
        if not self.source_dir or not self.source_dir.exists():
            logger.warning(f"Counseling source directory not found: {self.source_dir}")
            return []

        yaml_path = self.source_dir / "counseling_sessions.yaml"
        if not yaml_path.exists():
            # Also check for .yml extension
            yaml_path = self.source_dir / "counseling_sessions.yml"
            if not yaml_path.exists():
                logger.warning(f"No counseling_sessions.yaml found in {self.source_dir}")
                return []

        # Hash the YAML metadata file
        self._hash_source_file(yaml_path)

        # Hash all PDF files in the directory
        for pdf_file in sorted(self.source_dir.glob("*.pdf")):
            self._hash_source_file(pdf_file)

        # Parse the YAML
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to parse {yaml_path}: {e}")
            return []

        if not data or not isinstance(data.get('sessions'), list):
            logger.warning(f"No sessions found in {yaml_path}")
            return []

        sessions = []
        person1_name = getattr(self.config, 'person1_name', 'Person 1')

        for entry in data['sessions']:
            session = self._process_session(entry, person1_name)
            if session:
                sessions.append(session)

        # Sort by timestamp
        if sessions:
            sessions.sort(
                key=lambda x: x['timestamp'] if x['timestamp'] is not None and not pd.isna(x['timestamp'])
                else pd.Timestamp.min.tz_localize('UTC')
            )

        self.forensic.record_action(
            "counseling_extraction",
            f"Extracted {len(sessions)} counseling sessions from {yaml_path.name}"
        )

        logger.info(f"Extracted {len(sessions)} counseling sessions")

        return sessions

    def _process_session(self, entry: dict, person1_name: str) -> Dict:
        """
        Process a single session entry from the YAML.

        Args:
            entry: Session dictionary from YAML.
            person1_name: Name of person 1 (the client).

        Returns:
            Message-compatible dictionary, or None if the entry is invalid.
        """
        date_str = entry.get('date')
        topic = entry.get('topic', '')
        notes = entry.get('notes', '')

        if not date_str:
            logger.warning(f"Counseling session missing 'date' field, skipping: {entry}")
            return None

        if not topic and not notes:
            logger.warning(f"Counseling session on {date_str} has no topic or notes, skipping")
            return None

        # Parse the date (set time to 12:00 UTC as sessions are date-only)
        try:
            timestamp = pd.to_datetime(f"{date_str} 12:00:00", utc=True)
        except Exception as e:
            logger.warning(f"Could not parse date '{date_str}': {e}")
            return None

        provider = entry.get('provider', '')
        pdf_file = entry.get('pdf_file', '')
        pdf_text = ''

        # Extract text from linked PDF if specified
        if pdf_file and self.source_dir:
            pdf_path = self.source_dir / pdf_file
            if pdf_path.exists():
                pdf_text = self._extract_pdf_text(pdf_path)
            else:
                logger.warning(f"PDF file not found: {pdf_path}")

        # Generate a deterministic message ID
        id_source = f"counseling_{date_str}_{topic}"
        message_id = f"counseling_{date_str}_{hashlib.sha256(id_source.encode()).hexdigest()[:8]}"

        return {
            'message_id': message_id,
            'content': notes,
            'sender': provider or 'Counselor',
            'recipient': person1_name,
            'timestamp': timestamp,
            'source': 'counseling',
            'topic': topic,
            'provider': provider,
            'pdf_file': pdf_file,
            'pdf_text': pdf_text,
            'is_counseling_event': True,
        }

    def _extract_pdf_text(self, pdf_path: Path) -> str:
        """
        Extract text from a PDF file using pdfplumber.

        Args:
            pdf_path: Path to the PDF file.

        Returns:
            Extracted text, or empty string on failure.
        """
        try:
            import pdfplumber
            with pdfplumber.open(pdf_path) as pdf:
                text = '\n'.join(page.extract_text() or '' for page in pdf.pages)
            return text.strip()
        except ImportError:
            logger.warning("pdfplumber not installed; skipping PDF text extraction")
            return ''
        except Exception as e:
            logger.warning(f"Could not extract text from PDF {pdf_path}: {e}")
            return ''

    def _hash_source_file(self, file_path: Path):
        """
        Hash a source file for forensic integrity if the method is available.

        Args:
            file_path: Path to the file to hash
        """
        try:
            if hasattr(self.integrity, 'compute_and_record_hash'):
                self.integrity.compute_and_record_hash(file_path)
            elif hasattr(self.forensic, 'compute_hash'):
                self.forensic.compute_hash(file_path)
        except Exception as e:
            logger.warning(f"Could not hash source file {file_path}: {e}")
