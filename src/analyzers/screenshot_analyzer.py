"""
Screenshot OCR and analysis module.
Extracts text from screenshots and analyzes content.
"""

import re
import logging
from pathlib import Path
from typing import List, Dict, Any
import pytesseract
from PIL import Image
import hashlib
from datetime import datetime

# Regex patterns for contact extraction from OCR text
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_PHONE_RE = re.compile(
    r'(?:\+?1[-.\s]?)?'          # optional country code
    r'\(?[2-9]\d{2}\)?'          # area code
    r'[-.\s]?'
    r'\d{3}'                     # prefix
    r'[-.\s]?'
    r'\d{4}'                     # line number
)
_NAME_LINE_RE = re.compile(
    r'(?:From|To|Sender|Recipient)\s*:\s*(.+)',
    re.IGNORECASE,
)


class ScreenshotAnalyzer:
    """Analyzes screenshots using OCR."""

    def __init__(self, forensic, third_party_registry=None):
        """Initialize screenshot analyzer.

        Args:
            forensic: ForensicRecorder instance.
            third_party_registry: Optional ThirdPartyRegistry for contact tracking.
        """
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        self.screenshots_dir = Path("source_files/screenshots")
        self.third_party_registry = third_party_registry

        self.forensic.record_action(
            "SCREENSHOT_ANALYZER_INIT",
            "Initialized screenshot OCR analyzer"
        )

    def analyze_screenshots(self) -> List[Dict[str, Any]]:
        """
        Analyze all screenshots in the source directory.

        Returns:
            List of analyzed screenshot data
        """
        results = []

        if not self.screenshots_dir.exists():
            self.logger.warning(f"Screenshots directory not found: {self.screenshots_dir}")
            return results

        image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp']
        image_files = [f for f in self.screenshots_dir.iterdir()
                      if f.suffix.lower() in image_extensions]

        self.logger.info(f"Found {len(image_files)} screenshots to analyze")

        for image_file in image_files:
            try:
                # Calculate hash for integrity
                with open(image_file, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()

                # Extract text using OCR
                image = Image.open(image_file)
                extracted_text = pytesseract.image_to_string(image)

                # Extract metadata from filename if available
                filename = image_file.name
                date_extracted = None
                if 'Screenshot_' in filename:
                    # Try to extract date from filename
                    try:
                        date_str = filename.split('_')[1].split('-')[0]
                        date_extracted = datetime.strptime(date_str, '%Y%m%d')
                    except Exception:
                        pass

                # Extract contacts from OCR text
                contacts_found = self._extract_contact_info(extracted_text, filename)

                result = {
                    'filename': filename,
                    'filepath': str(image_file),
                    'file_hash': file_hash,
                    'extracted_text': extracted_text,
                    'text_length': len(extracted_text),
                    'date_extracted': date_extracted,
                    'processing_timestamp': datetime.now().isoformat(),
                    'source': 'screenshot',
                    'contacts_found': contacts_found,
                }

                results.append(result)

                self.forensic.record_action(
                    "SCREENSHOT_PROCESSED",
                    f"Processed {filename}: {len(extracted_text)} chars extracted, "
                    f"{len(contacts_found)} contacts found"
                )

            except Exception as e:
                self.logger.error(f"Failed to process {image_file}: {e}")
                self.forensic.record_action(
                    "SCREENSHOT_PROCESSING_FAILED",
                    f"Failed to process {image_file.name}: {str(e)}"
                )

        self.logger.info(f"Successfully analyzed {len(results)} screenshots")
        return results

    def _extract_contact_info(self, text: str, filename: str = '') -> List[Dict[str, str]]:
        """
        Extract email addresses, phone numbers, and display names from OCR text.

        Each discovered contact is also registered with the third-party registry
        (if available) so it can appear in reports.

        Args:
            text: OCR-extracted text from a screenshot.
            filename: Source filename for context.

        Returns:
            List of dicts with keys ``type`` and ``value``.
        """
        contacts: List[Dict[str, str]] = []
        seen: set = set()

        # Emails
        for match in _EMAIL_RE.finditer(text):
            addr = match.group().lower()
            if addr not in seen:
                seen.add(addr)
                contacts.append({'type': 'email', 'value': addr})
                if self.third_party_registry:
                    self.third_party_registry.register(
                        identifier=addr,
                        source='screenshot',
                        context=filename,
                    )

        # Phone numbers
        for match in _PHONE_RE.finditer(text):
            phone = match.group().strip()
            norm = re.sub(r'\D', '', phone)
            if norm not in seen and len(norm) >= 10:
                seen.add(norm)
                contacts.append({'type': 'phone', 'value': phone})
                if self.third_party_registry:
                    self.third_party_registry.register(
                        identifier=phone,
                        source='screenshot',
                        context=filename,
                    )

        # Display names from header-like lines
        for match in _NAME_LINE_RE.finditer(text):
            name = match.group(1).strip()
            # Skip if the "name" is actually an email (already captured)
            if '@' in name or not name:
                continue
            name_lower = name.lower()
            if name_lower not in seen:
                seen.add(name_lower)
                contacts.append({'type': 'name', 'value': name})
                if self.third_party_registry:
                    self.third_party_registry.register(
                        identifier=name,
                        source='screenshot',
                        context=filename,
                        display_name=name,
                    )

        return contacts
