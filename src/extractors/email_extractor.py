#!/usr/bin/env python3
"""
Email extraction module.
Extracts messages from .eml files, .mbox files, and directories of .eml files.
"""

import email
import email.policy
import email.utils
import mailbox
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

from ..config import Config
from ..forensic_utils import ForensicRecorder, ForensicIntegrity

# Initialize config
config = Config()

logger = logging.getLogger(__name__)


class EmailExtractor:
    """
    Extracts messages from email sources.
    Handles .eml files, .mbox files, and directories of .eml files.
    """

    def __init__(self, source_dir: str, forensic_recorder: ForensicRecorder, forensic_integrity: ForensicIntegrity):
        """
        Initialize email extractor.

        Args:
            source_dir: Directory containing email files (.eml and/or .mbox)
            forensic_recorder: ForensicRecorder instance
            forensic_integrity: ForensicIntegrity instance
        """
        self.source_dir = Path(source_dir) if source_dir else None
        self.forensic = forensic_recorder
        self.integrity = forensic_integrity

        if self.source_dir and not self.source_dir.exists():
            raise FileNotFoundError(f"Email source directory not found: {self.source_dir}")

    def extract_all(self) -> List[Dict]:
        """
        Extract all email messages from the source directory.
        Processes .eml files, .mbox files, and recurses into subdirectories.

        Returns:
            List of message dictionaries
        """
        if not self.source_dir or not self.source_dir.exists():
            logger.warning(f"Email source directory not found: {self.source_dir}")
            return []

        all_messages = []

        # Process .eml files in the source directory and subdirectories
        eml_files = list(self.source_dir.rglob("*.eml"))
        for eml_file in eml_files:
            self._hash_source_file(eml_file)
            messages = self._extract_from_eml(eml_file)
            all_messages.extend(messages)

        # Process .mbox files in the source directory and subdirectories
        mbox_files = list(self.source_dir.rglob("*.mbox"))
        for mbox_file in mbox_files:
            self._hash_source_file(mbox_file)
            messages = self._extract_from_mbox(mbox_file)
            all_messages.extend(messages)

        # Sort by timestamp
        if all_messages:
            all_messages.sort(key=lambda x: x['timestamp'] or datetime.min)

        self.forensic.record_action(
            "email_extraction",
            f"Extracted {len(all_messages)} messages from {len(eml_files)} .eml files and {len(mbox_files)} .mbox files"
        )

        logger.info(
            f"Extracted {len(all_messages)} email messages from "
            f"{len(eml_files)} .eml files and {len(mbox_files)} .mbox files"
        )

        return all_messages

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

    def _extract_from_eml(self, file_path: Path) -> List[Dict]:
        """
        Extract a message from a single .eml file.

        Args:
            file_path: Path to the .eml file

        Returns:
            List containing the extracted message dictionary (or empty list on failure)
        """
        try:
            with open(file_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)

            parsed = self._parse_email_message(msg, file_path)
            if parsed:
                return [parsed]

        except Exception as e:
            logger.error(f"Error extracting from {file_path}: {e}")
            self.forensic.record_action(
                "email_eml_error",
                f"Failed to extract from {file_path.name}: {str(e)}"
            )

        return []

    def _extract_from_mbox(self, mbox_path: Path) -> List[Dict]:
        """
        Extract messages from an .mbox file.

        Args:
            mbox_path: Path to the .mbox file

        Returns:
            List of message dictionaries
        """
        messages = []

        try:
            mbox = mailbox.mbox(str(mbox_path))

            for msg in mbox:
                parsed = self._parse_email_message(msg, mbox_path)
                if parsed:
                    messages.append(parsed)

            mbox.close()

            logger.info(f"Extracted {len(messages)} messages from {mbox_path.name}")

        except Exception as e:
            logger.error(f"Error extracting from mbox {mbox_path}: {e}")
            self.forensic.record_action(
                "email_mbox_error",
                f"Failed to extract from {mbox_path.name}: {str(e)}"
            )

        return messages

    def _parse_email_message(self, msg, source_path: Path) -> Optional[Dict]:
        """
        Parse an email.message.Message object into a standardized dictionary.

        Args:
            msg: email.message.Message object
            source_path: Path to the source file (for reference)

        Returns:
            Parsed message dictionary or None if parsing fails
        """
        try:
            # Extract Message-ID
            message_id = msg.get('Message-ID', '').strip().strip('<>')
            if not message_id:
                # Generate a fallback ID from file and date
                message_id = f"email_{source_path.stem}_{id(msg)}"

            # Extract sender
            sender_raw = msg.get('From', '')
            sender = self._resolve_contact(sender_raw)

            # Extract recipient
            recipient_raw = msg.get('To', '')
            recipient = self._resolve_contact(recipient_raw)

            # Extract subject
            subject = msg.get('Subject', '')

            # Extract timestamp from Date header
            timestamp = self._parse_email_date(msg.get('Date', ''))

            # Extract body content, preferring text/plain
            content = self._extract_body(msg)

            return {
                'message_id': message_id,
                'content': content,
                'sender': sender,
                'recipient': recipient,
                'timestamp': timestamp,
                'source': 'email',
                'subject': subject,
                'file': source_path.name,
            }

        except Exception as e:
            logger.warning(f"Could not parse email message from {source_path.name}: {e}")
            return None

    def _extract_body(self, msg) -> Optional[str]:
        """
        Extract the body content from an email message, preferring text/plain.

        Args:
            msg: email.message.Message object

        Returns:
            Body text or None
        """
        # If the message is multipart, walk through parts
        if msg.is_multipart():
            text_plain = None
            text_html = None

            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))

                # Skip attachments
                if 'attachment' in content_disposition:
                    continue

                if content_type == 'text/plain' and text_plain is None:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            text_plain = payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            text_plain = payload.decode('utf-8', errors='replace')

                elif content_type == 'text/html' and text_html is None:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            text_html = payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            text_html = payload.decode('utf-8', errors='replace')

            # Prefer text/plain over text/html
            if text_plain:
                return text_plain.strip()
            if text_html:
                return text_html.strip()

            return None

        else:
            # Non-multipart message
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                try:
                    return payload.decode(charset, errors='replace').strip()
                except (LookupError, UnicodeDecodeError):
                    return payload.decode('utf-8', errors='replace').strip()

            return None

    def _parse_email_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse an email Date header into a datetime object.

        Args:
            date_str: Date string from email header

        Returns:
            Parsed datetime or None
        """
        if not date_str:
            return None

        try:
            parsed = email.utils.parsedate_to_datetime(date_str)
            return parsed
        except (ValueError, TypeError) as e:
            logger.warning(f"Could not parse email date '{date_str}': {e}")
            return None

    def _resolve_contact(self, raw_address: str) -> str:
        """
        Resolve an email address to a contact name using config mappings.
        Extracts the email address from a formatted string like 'Name <email@example.com>'
        and checks against contact mappings.

        Args:
            raw_address: Raw address string from email header

        Returns:
            Resolved contact name or the original address
        """
        if not raw_address:
            return 'Unknown'

        # Parse the address to extract name and email
        display_name, email_addr = email.utils.parseaddr(raw_address)
        email_addr = email_addr.strip().lower()

        # Check against contact mappings
        for person_name, identifiers in config.contact_mappings.items():
            for identifier in identifiers:
                identifier_lower = identifier.strip().lower()
                # Match against email address
                if email_addr and email_addr == identifier_lower:
                    return person_name
                # Match against display name
                if display_name and display_name.strip().lower() == identifier_lower:
                    return person_name

        # Fall back to display name if available, otherwise the email address
        if display_name:
            return display_name.strip()
        if email_addr:
            return email_addr

        return raw_address.strip()
