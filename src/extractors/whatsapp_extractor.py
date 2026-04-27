#!/usr/bin/env python3
"""
WhatsApp chat extraction module.
Processes exported WhatsApp chat files.
"""

import re
import logging
import zipfile
from pathlib import Path
from datetime import datetime
import pytz
import pandas as pd
from typing import List, Dict, Optional

from ..config import Config
from ..forensic_utils import ForensicRecorder, ForensicIntegrity

logger = logging.getLogger(__name__)


class WhatsAppExtractor:
    """
    Extracts messages from WhatsApp chat exports.
    Handles various export formats and attachments.
    """
    
    def __init__(self, export_dir: str, forensic_recorder: ForensicRecorder, forensic_integrity: ForensicIntegrity, config: Config = None):
        """
        Initialize WhatsApp extractor.

        Args:
            export_dir: Directory containing WhatsApp exports
            forensic_recorder: ForensicRecorder instance
            forensic_integrity: ForensicIntegrity instance
            config: Config instance. If None, creates a new one.
        """
        self.config = config if config is not None else Config()
        self.export_dir = Path(export_dir) if export_dir else None
        self.forensic = forensic_recorder
        self.integrity = forensic_integrity
        
        # Regex patterns for parsing WhatsApp messages
        # Format: [3/8/22, 4:12:34 PM] Sender: Message
        self.message_pattern = re.compile(
            r'\[(\d{1,2}/\d{1,2}/\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?\s+(?:[AP]M)?)\]\s+([^:]+):\s+(.*)',
            re.MULTILINE
        )
        
    def extract_all(self) -> list:
        """
        Extract all WhatsApp messages from export directory.
        
        Returns:
            List of message dictionaries
        """
        if not self.export_dir or not self.export_dir.exists():
            logger.warning(f"WhatsApp export directory not found: {self.export_dir}")
            return []
        
        # Check for ZIP files and extract them first
        self._extract_zip_files()
        
        all_messages = []
        
        # Find all text files in export directory
        chat_files = list(self.export_dir.glob("*.txt"))

        # Also check subdirectories in source directory (pre-existing extractions)
        for subdir in self.export_dir.iterdir():
            if subdir.is_dir():
                chat_files.extend(subdir.glob("*.txt"))

        # Check the extraction output directory for ZIP-extracted files
        wa_extract_dir = getattr(self, '_wa_extract_dir', None)
        if wa_extract_dir and wa_extract_dir.exists():
            for subdir in wa_extract_dir.iterdir():
                if subdir.is_dir():
                    chat_files.extend(subdir.glob("*.txt"))
        
        for chat_file in chat_files:
            messages = self._extract_from_file(chat_file)
            all_messages.extend(messages)
        
        # Sort by timestamp
        if all_messages:
            all_messages.sort(key=lambda x: x['timestamp'])
            
            self.forensic.record_action(
                "whatsapp_extraction",
                f"Extracted {len(all_messages)} messages from {len(chat_files)} WhatsApp files",
                {"file_count": len(chat_files), "message_count": len(all_messages)}
            )
            
            logger.info(f"Extracted {len(all_messages)} WhatsApp messages from {len(chat_files)} files")
        
        return all_messages
    
    # Hard caps for untrusted ZIP archives. Anything larger than these limits is rejected before any file is written to disk, guarding against decompression bombs and path-traversal ("zip-slip") attacks.
    _MAX_UNCOMPRESSED_BYTES = 5 * 1024 ** 3   # 5 GB total uncompressed
    _MAX_COMPRESSION_RATIO = 200              # per-member ratio ceiling
    _MAX_MEMBERS = 100_000                    # total member count

    def _extract_zip_files(self):
        """
        Extract any ZIP files to the output directory (not the source directory).
        Preserves forensic integrity of source evidence by never writing to the source.
        """
        zip_files = list(self.export_dir.glob("*.zip"))

        if not zip_files:
            return

        # Guard: warn if output_dir is not inside a run subfolder (skip during validation)
        output_dir = Path(self.config.output_dir)
        if not re.search(r'(run|validate)_\d{8}_\d{6}', str(output_dir)):
            logger.debug(
                "output_dir does not look like a run subfolder: %s. "
                "WhatsApp extracted files may be misplaced.", output_dir
            )

        # Extract to output directory, not source directory
        wa_extract_base = output_dir / "whatsapp_extracted"
        wa_extract_base.mkdir(parents=True, exist_ok=True)
        self._wa_extract_dir = wa_extract_base

        for zip_file in zip_files:
            try:
                extract_dir = wa_extract_base / zip_file.stem
                extract_dir.mkdir(exist_ok=True)
                self._safe_extract_zip(zip_file, extract_dir)

                logger.info(f"Extracted ZIP file: {zip_file.name} to {extract_dir}")

                self.forensic.record_action(
                    "whatsapp_zip_extraction",
                    f"Extracted ZIP file: {zip_file.name}",
                    {"zip_file": str(zip_file), "extract_dir": str(extract_dir)}
                )

            except Exception as e:
                logger.error(f"Error extracting ZIP file {zip_file}: {e}")
                self.forensic.record_action(
                    "whatsapp_zip_error",
                    f"Failed to extract ZIP: {zip_file.name}: {str(e)}",
                    {"zip_file": str(zip_file), "error": str(e)}
                )

    def _safe_extract_zip(self, zip_path: Path, extract_dir: Path):
        """Extract a ZIP archive with bounds and path-containment checks.

        Raises:
            ValueError if the archive appears to be a decompression bomb, contains absolute/traversing paths ("zip-slip"), or exceeds the member count cap.
        """
        extract_root = extract_dir.resolve()

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            members = zip_ref.infolist()

            if len(members) > self._MAX_MEMBERS:
                raise ValueError(
                    f"ZIP {zip_path.name} has {len(members)} members "
                    f"(limit {self._MAX_MEMBERS})"
                )

            total_uncompressed = sum(m.file_size for m in members)
            if total_uncompressed > self._MAX_UNCOMPRESSED_BYTES:
                raise ValueError(
                    f"ZIP {zip_path.name} uncompressed size "
                    f"{total_uncompressed} exceeds limit "
                    f"{self._MAX_UNCOMPRESSED_BYTES}"
                )

            for member in members:
                # Reject absolute paths and parent-directory traversal
                name = member.filename
                if name.startswith('/') or '..' in Path(name).parts:
                    raise ValueError(
                        f"ZIP {zip_path.name} contains unsafe path: {name!r}"
                    )

                # Per-member compression-ratio check (guards nested bombs)
                if member.compress_size > 0:
                    ratio = member.file_size / member.compress_size
                    if ratio > self._MAX_COMPRESSION_RATIO:
                        raise ValueError(
                            f"ZIP {zip_path.name} member {name!r} has "
                            f"compression ratio {ratio:.0f}x "
                            f"(limit {self._MAX_COMPRESSION_RATIO}x)"
                        )

                # Resolve the target path and ensure it stays inside extract_dir
                target = (extract_dir / name).resolve()
                try:
                    target.relative_to(extract_root)
                except ValueError:
                    raise ValueError(
                        f"ZIP {zip_path.name} member escapes extract dir: {name!r}"
                    )

                zip_ref.extract(member, extract_dir)
    
    def _extract_from_file(self, file_path: Path) -> List[Dict]:
        """
        Extract messages from a single WhatsApp export file.
        
        Args:
            file_path: Path to WhatsApp export file
            
        Returns:
            List of message dictionaries
        """
        messages = []
        msg_counter = 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find all message boundaries using finditer (captures multiline content)
            boundaries = list(self.message_pattern.finditer(content))

            # First pass: identify unique senders to determine chat participants. This lets us correctly assign recipients in 1:1 chats even when the filename doesn't contain the contact name.
            person1 = getattr(self.config, 'person1_name', None)
            raw_senders = set()
            for match in boundaries:
                raw_senders.add(match.group(2).strip())
            
            # Map raw senders to person names
            mapped_senders = set()
            for raw in raw_senders:
                for person_name, person_handles in self.config.contact_mappings.items():
                    if raw in person_handles:
                        mapped_senders.add(person_name)
                        break
                else:
                    if raw.lower() in ['you', 'me']:
                        if person1:
                            mapped_senders.add(person1)
                    else:
                        mapped_senders.add(raw)
            
            # For 1:1 chats: the "other person" is whoever isn't PERSON1
            other_person = None
            non_person1 = mapped_senders - {person1} if person1 else mapped_senders
            if len(non_person1) == 1:
                other_person = non_person1.pop()
            
            for idx, match in enumerate(boundaries):
                timestamp_str = match.group(1)
                sender = match.group(2)
                first_line = match.group(3)

                # Capture continuation lines between this boundary and the next. Any text after the first matched line up to the next message header belongs to this message (multiline messages).
                first_line_end = match.end()
                if idx + 1 < len(boundaries):
                    next_start = boundaries[idx + 1].start()
                else:
                    next_start = len(content)
                continuation = content[first_line_end:next_start].strip()
                if continuation:
                    message_content = first_line + '\n' + continuation
                else:
                    message_content = first_line

                # Parse timestamp (handle different formats)
                timestamp = self._parse_timestamp(timestamp_str)
                if timestamp is None:
                    logger.warning(f"Skipping message with unparseable timestamp: {timestamp_str}")
                    continue

                # Map sender to person name using contact mappings
                sender_name = sender.strip()
                sender_raw_val = sender_name  # preserve before mapping
                is_from_me = False
                for person_name, person_handles in self.config.contact_mappings.items():
                    if sender_name in person_handles:
                        sender_name = person_name
                        break
                else:
                    # No contact mapping matched; check if sender is 'Me' or similar
                    if sender_name.lower() in ['you', 'me']:
                        sender_name = 'Me'
                        is_from_me = True

                # If sender resolved to PERSON1 (device owner), treat as "from me"
                if person1 and sender_name == person1:
                    is_from_me = True

                # Determine recipient
                # For 1:1 chats: if sender is Me/PERSON1 → recipient is the other person
                # If sender is another person → recipient is Me/PERSON1
                if is_from_me or sender_name == 'Me':
                    # Use the other participant detected in first pass
                    if other_person:
                        recipient = other_person
                    else:
                        # Fallback: try filename-based matching
                        recipient = 'Unknown'
                        for person_name, identifiers in self.config.contact_mappings.items():
                            if person1 and person_name == person1:
                                continue
                            if any(identifier.lower() in file_path.name.lower() for identifier in identifiers):
                                recipient = person_name
                                break
                else:
                    # Sender is another person, so recipient is Me
                    recipient = 'Me'

                # Clean Unicode control characters (WhatsApp embeds LTR marks, object replacement chars, etc.)
                clean_content = message_content.strip()
                clean_content = re.sub(r'[\u200e\u200f\u202a-\u202e\ufffc\ufeff]', '', clean_content)

                # Detect attachment references (e.g. <attached: FILENAME.jpg>)
                attachment_match = re.search(r'<attached:\s*(.+?)>', clean_content)
                attachment_path = None
                if attachment_match:
                    attachment_name = attachment_match.group(1).strip()
                    candidate = file_path.parent / attachment_name
                    if candidate.exists():
                        attachment_path = str(candidate)

                msg_counter += 1
                msg_dict = {
                    'message_id': f"wa_{file_path.stem}_{msg_counter}",
                    'timestamp': timestamp,
                    'sender': sender_name,
                    'recipient': recipient,
                    'sender_raw': None if is_from_me else sender_raw_val,
                    'content': clean_content,
                    'source': 'whatsapp',
                    'file': file_path.name,
                }
                if attachment_path:
                    msg_dict['attachment'] = attachment_path
                    msg_dict['attachment_name'] = attachment_name
                messages.append(msg_dict)
            
            logger.info(f"Extracted {len(messages)} messages from {file_path.name}")
            
        except Exception as e:
            logger.error(f"Error extracting from {file_path}: {e}")
            self.forensic.record_action(
                "whatsapp_file_error",
                f"Failed to extract from {file_path.name}: {str(e)}",
                {"file": str(file_path), "error": str(e)}
            )
        
        return messages
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse WhatsApp timestamp into a timezone-aware (UTC) datetime.

        WhatsApp export timestamps are in the device's local timezone. We localize to the configured ANALYSIS_TIMEZONE and convert to UTC so they are consistent with iMessage, email, and Teams timestamps.

        Args:
            timestamp_str: Timestamp string from WhatsApp

        Returns:
            Timezone-aware datetime in UTC, or None if unparseable
        """
        local_tz = pytz.timezone(self.config.timezone)

        # Try different date formats
        formats = [
            "%m/%d/%y, %I:%M:%S %p",  # 3/8/22, 4:12:34 PM
            "%m/%d/%y, %I:%M %p",  # 12/25/23, 3:30 PM
            "%m/%d/%Y, %I:%M:%S %p",  # 12/25/2023, 3:30:00 PM
            "%m/%d/%Y, %I:%M %p",  # 12/25/2023, 3:30 PM
            "%d/%m/%y, %H:%M:%S",     # 25/12/23, 15:30:00
            "%d/%m/%y, %H:%M",     # 25/12/23, 15:30
            "%d/%m/%Y, %H:%M:%S",     # 25/12/2023, 15:30:00
            "%d/%m/%Y, %H:%M",     # 25/12/2023, 15:30
            "%m/%d/%y, %H:%M:%S",     # 12/25/23, 15:30:00
            "%m/%d/%y, %H:%M",     # 12/25/23, 15:30
            "%m/%d/%Y, %H:%M:%S",     # 12/25/2023, 15:30:00
            "%m/%d/%Y, %H:%M",     # 12/25/2023, 15:30
        ]

        for fmt in formats:
            try:
                naive_dt = datetime.strptime(timestamp_str.strip(), fmt)
                return local_tz.localize(naive_dt).astimezone(pytz.utc)
            except ValueError:
                continue

        # If no format matches, log warning and return None to flag the issue
        logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return None
