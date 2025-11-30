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
import pandas as pd
from typing import List, Dict, Optional

from ..config import Config
from ..forensic_utils import ForensicRecorder, ForensicIntegrity

# Initialize config
config = Config()

logger = logging.getLogger(__name__)


class WhatsAppExtractor:
    """
    Extracts messages from WhatsApp chat exports.
    Handles various export formats and attachments.
    """
    
    def __init__(self, export_dir: str, forensic_recorder: ForensicRecorder, forensic_integrity: ForensicIntegrity):
        """
        Initialize WhatsApp extractor.
        
        Args:
            export_dir: Directory containing WhatsApp exports
            forensic_recorder: ForensicRecorder instance
            forensic_integrity: ForensicIntegrity instance
        """
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
        
        # Also check subdirectories for extracted files
        for subdir in self.export_dir.iterdir():
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
    
    def _extract_zip_files(self):
        """
        Extract any ZIP files in the export directory.
        """
        zip_files = list(self.export_dir.glob("*.zip"))
        
        for zip_file in zip_files:
            try:
                # Create extraction directory
                extract_dir = self.export_dir / zip_file.stem
                extract_dir.mkdir(exist_ok=True)
                
                # Extract ZIP file
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
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
    
    def _extract_from_file(self, file_path: Path) -> List[Dict]:
        """
        Extract messages from a single WhatsApp export file.
        
        Args:
            file_path: Path to WhatsApp export file
            
        Returns:
            List of message dictionaries
        """
        messages = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find all messages
            matches = self.message_pattern.findall(content)
            
            for match in matches:
                timestamp_str, sender, message_content = match
                
                # Parse timestamp (handle different formats)
                timestamp = self._parse_timestamp(timestamp_str)
                
                # Map sender to person name using contact mappings
                sender_name = sender.strip()
                is_from_me = False
                for person_name, person_handles in config.contact_mappings.items():
                    if sender_name in person_handles:
                        sender_name = person_name
                        break
                    # Check if sender is 'Me' or similar
                    if sender_name.lower() in ['you', 'me']:
                        sender_name = 'Me'
                        is_from_me = True
                        break
                
                # Determine recipient using smart mapping
                # For 1:1 chats: if sender is Me → recipient is the other person
                # If sender is mapped person → recipient is Me
                if is_from_me or sender_name == 'Me':
                    # Sender is me, so recipient is the mapped person
                    # Try to find recipient from contact mappings
                    recipient = 'Unknown'
                    for person_name, identifiers in config.contact_mappings.items():
                        # Check if this file relates to this person
                        # Look at filename or sender name in other messages
                        if any(identifier.lower() in file_path.name.lower() for identifier in identifiers):
                            recipient = person_name
                            break
                else:
                    # Sender is another person, so recipient is Me
                    recipient = 'Me'
                
                messages.append({
                    'timestamp': timestamp,
                    'sender': sender_name,
                    'recipient': recipient,
                    'content': message_content.strip(),
                    'source': 'whatsapp',
                    'file': file_path.name
                })
            
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
        Parse WhatsApp timestamp into datetime object.
        
        Args:
            timestamp_str: Timestamp string from WhatsApp
            
        Returns:
            Parsed datetime object
        """
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
                return datetime.strptime(timestamp_str.strip(), fmt)
            except ValueError:
                continue
        
        # If no format matches, log and return current time
        logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return datetime.now()
