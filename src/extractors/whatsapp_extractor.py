#!/usr/bin/env python3
"""
WhatsApp chat extraction module.
Processes exported WhatsApp chat files.
"""

import re
import logging
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
        self.message_pattern = re.compile(
            r'(\d{1,2}/\d{1,2}/\d{2,4},?\s+\d{1,2}:\d{2}(?:\s+[AP]M)?)\s+-\s+([^:]+):\s+(.*)',
            re.MULTILINE
        )
        
    def extract_all(self) -> pd.DataFrame:
        """
        Extract all WhatsApp messages from export directory.
        
        Returns:
            DataFrame with all extracted messages
        """
        if not self.export_dir or not self.export_dir.exists():
            logger.warning(f"WhatsApp export directory not found: {self.export_dir}")
            return pd.DataFrame()
        
        all_messages = []
        
        # Find all text files in export directory
        chat_files = list(self.export_dir.glob("*.txt"))
        
        for chat_file in chat_files:
            messages = self._extract_from_file(chat_file)
            all_messages.extend(messages)
        
        # Convert to DataFrame
        if all_messages:
            df = pd.DataFrame(all_messages)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp')
            
            self.forensic.record_action(
                "whatsapp_extraction",
                f"Extracted {len(df)} messages from {len(chat_files)} WhatsApp files",
                {"file_count": len(chat_files), "message_count": len(df)}
            )
            
            return df
        
        return pd.DataFrame()
    
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
                timestamp_str, sender, content = match
                
                # Parse timestamp (handle different formats)
                timestamp = self._parse_timestamp(timestamp_str)
                
                messages.append({
                    'timestamp': timestamp,
                    'sender': sender.strip(),
                    'content': content.strip(),
                    'source': 'WhatsApp',
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
            "%m/%d/%y, %I:%M %p",  # 12/25/23, 3:30 PM
            "%m/%d/%Y, %I:%M %p",  # 12/25/2023, 3:30 PM
            "%d/%m/%y, %H:%M",     # 25/12/23, 15:30
            "%d/%m/%Y, %H:%M",     # 25/12/2023, 15:30
            "%m/%d/%y, %H:%M",     # 12/25/23, 15:30
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
