"""
WhatsApp extraction module.
Extracts messages from WhatsApp chat exports.
"""

import re
import logging
from pathlib import Path
from datetime import datetime
import pandas as pd
import zipfile
from charset_normalizer import from_bytes

from ..config import config
from ..forensic_utils import ForensicIntegrity

class WhatsAppExtractor:
    """Extract messages from WhatsApp exports."""
    
    # Regex patterns for different WhatsApp export formats
    PATTERNS = {
        'ios_us': r'^\[(\d{1,2}/\d{1,2}/\d{2,4},\s\d{1,2}:\d{2}:\d{2}\s[AP]M)\]\s([^:]+):\s(.+)$',
        'ios_eu': r'^(\d{1,2}/\d{1,2}/\d{2,4},\s\d{1,2}:\d{2})\s-\s([^:]+):\s(.+)$',
        'android_us': r'^(\d{1,2}/\d{1,2}/\d{2,4},\s\d{1,2}:\d{2}\s[AP]M)\s-\s([^:]+):\s(.+)$',
        'android_eu': r'^(\d{1,2}\.\d{1,2}\.\d{2,4},\s\d{1,2}:\d{2})\s-\s([^:]+):\s(.+)$'
    }
    
    def __init__(self, forensic_integrity: ForensicIntegrity):
        """Initialize WhatsApp extractor."""
        self.forensic = forensic_integrity
        self.source_dir = config.whatsapp_source_dir
        self.logger = logging.getLogger(__name__)
        self.chat_files = self._find_chat_files()
        
        self.forensic.record_action(
            "WHATSAPP_EXTRACTOR_INIT",
            "extraction",
            f"Found {len(self.chat_files)} chat files"
        )
    
    def _find_chat_files(self) -> list:
        """Find WhatsApp chat export files."""
        chat_files = []
        
        # Check for zip file
        zip_path = Path("source_files/whatsapp/WhatsApp_SourceFiles.zip")
        if zip_path.exists():
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    # Extract to temp location
                    extract_dir = Path("source_files/whatsapp/extracted")
                    extract_dir.mkdir(parents=True, exist_ok=True)
                    zf.extractall(extract_dir)
                    
                    # Find .txt files
                    for txt_file in extract_dir.rglob("*.txt"):
                        chat_files.append(txt_file)
                        
            except Exception as e:
                self.logger.error(f"Failed to extract WhatsApp zip: {e}")
        
        # Also check for direct .txt files
        whatsapp_dir = Path("source_files/whatsapp")
        if whatsapp_dir.exists():
            for txt_file in whatsapp_dir.glob("*.txt"):
                if txt_file not in chat_files:
                    chat_files.append(txt_file)
        
        return chat_files
    
    def extract(self) -> pd.DataFrame:
        """
        Extract messages from WhatsApp chat exports.
        
        Returns:
            DataFrame with extracted messages
        """
        all_messages = []
        
        for chat_file in self.chat_files:
            try:
                messages = self._parse_chat_file(chat_file)
                all_messages.extend(messages)
                self.logger.info(f"Extracted {len(messages)} messages from {chat_file.name}")
            except Exception as e:
                self.logger.error(f"Failed to parse {chat_file}: {e}")
        
        if all_messages:
            df = pd.DataFrame(all_messages)
            self.logger.info(f"Total WhatsApp messages extracted: {len(df)}")
            
            self.forensic.record_action(
                "WHATSAPP_EXTRACTION_COMPLETE",
                "extraction",
                f"Extracted {len(df)} messages from {len(self.chat_files)} files"
            )
            
            return df
        
        return pd.DataFrame()
    
    def _parse_chat_file(self, file_path: Path) -> list:
        """Parse a single WhatsApp chat export file."""
        messages = []
        
        # WhatsApp format: [DD/MM/YYYY, HH:MM:SS] Contact: Message
        pattern = r'\[(\d{1,2}/\d{1,2}/\d{4}),?\s+(\d{1,2}:\d{2}:\d{2})\]\s+([^:]+):\s+(.*)'
        
        with open(file_path, 'r', encoding='utf-8') as f:
            current_message = None
            
            for line in f:
                match = re.match(pattern, line)
                
                if match:
                    # Save previous message if exists
                    if current_message:
                        messages.append(current_message)
                    
                    # Parse new message
                    date_str = match.group(1)
                    time_str = match.group(2)
                    sender = match.group(3)
                    content = match.group(4)
                    
                    # Parse timestamp
                    timestamp_str = f"{date_str} {time_str}"
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%d/%m/%Y %H:%M:%S")
                    except:
                        try:
                            timestamp = datetime.strptime(timestamp_str, "%m/%d/%Y %H:%M:%S")
                        except:
                            timestamp = datetime.now()
                    
                    current_message = {
                        'message_id': f"wa_{file_path.stem}_{len(messages)}",
                        'timestamp': timestamp,
                        'sender': sender.strip(),
                        'content': content.strip(),
                        'chat_name': file_path.stem
                    }
                elif current_message and line.strip():
                    # Continuation of previous message
                    current_message['content'] += '\n' + line.strip()
            
            # Don't forget the last message
            if current_message:
                messages.append(current_message)
        
        return messages
