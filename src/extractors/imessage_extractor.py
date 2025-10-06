#!/usr/bin/env python3
"""
iMessage extraction module.
Extracts messages from iMessage chat.db database.
"""

import os
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
import pandas as pd

from ..config import Config
from ..forensic_utils import ForensicRecorder, ForensicIntegrity

# Initialize config
config = Config()

logger = logging.getLogger(__name__)


class IMessageExtractor:
    """
    Extracts messages from iMessage chat.db database.
    Handles both SMS and iMessage conversations.
    Includes attributedBody decoding for modern iMessage format.
    """
    
    def __init__(self, db_path: str, forensic_recorder: ForensicRecorder, forensic_integrity: ForensicIntegrity):
        """
        Initialize iMessage extractor.
        
        Args:
            db_path: Path to chat.db database
            forensic_recorder: ForensicRecorder instance
            forensic_integrity: ForensicIntegrity instance
        """
        self.db_path = Path(db_path) if db_path else None
        self.forensic = forensic_recorder
        self.integrity = forensic_integrity
        
        if self.db_path and not self.db_path.exists():
            raise FileNotFoundError(f"iMessage database not found: {self.db_path}")
    
    def decode_attributed_body(self, blob_data):
        """
        Decode text from attributedBody BLOB data.
        
        Modern iMessages store text content in the attributedBody field in binary format
        rather than the plain text field. This implements a simplified decoder based
        on imessage-exporter's approach.
        
        Args:
            blob_data: Raw BLOB data from attributedBody column
            
        Returns:
            Decoded text string or None if decoding fails
        """
        if not blob_data:
            return None
            
        try:
            # Try streamtyped parser first (simpler format)
            text = self._parse_streamtyped(blob_data)
            if text:
                return text
        except Exception:
            pass
            
        try:
            # Try typedstream parser (NSAttributedString format)
            text = self._parse_typedstream(blob_data)
            if text:
                return text
        except Exception:
            pass
            
        return None
    
    def _parse_streamtyped(self, data):
        """
        Parse streamtyped format (legacy simple format).
        
        Format: streamtyped header + text content between patterns
        """
        # Start and end patterns from imessage-exporter
        START_PATTERN = b'\x01\x2b'  # SOH + Plus
        END_PATTERN = b'\x86\x84'    # SSA + IND
        
        # Find start pattern
        start_idx = -1
        for i in range(len(data) - 1):
            if data[i:i+2] == START_PATTERN:
                start_idx = i + 2
                break
                
        if start_idx == -1:
            return None
            
        # Find end pattern
        end_idx = -1
        for i in range(start_idx, len(data) - 1):
            if data[i:i+2] == END_PATTERN:
                end_idx = i
                break
                
        if end_idx == -1:
            return None
            
        # Extract text content
        text_data = data[start_idx:end_idx]
        
        # Try UTF-8 decode
        try:
            text = text_data.decode('utf-8')
            # Remove first character prefix (common in streamtyped)
            if len(text) > 1:
                return text[1:].strip()
            return text.strip()
        except UnicodeDecodeError:
            # Try UTF-8 with lossy conversion, remove 3-char prefix
            text = text_data.decode('utf-8', errors='replace')
            if len(text) > 3:
                return text[3:].strip()
            return text.strip()
    
    def _parse_typedstream(self, data):
        """
        Parse typedstream format (NSAttributedString format).
        
        This is a simplified approach - the full parser is very complex.
        We'll try to extract text using common patterns.
        """
        try:
            # Look for NSString patterns in the data
            text_str = data.decode('utf-8', errors='ignore')
            
            # Look for "NSString" marker followed by text content
            nsstring_marker = "NSString"
            if nsstring_marker in text_str:
                # Find text after NSString marker
                parts = text_str.split(nsstring_marker)
                if len(parts) > 1:
                    # Extract potential text content
                    potential_text = parts[1]
                    # Clean up control characters and find readable text
                    cleaned = ''.join(c for c in potential_text if c.isprintable())
                    if len(cleaned) > 2:  # Minimum reasonable text length
                        return cleaned.strip()
            
            # Alternative: look for readable text sequences
            # Extract sequences of printable characters
            readable_parts = []
            current_text = ""
            
            for byte in data:
                try:
                    char = chr(byte)
                    if char.isprintable() and not char.isspace():
                        current_text += char
                    elif char in ' \n\r\t':
                        if current_text:
                            current_text += char
                    else:
                        if len(current_text) > 3:  # Minimum length for valid text
                            readable_parts.append(current_text.strip())
                        current_text = ""
                except (ValueError, UnicodeDecodeError):
                    if len(current_text) > 3:
                        readable_parts.append(current_text.strip())
                    current_text = ""
            
            # Add final text if any
            if len(current_text) > 3:
                readable_parts.append(current_text.strip())
            
            # Return the longest readable part (most likely to be the message)
            if readable_parts:
                longest = max(readable_parts, key=len)
                if len(longest) > 5:  # Reasonable minimum message length
                    return longest
                    
        except Exception:
            pass
            
        return None
    
    def extract_text_with_fallback(self, text, attributed_body):
        """
        Extract text with fallback to attributedBody decoding.
        
        Args:
            text: Plain text field from message
            attributed_body: Binary BLOB from attributedBody field
            
        Returns:
            Best available text content
        """
        # If we have plain text and it's not empty, use it
        if text and str(text).strip():
            return str(text).strip()
        
        # Otherwise try to decode attributedBody
        if attributed_body:
            decoded = self.decode_attributed_body(attributed_body)
            if decoded and decoded.strip():
                return decoded.strip()
        
        # Return None if no text found
        return None
    
    def extract_messages(self) -> list:
        """
        Extract messages from iMessage database.
        Uses contact mappings to filter for relevant participants only.
        Decodes attributedBody for modern iMessage format.
        
        Returns:
            List of message dictionaries
        """
        if not self.db_path:
            logger.warning("No iMessage database path configured")
            return []
        
        try:
            # Create read-only connection
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            
            # Get all participant handles from config
            all_handles = []
            for person_mappings in config.contact_mappings.values():
                all_handles.extend(person_mappings)
            
            # Create placeholders for SQL IN clause
            placeholders = ','.join('?' * len(all_handles))
            
            # Query to extract messages with attributedBody
            # Exclude tapbacks/reactions (associated_message_type 2000-3007)
            query = f"""
            SELECT 
                m.ROWID as message_id,
                m.guid,
                m.text,
                m.attributedBody,
                m.is_from_me,
                h.id as handle,
                c.chat_identifier,
                datetime(m.date/1000000000 + strftime('%s','2001-01-01'), 'unixepoch', 'localtime') as timestamp,
                m.service,
                m.associated_message_type
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id
            LEFT JOIN chat c ON cmj.chat_id = c.ROWID
            WHERE (h.id IN ({placeholders}) OR m.is_from_me = 1)
              AND (m.associated_message_type IS NULL 
                   OR m.associated_message_type NOT BETWEEN 2000 AND 3007)
            ORDER BY m.date ASC
            """
            
            # Execute query
            cursor.execute(query, all_handles)
            rows = cursor.fetchall()
            conn.close()
            
            # Process messages and extract text
            messages = []
            for row in rows:
                message_id, guid, text, attributed_body, is_from_me, handle, chat_id, timestamp, service, assoc_type = row
                
                # Extract text with fallback to attributedBody
                content = self.extract_text_with_fallback(text, attributed_body)
                
                # Skip messages with no text content
                if not content:
                    continue
                
                # Determine sender and recipient
                if is_from_me == 1:
                    sender = 'Me'
                    # Recipient is the handle or chat_identifier
                    recipient_handle = handle or chat_id
                    recipient = recipient_handle
                    # Map to person name
                    for person_name, person_handles in config.contact_mappings.items():
                        if recipient_handle in person_handles:
                            recipient = person_name
                            break
                else:
                    # Message from someone else to me
                    recipient = 'Me'
                    # Map handle to person name
                    sender = handle
                    for person_name, person_handles in config.contact_mappings.items():
                        if handle in person_handles:
                            sender = person_name
                            break
                
                # Convert timestamp string to datetime object
                timestamp_dt = pd.to_datetime(timestamp) if timestamp else None
                
                messages.append({
                    'message_id': message_id,
                    'guid': guid,
                    'content': content,
                    'sender': sender,
                    'recipient': recipient,
                    'timestamp': timestamp_dt,
                    'service': service,
                    'source': 'imessage'
                })
            
            # Record extraction
            self.forensic.record_action(
                "imessage_extraction",
                f"Extracted {len(messages)} messages from iMessage database",
                {
                    "path": str(self.db_path),
                    "message_count": len(messages),
                    "participants": list(config.contact_mappings.keys())
                }
            )
            
            logger.info(f"Extracted {len(messages)} iMessages from database")
            return messages
            
        except Exception as e:
            logger.error(f"Error extracting iMessage data: {e}")
            self.forensic.record_action(
                "imessage_extraction_error",
                f"Failed to extract iMessage data: {str(e)}",
                {"error": str(e)}
            )
            return []


# Maintain backward compatibility
iMessageExtractor = IMessageExtractor
