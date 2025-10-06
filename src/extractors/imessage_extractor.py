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
    
    def extract_messages(self) -> pd.DataFrame:
        """
        Extract messages from iMessage database.
        
        Returns:
            DataFrame with message data
        """
        if not self.db_path:
            logger.warning("No iMessage database path configured")
            return pd.DataFrame()
        
        try:
            # Create read-only connection
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            
            # Query to extract messages with sender information
            query = """
            SELECT 
                m.ROWID as message_id,
                m.text as content,
                m.is_from_me,
                h.id as handle,
                datetime(m.date/1000000000 + strftime('%s','2001-01-01'), 'unixepoch', 'localtime') as timestamp,
                m.service
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            WHERE m.text IS NOT NULL
            ORDER BY m.date DESC
            """
            
            # Execute query
            df = pd.read_sql_query(query, conn)
            conn.close()
            
            # Map sender based on is_from_me flag
            df['sender'] = df.apply(lambda row: 'Me' if row['is_from_me'] == 1 else row['handle'], axis=1)
            
            # Convert timestamp to datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Record extraction
            self.forensic.record_action(
                "imessage_extraction",
                f"Extracted {len(df)} messages from iMessage database",
                {"path": str(self.db_path), "message_count": len(df)}
            )
            
            return df[['message_id', 'content', 'sender', 'timestamp', 'service']]
            
        except Exception as e:
            logger.error(f"Error extracting iMessage data: {e}")
            self.forensic.record_action(
                "imessage_extraction_error",
                f"Failed to extract iMessage data: {str(e)}",
                {"error": str(e)}
            )
            return pd.DataFrame()


# Maintain backward compatibility
iMessageExtractor = IMessageExtractor
