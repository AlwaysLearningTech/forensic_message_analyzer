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

from ..config import config
from ..forensic_utils import ForensicIntegrity

class iMessageExtractor:  # Changed to match the import name
    """Extract and analyze iMessage data from chat.db"""
    
    def __init__(self, db_path: str = None, forensic = None):
        """Initialize the iMessage extractor"""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        
        if db_path is None:
            # Default macOS iMessage database location
            db_path = os.path.expanduser("~/Library/Messages/chat.db")
        
        self.db_path = db_path
        self.messages = []
        
        # Try to find iMessage database
        self.db_path = self._find_database()
        
        if self.db_path and self.forensic:
            self.forensic.record_action(
                "IMESSAGE_EXTRACTOR_INIT",
                "extraction",
                f"Database: {self.db_path}"
            )
    
    def _find_database(self):
        """Find iMessage database in various locations"""
        possible_paths = [
            os.path.expanduser("~/Library/Messages/chat.db"),
            Path(config.SOURCE_DIR) / "chat.db",
            Path(config.SOURCE_DIR) / "imessage" / "chat.db",
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                self.logger.info(f"Found iMessage database at: {path}")
                return path
        
        self.logger.warning("iMessage database not found in expected locations")
        return None
    
    def extract(self, start_date=None, end_date=None):
        """Extract messages from iMessage database"""
        if not self.db_path:
            self.logger.error("No iMessage database available")
            return pd.DataFrame()
        
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Basic query to get messages
            query = """
            SELECT 
                m.ROWID as message_id,
                m.text as content,
                datetime(m.date/1000000000 + strftime('%s', '2001-01-01'), 'unixepoch', 'localtime') as timestamp,
                h.id as sender,
                c.chat_identifier as conversation
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id
            LEFT JOIN chat c ON cmj.chat_id = c.ROWID
            WHERE m.text IS NOT NULL
            """
            
            df = pd.read_sql_query(query, conn)
            conn.close()
            
            # Convert timestamp to datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Apply date filters if provided
            if start_date:
                df = df[df['timestamp'] >= start_date]
            if end_date:
                df = df[df['timestamp'] <= end_date]
            
            self.logger.info(f"Extracted {len(df)} messages from iMessage")
            
            if self.forensic:
                self.forensic.record_action(
                    "IMESSAGE_EXTRACTION_COMPLETE",
                    "extraction",
                    f"Extracted {len(df)} messages"
                )
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error extracting iMessages: {e}")
            if self.forensic:
                self.forensic.record_action(
                    "IMESSAGE_EXTRACTION_ERROR",
                    "extraction",
                    str(e)
                )
            return pd.DataFrame()

# Also keep the original class name for backward compatibility
IMessageExtractor = iMessageExtractor
