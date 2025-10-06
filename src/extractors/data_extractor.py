"""
Unified data extraction module.
Coordinates extraction from multiple sources.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path

from .imessage_extractor import iMessageExtractor
from .whatsapp_extractor import WhatsAppExtractor

class DataExtractor:
    """Coordinates data extraction from all sources."""
    
    def __init__(self, forensic):
        """Initialize data extractor with forensic tracking."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        
        # Initialize individual extractors
        self.imessage = iMessageExtractor(forensic)
        self.whatsapp = WhatsAppExtractor(forensic)
        
        self.forensic.record_action(
            "DATA_EXTRACTOR_INIT",
            "extraction",
            "Initialized unified data extractor"
        )
    
    def extract_all(self, start_date: datetime = None, end_date: datetime = None) -> List[Dict[str, Any]]:
        """
        Extract data from all available sources.
        
        Args:
            start_date: Optional start date filter
            end_date: Optional end date filter
            
        Returns:
            List of extracted messages from all sources
        """
        all_messages = []
        
        # Extract iMessages
        try:
            self.logger.info("Extracting iMessages...")
            imessages = self.imessage.extract(start_date, end_date)
            if not imessages.empty:
                # Convert DataFrame to list of dicts
                messages = imessages.to_dict('records')
                for msg in messages:
                    msg['source'] = 'iMessage'
                all_messages.extend(messages)
                self.logger.info(f"Extracted {len(messages)} iMessages")
        except Exception as e:
            self.logger.error(f"Failed to extract iMessages: {e}")
            self.forensic.record_action(
                "IMESSAGE_EXTRACTION_FAILED",
                "extraction",
                str(e)
            )
        
        # Extract WhatsApp messages
        try:
            self.logger.info("Extracting WhatsApp messages...")
            whatsapp_messages = self.whatsapp.extract()
            if not whatsapp_messages.empty:
                messages = whatsapp_messages.to_dict('records')
                for msg in messages:
                    msg['source'] = 'WhatsApp'
                all_messages.extend(messages)
                self.logger.info(f"Extracted {len(messages)} WhatsApp messages")
        except Exception as e:
            self.logger.error(f"Failed to extract WhatsApp messages: {e}")
            self.forensic.record_action(
                "WHATSAPP_EXTRACTION_FAILED",
                "extraction",
                str(e)
            )
        
        # Record extraction summary
        self.forensic.record_action(
            "EXTRACTION_COMPLETE",
            "extraction",
            f"Extracted {len(all_messages)} total messages from all sources"
        )
        
        return all_messages
    
    def validate_extraction(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate extracted data for completeness and integrity.
        
        Args:
            messages: List of extracted messages
            
        Returns:
            Validation report
        """
        validation = {
            'total_messages': len(messages),
            'sources': {},
            'missing_content': 0,
            'missing_timestamps': 0,
            'duplicate_count': 0,
            'validation_passed': True
        }
        
        seen_ids = set()
        
        for msg in messages:
            # Count by source
            source = msg.get('source', 'unknown')
            validation['sources'][source] = validation['sources'].get(source, 0) + 1
            
            # Check for missing data
            if not msg.get('content'):
                validation['missing_content'] += 1
            if not msg.get('timestamp'):
                validation['missing_timestamps'] += 1
            
            # Check for duplicates
            msg_id = msg.get('message_id')
            if msg_id and msg_id in seen_ids:
                validation['duplicate_count'] += 1
            elif msg_id:
                seen_ids.add(msg_id)
        
        # Determine if validation passed
        if validation['missing_timestamps'] > len(messages) * 0.1:  # More than 10% missing
            validation['validation_passed'] = False
            validation['failure_reason'] = 'Too many missing timestamps'
        elif validation['duplicate_count'] > len(messages) * 0.05:  # More than 5% duplicates
            validation['validation_passed'] = False
            validation['failure_reason'] = 'Too many duplicate messages'
        
        self.forensic.record_action(
            "EXTRACTION_VALIDATED",
            "extraction",
            f"Validation {'passed' if validation['validation_passed'] else 'failed'}"
        )
        
        return validation