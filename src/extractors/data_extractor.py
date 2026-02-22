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
from .email_extractor import EmailExtractor
from .teams_extractor import TeamsExtractor
from ..config import Config
from ..forensic_utils import ForensicIntegrity

class DataExtractor:
    """Coordinates data extraction from all sources."""

    def __init__(self, forensic, third_party_registry=None):
        """Initialize data extractor with forensic tracking.

        Args:
            forensic: ForensicRecorder instance.
            third_party_registry: Optional ThirdPartyRegistry for unmapped contacts.
        """
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        self.config = Config()

        # Create forensic integrity instance
        self.integrity = ForensicIntegrity(forensic)

        # Initialize individual extractors with proper parameters
        # iMessage extractor needs: db_path, forensic_recorder, forensic_integrity
        self.imessage = iMessageExtractor(
            self.config.messages_db_path,
            forensic,
            self.integrity
        ) if self.config.messages_db_path else None

        # WhatsApp extractor needs: export_dir, forensic_recorder, forensic_integrity
        self.whatsapp = WhatsAppExtractor(
            self.config.whatsapp_source_dir,
            forensic,
            self.integrity
        ) if self.config.whatsapp_source_dir else None

        # Email extractor needs: source_dir, forensic_recorder, forensic_integrity
        # Also receives the third_party_registry for unmapped contact tracking
        self.email = EmailExtractor(
            self.config.email_source_dir,
            forensic,
            self.integrity,
            third_party_registry=third_party_registry,
        ) if self.config.email_source_dir else None

        # Teams extractor needs: source_dir, forensic_recorder, forensic_integrity
        self.teams = TeamsExtractor(
            self.config.teams_source_dir,
            forensic,
            self.integrity,
            third_party_registry=third_party_registry,
        ) if self.config.teams_source_dir else None

        self.forensic.record_action(
            "DATA_EXTRACTOR_INIT",
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
            imessages = self.imessage.extract_messages()
            if imessages:  # List check instead of DataFrame.empty
                all_messages.extend(imessages)
                self.logger.info(f"Extracted {len(imessages)} iMessages")
        except Exception as e:
            self.logger.error(f"Failed to extract iMessages: {e}")
            self.forensic.record_action(
                "IMESSAGE_EXTRACTION_FAILED",
                f"iMessage extraction failed: {str(e)}"
            )
        
        # Extract WhatsApp messages
        try:
            self.logger.info("Extracting WhatsApp messages...")
            whatsapp_messages = self.whatsapp.extract_all()
            if whatsapp_messages:  # List check
                all_messages.extend(whatsapp_messages)
                self.logger.info(f"Extracted {len(whatsapp_messages)} WhatsApp messages")
        except Exception as e:
            self.logger.error(f"Failed to extract WhatsApp messages: {e}")
            self.forensic.record_action(
                "WHATSAPP_EXTRACTION_FAILED",
                f"WhatsApp extraction failed: {str(e)}"
            )

        # Extract email messages
        try:
            self.logger.info("Extracting email messages...")
            email_messages = self.email.extract_all()
            if email_messages:  # List check
                all_messages.extend(email_messages)
                self.logger.info(f"Extracted {len(email_messages)} email messages")
        except Exception as e:
            self.logger.error(f"Failed to extract email messages: {e}")
            self.forensic.record_action(
                "EMAIL_EXTRACTION_FAILED",
                f"Email extraction failed: {str(e)}"
            )

        # Extract Teams messages
        try:
            self.logger.info("Extracting Teams messages...")
            teams_messages = self.teams.extract_all()
            if teams_messages:  # List check
                all_messages.extend(teams_messages)
                self.logger.info(f"Extracted {len(teams_messages)} Teams messages")
        except Exception as e:
            self.logger.error(f"Failed to extract Teams messages: {e}")
            self.forensic.record_action(
                "TEAMS_EXTRACTION_FAILED",
                f"Teams extraction failed: {str(e)}"
            )

        # Record extraction summary
        self.forensic.record_action(
            "EXTRACTION_COMPLETE",
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
            f"Validation {'passed' if validation['validation_passed'] else 'failed'}"
        )
        
        return validation