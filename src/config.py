#!/usr/bin/env python3
"""
Configuration management for the forensic message analyzer.
Loads settings from environment variables and .env file.
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Optional
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)


class Config:
    """
    Manages configuration settings for the forensic message analyzer.
    Loads from .env file and provides validated access to settings.
    """
    
    def __init__(self):
        """Initialize configuration by loading environment variables."""
        # Try multiple locations for .env file
        env_locations = [
            # Primary location: data directory
            Path.home() / 'workspace/data/forensic_message_analyzer/.env',
            # Check if specified via environment variable
            Path(os.environ.get('DOTENV_PATH', '')),
            # Fallback: local .env
            Path('.env'),
        ]
        
        # Try each location
        loaded = False
        for env_path in env_locations:
            if env_path and env_path.exists():
                load_dotenv(env_path, override=True)
                logger.info(f"Loaded .env from: {env_path}")
                loaded = True
                break
        
        if not loaded:
            logger.warning("No .env file found. Using system environment variables only.")
            logger.info(f"Searched locations: {[str(p) for p in env_locations if p]}")
        
        # Load configuration values
        self._load_config()
    
    def _load_config(self):
        """Load configuration from environment variables."""
        # Azure OpenAI settings
        self.azure_endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
        self.azure_api_key = os.getenv('AZURE_OPENAI_API_KEY')
        self.azure_deployment = os.getenv('AZURE_OPENAI_DEPLOYMENT_NAME')
        self.azure_api_version = os.getenv('AZURE_OPENAI_API_VERSION')
        
        # Contact mappings - flexible system that allows custom names
        # PERSON1_NAME defines the name used in reports (e.g., "David Snyder")
        # PERSON1_MAPPING contains the list of identifiers to match (phones, emails, names)
        person1_name = os.getenv('PERSON1_NAME', 'Person1')
        person2_name = os.getenv('PERSON2_NAME', 'Person2')
        person3_name = os.getenv('PERSON3_NAME', 'Person3')
        
        # Load contact mappings and expand phone number variations
        self.person1_contacts = self._expand_contact_mappings(self._parse_json_list('PERSON1_MAPPING'))
        self.person2_contacts = self._expand_contact_mappings(self._parse_json_list('PERSON2_MAPPING'))
        self.person3_contacts = self._expand_contact_mappings(self._parse_json_list('PERSON3_MAPPING'))
        
        # Store the actual names being used (these appear in reports)
        self.person1_name = person1_name
        self.person2_name = person2_name
        self.person3_name = person3_name
        
        # Create contact_mappings using the report names
        # This maps display names to their list of identifiers
        self.contact_mappings = {
            person1_name: self.person1_contacts,
            person2_name: self.person2_contacts,
            person3_name: self.person3_contacts,
        }
        
        # Date range
        self.start_date = os.getenv('START_DATE')
        self.end_date = os.getenv('END_DATE')
        
        # Analysis thresholds
        self.threat_threshold = float(os.getenv('THREAT_CONFIDENCE_THRESHOLD', '0.5'))
        self.review_threshold = float(os.getenv('MANUAL_REVIEW_THRESHOLD', '0.5'))
        
        # Analysis settings
        self.batch_size = int(os.getenv('BATCH_SIZE', '10'))
        self.max_retries = int(os.getenv('MAX_RETRIES', '3'))
        self.enable_image_analysis = os.getenv('ENABLE_IMAGE_ANALYSIS', 'true').lower() == 'true'
        self.enable_sentiment = os.getenv('ENABLE_SENTIMENT_ANALYSIS', 'true').lower() == 'true'
        self.enable_ocr = os.getenv('ENABLE_OCR', 'true').lower() == 'true'
        
        # Data sources (expand ~ to home directory)
        self.whatsapp_source_dir = self._expand_path(os.getenv('WHATSAPP_SOURCE_DIR'))
        self.screenshot_source_dir = self._expand_path(os.getenv('SCREENSHOT_SOURCE_DIR'))
        self.messages_db_path = self._expand_path(os.getenv('MESSAGES_DB_PATH'))
        self.messages_db_wal = self._expand_path(os.getenv('MESSAGES_DB_WAL'))
        self.messages_db_shm = self._expand_path(os.getenv('MESSAGES_DB_SHM'))
        
        # Review directory
        self.review_dir = self._expand_path(
            os.getenv('REVIEW_DIR', '~/workspace/data/forensic_message_analyzer/review')
        )
        
        # Rate limiting
        self.tokens_per_minute = int(os.getenv('TOKENS_PER_MINUTE', '2000'))
        self.request_delay_ms = int(os.getenv('REQUEST_DELAY_MS', '500'))
        self.max_tokens_per_request = int(os.getenv('MAX_TOKENS_PER_REQUEST', '150'))
        
        # Output settings
        self.output_dir = self._expand_path(
            os.getenv('OUTPUT_DIR', '~/workspace/output/forensic_message_analyzer')
        )
        
        # Logging
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.content_filter_log = self._expand_path(os.getenv('CONTENT_FILTER_LOG'))
        
        # Ensure critical directories exist
        self._ensure_directories()
    
    def _expand_path(self, path: Optional[str]) -> Optional[str]:
        """Expand ~ in paths to actual home directory."""
        if path:
            return str(Path(path).expanduser())
        return None
    
    def _parse_json_list(self, env_var: str) -> List[str]:
        """Parse JSON list from environment variable."""
        value = os.getenv(env_var, '[]')
        try:
            if value and value != 'None':
                return json.loads(value)
        except json.JSONDecodeError:
            logger.warning(f"Could not parse {env_var} as JSON: {value}")
        return []
    
    def _normalize_phone_number(self, phone: str) -> List[str]:
        """
        Generate common format variations of a phone number.
        
        Args:
            phone: Phone number in any format (e.g., "+12345678901", "234-567-8901")
            
        Returns:
            List of phone number variations including:
            - Original format
            - E.164 format (+12345678901)
            - Dashed format (234-567-8901)
            - Parentheses format ((234) 567-8901)
        """
        import re
        
        # Extract just the digits
        digits = re.sub(r'\D', '', phone)
        
        # Skip if not a valid phone number length (assuming US/Canada)
        if len(digits) < 10:
            return [phone]
        
        variations = [phone]  # Always include original
        
        # Handle different lengths
        if len(digits) == 10:
            # US/Canada number without country code
            area = digits[0:3]
            prefix = digits[3:6]
            line = digits[6:10]
            
            # Add E.164 format with +1
            variations.append(f"+1{digits}")
            # Add dashed format
            variations.append(f"{area}-{prefix}-{line}")
            # Add parentheses format
            variations.append(f"({area}) {prefix}-{line}")
            
        elif len(digits) == 11 and digits[0] == '1':
            # US/Canada number with country code
            area = digits[1:4]
            prefix = digits[4:7]
            line = digits[7:11]
            
            # Add E.164 format
            variations.append(f"+{digits}")
            # Add dashed format (without country code)
            variations.append(f"{area}-{prefix}-{line}")
            # Add parentheses format (without country code)
            variations.append(f"({area}) {prefix}-{line}")
            # Add 10-digit format
            variations.append(digits[1:])
            
        else:
            # International or non-standard format
            # Just add E.164 if not already present
            if not phone.startswith('+'):
                variations.append(f"+{digits}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variations = []
        for var in variations:
            if var not in seen:
                seen.add(var)
                unique_variations.append(var)
        
        return unique_variations
    
    def _expand_contact_mappings(self, contacts: List[str]) -> List[str]:
        """
        Expand contact list to include phone number variations.
        
        Args:
            contacts: List of contact identifiers (phones, emails, names)
            
        Returns:
            Expanded list with phone number variations included
        """
        import re
        
        expanded = []
        phone_pattern = re.compile(r'[\d\+\(\)\-\s]{10,}')  # Matches phone-like strings
        
        for contact in contacts:
            expanded.append(contact)  # Always include original
            
            # If it looks like a phone number, add variations
            if phone_pattern.match(contact.strip()):
                variations = self._normalize_phone_number(contact)
                expanded.extend([v for v in variations if v != contact])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_expanded = []
        for item in expanded:
            if item not in seen:
                seen.add(item)
                unique_expanded.append(item)
        
        return unique_expanded
    
    def _ensure_directories(self):
        """Create necessary directories if they don't exist."""
        directories = [
            self.output_dir,
            self.review_dir,
        ]
        
        for dir_path in directories:
            if dir_path:
                path = Path(dir_path)
                if not path.exists():
                    try:
                        path.mkdir(parents=True, exist_ok=True)
                        logger.info(f"Created directory: {path}")
                    except Exception as e:
                        logger.warning(f"Could not create directory {path}: {e}")
    
    def validate(self) -> tuple[bool, List[str]]:
        """
        Validate configuration settings.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required paths
        if not self.output_dir:
            errors.append("OUTPUT_DIR not configured")
        
        # Check for at least one data source
        if not any([self.messages_db_path, self.whatsapp_source_dir, self.screenshot_source_dir]):
            errors.append("No data sources configured (need iMessage, WhatsApp, or screenshots)")
        
        # Check Azure configuration if AI analysis is expected
        if self.azure_endpoint and not self.azure_api_key:
            errors.append("Azure endpoint configured but API key missing")
        
        return len(errors) == 0, errors
    
    def get_source_info(self) -> Dict[str, str]:
        """
        Get information about configured data sources.
        
        Returns:
            Dictionary of source type to path
        """
        sources = {}
        
        if self.messages_db_path:
            sources['iMessage'] = self.messages_db_path
        if self.whatsapp_source_dir:
            sources['WhatsApp'] = self.whatsapp_source_dir
        if self.screenshot_source_dir:
            sources['Screenshots'] = self.screenshot_source_dir
            
        return sources
