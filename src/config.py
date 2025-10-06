#!/usr/bin/env python3
"""
Configuration settings for the forensic analyzer
"""

import os
from pathlib import Path
from typing import Dict, Any

class Config:
    """Configuration class for forensic analyzer settings"""
    
    def __init__(self):
        # Base paths
        self.BASE_DIR = Path(__file__).parent.parent
        self.SOURCE_DIR = self.BASE_DIR / "source_files"
        self.OUTPUT_DIR = self.BASE_DIR / "output"
        self.LOGS_DIR = self.BASE_DIR / "logs"
        self.PATTERNS_DIR = self.BASE_DIR / "patterns"
        
        # Ensure directories exist
        for directory in [self.OUTPUT_DIR, self.LOGS_DIR, self.PATTERNS_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Analysis settings
        self.ENABLE_IMESSAGE = True
        self.ENABLE_WHATSAPP = True
        self.ENABLE_SCREENSHOTS = True
        self.ENABLE_THREAT_ANALYSIS = True
        
        # Logging settings
        self.LOG_LEVEL = "INFO"
        self.LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        # Database settings
        self.DB_PATH = self.OUTPUT_DIR / "forensic_analysis.db"
        
        # API Keys (loaded from environment)
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
        self.VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
        
    def get_config(self) -> Dict[str, Any]:
        """Return configuration as dictionary"""
        return {
            "base_dir": str(self.BASE_DIR),
            "source_dir": str(self.SOURCE_DIR),
            "output_dir": str(self.OUTPUT_DIR),
            "logs_dir": str(self.LOGS_DIR),
            "patterns_dir": str(self.PATTERNS_DIR),
            "enable_imessage": self.ENABLE_IMESSAGE,
            "enable_whatsapp": self.ENABLE_WHATSAPP,
            "enable_screenshots": self.ENABLE_SCREENSHOTS,
            "enable_threat_analysis": self.ENABLE_THREAT_ANALYSIS,
            "log_level": self.LOG_LEVEL,
            "db_path": str(self.DB_PATH),
        }
    
    def validate(self) -> bool:
        """Validate configuration settings"""
        if not self.SOURCE_DIR.exists():
            print(f"Warning: Source directory does not exist: {self.SOURCE_DIR}")
            self.SOURCE_DIR.mkdir(parents=True, exist_ok=True)
        
        return True

# Create a singleton instance
config = Config()
