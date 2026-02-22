"""
Threat detection and analysis module.
Identifies potentially harmful content and threats in messages.
"""

import re
import logging
from typing import Dict, List, Any
import pandas as pd
from datetime import datetime

class ThreatAnalyzer:
    """Analyzes messages for threats and harmful content."""
    
    def __init__(self, forensic):
        """Initialize threat analyzer with forensic integrity tracking."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)

        # Define threat patterns
        self.threat_patterns = {
            'physical_threat': [
                r'\b(kill|hurt|harm|attack|assault|hit|punch|slap)\b',
                r'\b(destroy|damage|break|smash)\b.*\b(property|house|car|belongings)\b',
                r'\b(threat|threaten|warning|consequences)\b'
            ],
            'harassment': [
                r'\b(stalk|follow|watch|monitor|track)\b',
                r'\b(harass|bother|annoy|torment)\b',
                r'(call|text|message|contact).*\b(repeatedly|constantly|non-stop)\b'
            ],
            'coercion': [
                r'\b(force|make|coerce|pressure)\b.*\b(you|to)\b',
                r'\bif you (don\'t|do not|won\'t)\b.*\b(will|going to)\b',
                r'\b(blackmail|extort|ransom)\b'
            ],
            'emotional_abuse': [
                r'\b(worthless|useless|stupid|idiot|pathetic)\b',
                r'\b(crazy|insane|mental|psycho)\b',
                r'\b(nobody|no one).*\b(believe|help|care)\b'
            ],
            'custody_interference': [
                r'\b(take|keep|hide).*\b(kids?|children?|custody)\b',
                r'\b(won\'t|will not|never).*\b(see|visit).*\b(kids?|children?)\b',
                r'\b(court|judge|custody).*\b(violat|ignor|defy)\b'
            ]
        }

        # Pre-compile a single regex per category for vectorized matching
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        for category, patterns in self.threat_patterns.items():
            combined = '|'.join(f'(?:{p})' for p in patterns)
            self._compiled_patterns[category] = re.compile(combined, re.IGNORECASE)

        self.forensic.record_action(
            "THREAT_ANALYZER_INIT",
            f"Initialized with {len(self.threat_patterns)} threat categories"
        )

    def detect_threats(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect threats and harmful content in messages.

        Args:
            df: DataFrame with messages to analyze

        Returns:
            DataFrame with threat detection columns added
        """
        self.logger.info(f"Analyzing {len(df)} messages for threats")

        content = df['content'].fillna('').astype(str).str.lower()

        # Vectorized: test each category against all messages at once
        category_hits = {}
        for category, pattern in self._compiled_patterns.items():
            category_hits[category] = content.str.contains(pattern, regex=True, na=False)

        # Build result columns from the per-category boolean series
        categories_list = []
        confidence_list = []
        for i in range(len(df)):
            matched = [cat for cat, hits in category_hits.items() if hits.iloc[i]]
            categories_list.append(', '.join(matched) if matched else '')
            confidence_list.append(min(len(matched) * 0.25, 1.0))

        df['threat_categories'] = categories_list
        df['threat_confidence'] = confidence_list
        df['threat_detected'] = df['threat_confidence'] > 0
        df['harmful_content'] = df['threat_detected']
        
        threats_found = df['threat_detected'].sum()
        self.logger.info(f"Found threats in {threats_found} messages")
        
        self.forensic.record_action(
            "THREAT_DETECTION_COMPLETE",
            f"Detected threats in {threats_found} of {len(df)} messages"
        )
        
        return df
    
    def generate_threat_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate summary of threat analysis."""
        summary = {
            'total_messages': len(df),
            'messages_with_threats': df['threat_detected'].sum(),
            'threat_percentage': (df['threat_detected'].sum() / len(df) * 100) if len(df) > 0 else 0,
            'category_breakdown': {},
            'high_confidence_threats': len(df[df['threat_confidence'] >= 0.75]),
            'timestamp': datetime.now().isoformat()
        }
        
        # Count by category
        for _, row in df[df['threat_detected'] == True].iterrows():
            categories = str(row.get('threat_categories', '')).split(', ')
            for cat in categories:
                if cat:
                    summary['category_breakdown'][cat] = summary['category_breakdown'].get(cat, 0) + 1
        
        self.forensic.record_action(
            "THREAT_SUMMARY_GENERATED",
            f"Summary generated for {summary['messages_with_threats']} threats"
        )
        
        return summary