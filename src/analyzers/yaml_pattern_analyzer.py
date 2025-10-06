"""
YAML-based pattern detection system.
Allows flexible pattern definitions for message analysis.
"""

import yaml
import re
import logging
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd

class YamlPatternAnalyzer:
    """Analyzes messages using YAML-defined patterns."""
    
    def __init__(self, forensic, patterns_file: Path = None):
        """Initialize pattern analyzer."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        
        if patterns_file is None:
            patterns_file = Path("patterns/analysis_patterns.yaml")
        
        self.patterns = self.load_patterns(patterns_file)
        
        self.forensic.record_action(
            "YAML_PATTERN_ANALYZER_INIT",
            "pattern_analysis",
            f"Loaded {len(self.patterns)} pattern categories"
        )
    
    def load_patterns(self, filepath: Path) -> Dict[str, Any]:
        """Load patterns from YAML file."""
        default_patterns = {
            'behavioral_patterns': {
                'love_bombing': {
                    'patterns': [
                        r'(love|adore|worship|obsessed).*you',
                        r'(perfect|amazing|incredible|best thing)',
                        r'(can\'t live without|need you|only one)'
                    ],
                    'weight': 0.7,
                    'description': 'Excessive affection or attention'
                },
                'gaslighting': {
                    'patterns': [
                        r'(never said|didn\'t happen|imagining)',
                        r'(crazy|paranoid|overreacting)',
                        r'(remember it wrong|confused)'
                    ],
                    'weight': 0.9,
                    'description': 'Psychological manipulation'
                },
                'isolation': {
                    'patterns': [
                        r'(don\'t need|shouldn\'t see).*friends',
                        r'(spend.*time).*with me',
                        r'(they\'re|he\'s|she\'s).*bad influence'
                    ],
                    'weight': 0.8,
                    'description': 'Attempts to isolate from support network'
                }
            },
            'communication_patterns': {
                'excessive_contact': {
                    'frequency_threshold': 20,  # messages per day
                    'description': 'Excessive messaging frequency'
                },
                'time_patterns': {
                    'late_night': {
                        'hours': [23, 0, 1, 2, 3, 4],
                        'description': 'Late night communications'
                    },
                    'work_hours': {
                        'hours': [9, 10, 11, 12, 13, 14, 15, 16],
                        'description': 'Communications during work hours'
                    }
                }
            }
        }
        
        if filepath.exists():
            try:
                with open(filepath, 'r') as f:
                    loaded_patterns = yaml.safe_load(f)
                    if loaded_patterns:
                        return loaded_patterns
            except Exception as e:
                self.logger.error(f"Failed to load patterns from {filepath}: {e}")
        
        # Create default patterns file
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            yaml.dump(default_patterns, f, default_flow_style=False)
        
        return default_patterns
    
    def analyze_patterns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Analyze messages for defined patterns.
        
        Args:
            df: DataFrame with messages
            
        Returns:
            DataFrame with pattern detection results
        """
        # Initialize pattern columns
        df['patterns_detected'] = ''
        df['pattern_score'] = 0.0
        
        behavioral = self.patterns.get('behavioral_patterns', {})
        
        for idx, row in df.iterrows():
            if pd.isna(row.get('content')):
                continue
            
            text = str(row['content']).lower()
            detected = []
            total_score = 0.0
            
            # Check behavioral patterns
            for pattern_name, pattern_config in behavioral.items():
                patterns = pattern_config.get('patterns', [])
                weight = pattern_config.get('weight', 1.0)
                
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        detected.append(pattern_name)
                        total_score += weight
                        break
            
            if detected:
                df.at[idx, 'patterns_detected'] = ', '.join(detected)
                df.at[idx, 'pattern_score'] = min(total_score, 1.0)
        
        patterns_found = (df['patterns_detected'] != '').sum()
        self.logger.info(f"Detected patterns in {patterns_found} messages")
        
        self.forensic.record_action(
            "PATTERN_ANALYSIS_COMPLETE",
            "pattern_analysis",
            f"Found patterns in {patterns_found} of {len(df)} messages"
        )
        
        return df
    
    def analyze_communication_frequency(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze communication frequency patterns."""
        if 'timestamp' not in df.columns:
            return {}
        
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        
        # Messages per day
        daily_counts = df.groupby('date').size()
        
        # Check for excessive contact
        comm_patterns = self.patterns.get('communication_patterns', {})
        excessive = comm_patterns.get('excessive_contact', {})
        threshold = excessive.get('frequency_threshold', 20)
        
        excessive_days = daily_counts[daily_counts > threshold]
        
        # Time-based patterns
        time_patterns = comm_patterns.get('time_patterns', {})
        late_night = time_patterns.get('late_night', {}).get('hours', [])
        work_hours = time_patterns.get('work_hours', {}).get('hours', [])
        
        late_night_msgs = df[df['hour'].isin(late_night)]
        work_hour_msgs = df[df['hour'].isin(work_hours)]
        
        analysis = {
            'total_days': len(daily_counts),
            'avg_messages_per_day': daily_counts.mean(),
            'max_messages_per_day': daily_counts.max(),
            'excessive_contact_days': len(excessive_days),
            'late_night_messages': len(late_night_msgs),
            'work_hour_messages': len(work_hour_msgs),
            'excessive_dates': excessive_days.index.tolist() if len(excessive_days) > 0 else []
        }
        
        return analysis