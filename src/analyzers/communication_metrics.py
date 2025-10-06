"""
Communication metrics generation module.
Generates comprehensive statistics and metrics from message data.
"""

import logging
from typing import Dict, Any, List
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

class CommunicationMetricsGenerator:
    """Generate comprehensive communication metrics."""
    
    def __init__(self, forensic):
        """Initialize metrics generator."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        
        self.forensic.record_action(
            "METRICS_GENERATOR_INIT",
            "metrics",
            "Initialized communication metrics generator"
        )
    
    def generate_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate comprehensive metrics from message data.
        
        Args:
            df: DataFrame with messages
            
        Returns:
            Dictionary of metrics
        """
        metrics = {
            'overview': self.generate_overview_metrics(df),
            'temporal': self.generate_temporal_metrics(df),
            'sentiment': self.generate_sentiment_metrics(df),
            'threats': self.generate_threat_metrics(df),
            'patterns': self.generate_pattern_metrics(df),
            'participants': self.generate_participant_metrics(df)
        }
        
        self.forensic.record_action(
            "METRICS_GENERATED",
            "metrics",
            f"Generated {len(metrics)} metric categories"
        )
        
        return metrics
    
    def generate_overview_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate overview metrics."""
        return {
            'total_messages': len(df),
            'unique_participants': df['sender'].nunique() if 'sender' in df.columns else 0,
            'sources': df['source'].value_counts().to_dict() if 'source' in df.columns else {},
            'date_range': {
                'start': df['timestamp'].min() if 'timestamp' in df.columns else None,
                'end': df['timestamp'].max() if 'timestamp' in df.columns else None,
                'days': (pd.to_datetime(df['timestamp'].max()) - 
                        pd.to_datetime(df['timestamp'].min())).days if 'timestamp' in df.columns else 0
            }
        }
    
    def generate_temporal_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate time-based metrics."""
        if 'timestamp' not in df.columns:
            return {}
        
        df['datetime'] = pd.to_datetime(df['timestamp'])
        df['date'] = df['datetime'].dt.date
        df['hour'] = df['datetime'].dt.hour
        df['weekday'] = df['datetime'].dt.dayofweek
        df['month'] = df['datetime'].dt.to_period('M')
        
        return {
            'messages_by_date': df.groupby('date').size().to_dict(),
            'messages_by_hour': df.groupby('hour').size().to_dict(),
            'messages_by_weekday': {
                0: len(df[df['weekday'] == 0]),  # Monday
                1: len(df[df['weekday'] == 1]),  # Tuesday
                2: len(df[df['weekday'] == 2]),  # Wednesday
                3: len(df[df['weekday'] == 3]),  # Thursday
                4: len(df[df['weekday'] == 4]),  # Friday
                5: len(df[df['weekday'] == 5]),  # Saturday
                6: len(df[df['weekday'] == 6])   # Sunday
            },
            'messages_by_month': df.groupby('month').size().to_dict(),
            'peak_hour': df['hour'].mode()[0] if len(df) > 0 else None,
            'peak_day': df['date'].mode()[0] if len(df) > 0 else None,
            'average_messages_per_day': df.groupby('date').size().mean(),
            'max_messages_in_day': df.groupby('date').size().max()
        }
    
    def generate_sentiment_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate sentiment-based metrics."""
        if 'sentiment_score' not in df.columns:
            return {}
        
        return {
            'average_sentiment': df['sentiment_score'].mean(),
            'sentiment_std': df['sentiment_score'].std(),
            'positive_messages': len(df[df['sentiment_score'] > 0.1]),
            'negative_messages': len(df[df['sentiment_score'] < -0.1]),
            'neutral_messages': len(df[(df['sentiment_score'] >= -0.1) & 
                                       (df['sentiment_score'] <= 0.1)]),
            'most_positive': df['sentiment_score'].max(),
            'most_negative': df['sentiment_score'].min(),
            'sentiment_trend': self.calculate_sentiment_trend(df)
        }
    
    def generate_threat_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate threat-related metrics."""
        if 'threat_detected' not in df.columns:
            return {}
        
        threat_df = df[df['threat_detected'] == True]
        
        metrics = {
            'total_threats': len(threat_df),
            'threat_percentage': (len(threat_df) / len(df) * 100) if len(df) > 0 else 0,
            'threat_categories': {},
            'high_confidence_threats': len(df[df.get('threat_confidence', 0) >= 0.75]),
            'threats_by_sender': threat_df['sender'].value_counts().to_dict() if 'sender' in threat_df.columns else {}
        }
        
        if 'threat_categories' in df.columns:
            for _, row in threat_df.iterrows():
                categories = str(row['threat_categories']).split(', ')
                for cat in categories:
                    if cat:
                        metrics['threat_categories'][cat] = metrics['threat_categories'].get(cat, 0) + 1
        
        return metrics
    
    def generate_pattern_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate pattern-related metrics."""
        if 'patterns_detected' not in df.columns:
            return {}
        
        pattern_df = df[df['patterns_detected'] != '']
        
        patterns = {}
        for _, row in pattern_df.iterrows():
            detected = str(row['patterns_detected']).split(', ')
            for pattern in detected:
                if pattern:
                    patterns[pattern] = patterns.get(pattern, 0) + 1
        
        return {
            'total_patterns_detected': len(pattern_df),
            'pattern_percentage': (len(pattern_df) / len(df) * 100) if len(df) > 0 else 0,
            'pattern_breakdown': patterns,
            'high_score_patterns': len(df[df.get('pattern_score', 0) >= 0.7])
        }
    
    def generate_participant_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate participant-based metrics."""
        if 'sender' not in df.columns:
            return {}
        
        participants = {}
        for sender in df['sender'].unique():
            if pd.isna(sender):
                continue
            
            sender_df = df[df['sender'] == sender]
            participants[str(sender)] = {
                'message_count': len(sender_df),
                'percentage': (len(sender_df) / len(df) * 100) if len(df) > 0 else 0,
                'avg_sentiment': sender_df['sentiment_score'].mean() if 'sentiment_score' in sender_df.columns else None,
                'threats_sent': sender_df['threat_detected'].sum() if 'threat_detected' in sender_df.columns else 0,
                'first_message': sender_df['timestamp'].min() if 'timestamp' in sender_df.columns else None,
                'last_message': sender_df['timestamp'].max() if 'timestamp' in sender_df.columns else None
            }
        
        return participants
    
    def calculate_sentiment_trend(self, df: pd.DataFrame) -> str:
        """Calculate overall sentiment trend."""
        if 'timestamp' not in df.columns or 'sentiment_score' not in df.columns:
            return 'unknown'
        
        df_sorted = df.sort_values('timestamp')
        first_half = df_sorted.iloc[:len(df_sorted)//2]
        second_half = df_sorted.iloc[len(df_sorted)//2:]
        
        first_avg = first_half['sentiment_score'].mean()
        second_avg = second_half['sentiment_score'].mean()
        
        if second_avg > first_avg + 0.1:
            return 'improving'
        elif second_avg < first_avg - 0.1:
            return 'declining'
        else:
            return 'stable'