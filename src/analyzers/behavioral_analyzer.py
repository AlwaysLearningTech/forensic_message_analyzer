"""
Behavioral analysis module.
Analyzes communication patterns and behaviors.
"""

import logging
from typing import Dict, Any, List
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

class BehavioralAnalyzer:
    """Analyze behavioral patterns in communications."""
    
    def __init__(self, forensic):
        """Initialize behavioral analyzer."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        
        self.forensic.record_action(
            "BEHAVIORAL_ANALYZER_INIT",
            "behavioral_analysis",
            "Initialized behavioral pattern analyzer"
        )
    
    def analyze_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze behavioral patterns in messages.
        
        Args:
            df: DataFrame with messages
            
        Returns:
            Dictionary of behavioral analysis results
        """
        results = {
            'behavioral_profiles': self._create_behavioral_profiles(df),
            'sentiment_progression': self._analyze_sentiment_progression(df),
            'communication_frequency': self._analyze_communication_patterns(df),
            'escalation_patterns': self._identify_escalation_patterns(df),
            'relationship_dynamics': self._analyze_relationship_dynamics(df),
            'threat_assessment': self._comprehensive_threat_assessment(df),
            'visitation_analysis': self._analyze_visitation_patterns(df),
            'communication_patterns': self._analyze_communication_patterns(df),
            'response_patterns': self._analyze_response_patterns(df),
            'time_patterns': self._analyze_time_patterns(df)
        }
        
        self.forensic.record_action(
            "BEHAVIORAL_ANALYSIS_COMPLETE",
            "behavioral_analysis",
            f"Analyzed {len(df)} messages for behavioral patterns"
        )
        
        return results
    
    def _create_behavioral_profiles(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Create behavioral profiles for each participant."""
        profiles = {}
        
        if 'sender' not in df.columns:
            return profiles
        
        for sender in df['sender'].unique():
            if pd.isna(sender):
                continue
                
            sender_msgs = df[df['sender'] == sender]
            
            profile = {
                'message_count': len(sender_msgs),
                'avg_message_length': sender_msgs['message'].str.len().mean() if 'message' in df.columns else 0,
                'active_hours': self._get_active_hours(sender_msgs),
                'communication_style': self._analyze_communication_style(sender_msgs)
            }
            
            # Add sentiment if available
            if 'sentiment_score' in df.columns:
                profile['avg_sentiment'] = sender_msgs['sentiment_score'].mean()
                profile['sentiment_variance'] = sender_msgs['sentiment_score'].var()
            
            profiles[str(sender)] = profile
        
        return profiles
    
    def _analyze_sentiment_progression(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze how sentiment changes over time."""
        if 'sentiment_score' not in df.columns or 'timestamp' not in df.columns:
            return {}
        
        df_sorted = df.sort_values('timestamp')
        
        # Divide into quarters
        quarter_size = len(df_sorted) // 4
        quarters = []
        
        for i in range(4):
            start_idx = i * quarter_size
            end_idx = start_idx + quarter_size if i < 3 else len(df_sorted)
            quarter_data = df_sorted.iloc[start_idx:end_idx]
            
            quarters.append({
                'period': f'Q{i+1}',
                'avg_sentiment': quarter_data['sentiment_score'].mean(),
                'min_sentiment': quarter_data['sentiment_score'].min(),
                'max_sentiment': quarter_data['sentiment_score'].max()
            })
        
        # Calculate trend
        sentiment_trend = 'stable'
        if len(quarters) >= 2:
            first_half = (quarters[0]['avg_sentiment'] + quarters[1]['avg_sentiment']) / 2
            second_half = (quarters[2]['avg_sentiment'] + quarters[3]['avg_sentiment']) / 2
            
            if second_half < first_half - 0.2:
                sentiment_trend = 'declining'
            elif second_half > first_half + 0.2:
                sentiment_trend = 'improving'
        
        return {
            'quarterly_analysis': quarters,
            'overall_trend': sentiment_trend,
            'volatility': df_sorted['sentiment_score'].std() if len(df_sorted) > 1 else 0
        }
    
    def _analyze_relationship_dynamics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze dynamics between participants."""
        dynamics = {
            'power_balance': self._analyze_power_dynamics(df),
            'conflict_periods': self._identify_conflict_periods(df),
            'cooperation_level': self._measure_cooperation(df)
        }
        
        return dynamics
    
    def _comprehensive_threat_assessment(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Comprehensive threat and risk assessment."""
        assessment = {
            'threat_level': 'low',
            'risk_factors': [],
            'protective_factors': []
        }
        
        if 'threat_detected' in df.columns:
            threat_rate = df['threat_detected'].mean()
            
            if threat_rate > 0.3:
                assessment['threat_level'] = 'high'
                assessment['risk_factors'].append('High frequency of threatening language')
            elif threat_rate > 0.1:
                assessment['threat_level'] = 'moderate'
                assessment['risk_factors'].append('Moderate presence of concerning language')
        
        # Check for escalation
        escalation = self._identify_escalation_patterns(df)
        if escalation.get('sentiment_escalation'):
            assessment['risk_factors'].append('Escalating negative sentiment')
        
        if escalation.get('threat_escalation'):
            assessment['risk_factors'].append('Increasing threat frequency')
        
        # Check for protective factors
        if 'sentiment_score' in df.columns:
            positive_msgs = df[df['sentiment_score'] > 0.5]
            if len(positive_msgs) / len(df) > 0.3:
                assessment['protective_factors'].append('Significant positive communication')
        
        return assessment
    
    def _analyze_visitation_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze discussions about visitation."""
        visitation = {
            'mentions': 0,
            'sentiment_around_visits': [],
            'scheduling_conflicts': 0
        }
        
        if 'message' not in df.columns:
            return visitation
        
        # Keywords related to visitation
        visit_keywords = ['visit', 'visitation', 'pickup', 'drop off', 'custody', 
                         'weekend', 'schedule', 'exchange', 'parenting time']
        
        for _, row in df.iterrows():
            msg_lower = str(row.get('message', '')).lower()
            if any(keyword in msg_lower for keyword in visit_keywords):
                visitation['mentions'] += 1
                
                if 'sentiment_score' in row:
                    visitation['sentiment_around_visits'].append(row['sentiment_score'])
                
                # Check for conflict indicators
                if any(word in msg_lower for word in ['cancel', 'refuse', 'deny', 'won\'t', 'can\'t']):
                    visitation['scheduling_conflicts'] += 1
        
        # Calculate average sentiment around visitation discussions
        if visitation['sentiment_around_visits']:
            visitation['avg_visit_sentiment'] = np.mean(visitation['sentiment_around_visits'])
        
        return visitation
    
    def _analyze_communication_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze communication frequency and volume patterns."""
        if 'timestamp' not in df.columns:
            return {}
        
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        daily_counts = df.groupby('date').size()
        
        # Identify bursts (days with unusually high message volume)
        mean_daily = daily_counts.mean()
        std_daily = daily_counts.std()
        burst_threshold = mean_daily + (2 * std_daily)
        burst_days = daily_counts[daily_counts > burst_threshold]
        
        return {
            'average_daily_messages': mean_daily,
            'standard_deviation': std_daily,
            'burst_days': len(burst_days),
            'burst_dates': burst_days.index.tolist() if len(burst_days) > 0 else [],
            'longest_silence': self._find_longest_silence(daily_counts)
        }
    
    def _identify_escalation_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze escalation in tone or threats."""
        if 'sentiment_score' not in df.columns:
            return {}
        
        # Sort by timestamp
        df_sorted = df.sort_values('timestamp')
        
        # Calculate rolling average of sentiment
        window_size = min(50, len(df) // 10)  # Adaptive window
        if window_size > 1:
            df_sorted['rolling_sentiment'] = df_sorted['sentiment_score'].rolling(window_size).mean()
            
            # Detect declining sentiment trend
            first_half_avg = df_sorted.iloc[:len(df_sorted)//2]['sentiment_score'].mean()
            second_half_avg = df_sorted.iloc[len(df_sorted)//2:]['sentiment_score'].mean()
            
            escalation_detected = second_half_avg < first_half_avg - 0.2
        else:
            escalation_detected = False
            first_half_avg = 0
            second_half_avg = 0
        
        # Count threat escalation
        threat_escalation = False
        if 'threat_detected' in df.columns:
            df_sorted['threat_cumsum'] = df_sorted['threat_detected'].cumsum()
            threat_rate_first = df_sorted.iloc[:len(df_sorted)//2]['threat_detected'].mean()
            threat_rate_second = df_sorted.iloc[len(df_sorted)//2:]['threat_detected'].mean()
            threat_escalation = threat_rate_second > threat_rate_first * 1.5
        
        return {
            'sentiment_escalation': escalation_detected,
            'sentiment_change': second_half_avg - first_half_avg,
            'threat_escalation': threat_escalation,
            'escalation_periods': self._identify_escalation_periods(df_sorted)
        }
    
    def _analyze_response_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze response times and patterns."""
        if 'sender' not in df.columns or 'timestamp' not in df.columns:
            return {}
        
        df_sorted = df.sort_values('timestamp')
        df_sorted['time_diff'] = df_sorted['timestamp'].diff()
        
        # Calculate average response times by sender
        response_times = {}
        for sender in df_sorted['sender'].unique():
            if pd.isna(sender):
                continue
            sender_messages = df_sorted[df_sorted['sender'] == sender]
            avg_response = sender_messages['time_diff'].mean()
            if pd.notna(avg_response):
                response_times[str(sender)] = str(avg_response)
        
        return {
            'average_response_times': response_times,
            'immediate_responses': len(df_sorted[df_sorted['time_diff'] < pd.Timedelta(minutes=1)]),
            'delayed_responses': len(df_sorted[df_sorted['time_diff'] > pd.Timedelta(hours=24)])
        }
    
    def _analyze_time_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze temporal patterns."""
        if 'timestamp' not in df.columns:
            return {}
        
        # Work with a copy to avoid SettingWithCopyWarning
        df_time = df.copy()
        df_time['hour'] = pd.to_datetime(df_time['timestamp']).dt.hour
        df_time['weekday'] = pd.to_datetime(df_time['timestamp']).dt.dayofweek
        
        # Identify unusual timing patterns
        late_night = df_time[(df_time['hour'] >= 23) | (df_time['hour'] <= 4)]
        early_morning = df_time[(df_time['hour'] >= 5) & (df_time['hour'] <= 7)]
        
        return {
            'late_night_messages': len(late_night),
            'early_morning_messages': len(early_morning),
            'most_active_hour': df_time['hour'].mode()[0] if len(df_time) > 0 else None,
            'weekend_vs_weekday': {
                'weekend': len(df_time[df_time['weekday'].isin([5, 6])]),
                'weekday': len(df_time[~df_time['weekday'].isin([5, 6])])
            }
        }
    
    def _get_active_hours(self, df: pd.DataFrame) -> List[int]:
        """Get most active hours for a sender."""
        if 'timestamp' not in df.columns:
            return []
        
        # Extract hours without modifying the original DataFrame
        hours = pd.to_datetime(df['timestamp']).dt.hour
        hour_counts = hours.value_counts()
        
        # Return top 3 most active hours
        return hour_counts.nlargest(3).index.tolist()
    
    def _analyze_communication_style(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze communication style characteristics."""
        style = {}
        
        if 'message' not in df.columns:
            return style
        
        # Message length patterns
        msg_lengths = df['message'].str.len()
        style['avg_length'] = msg_lengths.mean()
        style['uses_caps'] = df['message'].str.isupper().sum() / len(df)
        style['uses_questions'] = df['message'].str.contains('\\?').sum() / len(df)
        style['uses_exclamations'] = df['message'].str.contains('!').sum() / len(df)
        
        return style
    
    def _analyze_power_dynamics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze power dynamics in conversation."""
        dynamics = {}
        
        if 'sender' not in df.columns:
            return dynamics
        
        # Message initiation patterns
        sender_counts = df['sender'].value_counts()
        if len(sender_counts) > 1:
            dynamics['message_balance'] = sender_counts.min() / sender_counts.max()
            dynamics['dominant_sender'] = sender_counts.idxmax()
        
        return dynamics
    
    def _identify_conflict_periods(self, df: pd.DataFrame) -> List[Dict]:
        """Identify periods of conflict."""
        periods = []
        
        if 'sentiment_score' not in df.columns or 'timestamp' not in df.columns:
            return periods
        
        # Look for clusters of negative sentiment
        df_sorted = df.sort_values('timestamp')
        negative_msgs = df_sorted[df_sorted['sentiment_score'] < -0.3]
        
        if len(negative_msgs) > 0:
            # Group negative messages that are close in time
            negative_msgs['time_diff'] = negative_msgs['timestamp'].diff()
            
            current_period = {'start': None, 'end': None, 'messages': []}
            
            for _, row in negative_msgs.iterrows():
                if current_period['start'] is None:
                    current_period = {
                        'start': row['timestamp'],
                        'end': row['timestamp'],
                        'messages': [row['message']] if 'message' in row else []
                    }
                elif row['time_diff'] < timedelta(hours=24):
                    current_period['end'] = row['timestamp']
                    if 'message' in row:
                        current_period['messages'].append(row['message'])
                else:
                    periods.append(current_period)
                    current_period = {
                        'start': row['timestamp'],
                        'end': row['timestamp'],
                        'messages': [row['message']] if 'message' in row else []
                    }
            
            if current_period['start'] is not None:
                periods.append(current_period)
        
        return periods
    
    def _measure_cooperation(self, df: pd.DataFrame) -> float:
        """Measure level of cooperation in conversations."""
        if 'sentiment_score' not in df.columns:
            return 0.5  # Neutral if no data
        
        # Positive sentiment ratio as proxy for cooperation
        positive_ratio = (df['sentiment_score'] > 0.2).mean()
        
        return positive_ratio
    
    def _find_longest_silence(self, daily_counts: pd.Series) -> int:
        """Find the longest gap between messages."""
        if len(daily_counts) < 2:
            return 0
        
        dates = pd.to_datetime(daily_counts.index)
        max_gap = 0
        
        for i in range(1, len(dates)):
            gap = (dates[i] - dates[i-1]).days
            if gap > max_gap:
                max_gap = gap
        
        return max_gap
    
    def _identify_escalation_periods(self, df: pd.DataFrame) -> list:
        """Identify specific periods of escalation."""
        periods = []
        
        if 'threat_detected' not in df.columns:
            return periods
        
        # Use a sliding window to find periods with high threat density
        window_size = min(20, len(df) // 5)
        if window_size < 3:
            return periods
        
        for i in range(len(df) - window_size):
            window = df.iloc[i:i+window_size]
            threat_rate = window['threat_detected'].mean()
            
            if threat_rate > 0.3:  # More than 30% threats in window
                periods.append({
                    'start': window.iloc[0]['timestamp'],
                    'end': window.iloc[-1]['timestamp'],
                    'threat_rate': threat_rate,
                    'message_count': len(window)
                })
        
        # Merge overlapping periods
        merged_periods = []
        for period in periods:
            if not merged_periods:
                merged_periods.append(period)
            elif period['start'] <= merged_periods[-1]['end']:
                # Merge with previous
                merged_periods[-1]['end'] = period['end']
                merged_periods[-1]['threat_rate'] = max(merged_periods[-1]['threat_rate'], period['threat_rate'])
            else:
                merged_periods.append(period)
        
        return merged_periods
