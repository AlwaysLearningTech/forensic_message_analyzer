"""
Communication metrics analyzer for forensic message analysis.
Generates metrics and statistics for legal review following Daubert standards.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import pandas as pd
from pathlib import Path

from ..forensic_utils import ForensicRecorder


class CommunicationMetricsAnalyzer:
    """
    Analyzes communication patterns and generates metrics for legal review.
    Provides quantitative evidence of communication frequency, timing, and volume.
    """
    
    def __init__(self, forensic_recorder: Optional[ForensicRecorder] = None):
        """
        Initialize the communication metrics analyzer.
        
        Args:
            forensic_recorder: Optional ForensicRecorder for chain of custody
        """
        self.forensic = forensic_recorder or ForensicRecorder()
        self.forensic.record_action(
            "metrics_init",
            "Communication metrics analyzer initialized"
        )
    
    def analyze_messages(self, messages: List[Dict]) -> Dict[str, Any]:
        """
        Analyze messages to generate communication metrics.
        Provides statistical evidence for pattern identification (Daubert reliability).
        
        Args:
            messages: List of message dictionaries
            
        Returns:
            Dictionary containing comprehensive metrics
        """
        if not messages:
            self.forensic.record_action(
                "metrics_analysis",
                "No messages to analyze",
                {"message_count": 0}
            )
            return self._empty_metrics()
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame(messages)
        
        # Ensure timestamp column is datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        metrics = {
            "generated_at": datetime.now().isoformat(),
            "total_messages": len(messages),
            "overview": self._calculate_overview_metrics(df),
            "temporal": self._calculate_temporal_metrics(df),
            "participants": self._calculate_participant_metrics(df),
            "content": self._calculate_content_metrics(df),
            "patterns": self._identify_communication_patterns(df),
            "legal_relevance": self._assess_legal_relevance(df)
        }
        
        self.forensic.record_action(
            "metrics_generated",
            f"Generated communication metrics for {len(messages)} messages",
            {
                "message_count": len(messages),
                "metrics_categories": list(metrics.keys())
            }
        )
        
        return metrics
    
    def _empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics structure when no data available."""
        return {
            "generated_at": datetime.now().isoformat(),
            "total_messages": 0,
            "overview": {},
            "temporal": {},
            "participants": {},
            "content": {},
            "patterns": {},
            "legal_relevance": {}
        }
    
    def _calculate_overview_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate high-level overview metrics.
        Provides summary statistics for legal review.
        """
        overview = {
            "total_messages": len(df),
            "unique_senders": df['sender'].nunique() if 'sender' in df.columns else 0,
            "unique_recipients": df['recipient'].nunique() if 'recipient' in df.columns else 0,
            "date_range": {
                "start": str(df['timestamp'].min()) if 'timestamp' in df.columns and not df.empty else None,
                "end": str(df['timestamp'].max()) if 'timestamp' in df.columns and not df.empty else None,
                "duration_days": (df['timestamp'].max() - df['timestamp'].min()).days if 'timestamp' in df.columns and not df.empty else 0
            }
        }
        
        # Add message source breakdown
        if 'source' in df.columns:
            overview['sources'] = df['source'].value_counts().to_dict()
        
        return overview
    
    def _calculate_temporal_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate time-based metrics.
        Shows communication patterns over time for establishing behavior patterns.
        """
        if 'timestamp' not in df.columns or df.empty:
            return {}
        
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.day_name()
        df['date'] = df['timestamp'].dt.date
        
        temporal = {
            "messages_by_hour": df['hour'].value_counts().sort_index().to_dict(),
            "messages_by_day_of_week": df['day_of_week'].value_counts().to_dict(),
            "messages_by_date": df.groupby('date').size().to_dict(),
            "peak_hour": int(df['hour'].mode().iloc[0]) if not df['hour'].mode().empty else None,
            "peak_day": df['day_of_week'].mode().iloc[0] if not df['day_of_week'].mode().empty else None,
            "average_messages_per_day": len(df) / max((df['timestamp'].max() - df['timestamp'].min()).days, 1)
        }
        
        # Convert date keys to strings for JSON serialization
        temporal['messages_by_date'] = {str(k): v for k, v in temporal['messages_by_date'].items()}
        
        return temporal
    
    def _calculate_participant_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate metrics for each participant.
        Identifies communication imbalances and patterns per participant.
        """
        if 'sender' not in df.columns:
            return {}
        
        participants = {}
        
        # Analyze each unique participant
        all_participants = set()
        if 'sender' in df.columns:
            all_participants.update(df['sender'].unique())
        if 'recipient' in df.columns:
            all_participants.update(df['recipient'].unique())
        
        for participant in all_participants:
            sent = df[df['sender'] == participant] if 'sender' in df.columns else pd.DataFrame()
            received = df[df['recipient'] == participant] if 'recipient' in df.columns else pd.DataFrame()
            
            participants[participant] = {
                "messages_sent": len(sent),
                "messages_received": len(received),
                "total_messages": len(sent) + len(received),
                "sent_ratio": len(sent) / max(len(sent) + len(received), 1),
                "first_message": str(min(
                    sent['timestamp'].min() if not sent.empty and 'timestamp' in sent.columns else datetime.max,
                    received['timestamp'].min() if not received.empty and 'timestamp' in received.columns else datetime.max
                )) if 'timestamp' in df.columns else None,
                "last_message": str(max(
                    sent['timestamp'].max() if not sent.empty and 'timestamp' in sent.columns else datetime.min,
                    received['timestamp'].max() if not received.empty and 'timestamp' in received.columns else datetime.min
                )) if 'timestamp' in df.columns else None
            }
            
            # Calculate average message length if content available
            if 'content' in sent.columns and not sent.empty:
                participants[participant]['avg_message_length'] = sent['content'].str.len().mean()
        
        return participants
    
    def _calculate_content_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate content-based metrics.
        Provides insights into message characteristics without revealing content.
        """
        if 'content' not in df.columns:
            return {}
        
        content_metrics = {
            "avg_message_length": df['content'].str.len().mean(),
            "max_message_length": df['content'].str.len().max(),
            "min_message_length": df['content'].str.len().min(),
            "total_characters": df['content'].str.len().sum(),
            "empty_messages": (df['content'].str.len() == 0).sum(),
            "messages_with_attachments": df['has_attachment'].sum() if 'has_attachment' in df.columns else 0
        }
        
        # Add word count statistics
        df['word_count'] = df['content'].str.split().str.len()
        content_metrics['avg_word_count'] = df['word_count'].mean()
        content_metrics['total_words'] = df['word_count'].sum()
        
        return content_metrics
    
    def _identify_communication_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Identify communication patterns relevant for legal analysis.
        Helps establish behavioral patterns and anomalies (FRE 901 authentication).
        """
        patterns = {}
        
        if 'timestamp' in df.columns and not df.empty:
            # Calculate response times between consecutive messages
            df_sorted = df.sort_values('timestamp')
            df_sorted['time_diff'] = df_sorted['timestamp'].diff()
            
            # Filter for reasonable response times (less than 24 hours)
            response_times = df_sorted[df_sorted['time_diff'] < timedelta(days=1)]['time_diff']
            
            if not response_times.empty:
                patterns['avg_response_time_minutes'] = response_times.mean().total_seconds() / 60
                patterns['median_response_time_minutes'] = response_times.median().total_seconds() / 60
            
            # Identify conversation sessions (messages within 30 minutes of each other)
            session_threshold = timedelta(minutes=30)
            df_sorted['new_session'] = df_sorted['time_diff'] > session_threshold
            df_sorted['session_id'] = df_sorted['new_session'].cumsum()
            
            patterns['total_sessions'] = df_sorted['session_id'].nunique()
            patterns['avg_messages_per_session'] = len(df) / max(patterns['total_sessions'], 1)
            
            # Identify periods of high activity
            if 'date' in df.columns:
                daily_counts = df.groupby('date').size()
                patterns['high_activity_threshold'] = daily_counts.quantile(0.75)
                patterns['high_activity_days'] = len(daily_counts[daily_counts > patterns['high_activity_threshold']])
        
        # Communication balance
        if 'sender' in df.columns and 'recipient' in df.columns:
            sender_counts = df['sender'].value_counts()
            patterns['communication_balance'] = {
                "most_active_sender": sender_counts.index[0] if not sender_counts.empty else None,
                "most_active_sender_percentage": (sender_counts.iloc[0] / len(df) * 100) if not sender_counts.empty else 0
            }
        
        return patterns
    
    def _assess_legal_relevance(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Assess metrics for legal relevance.
        Highlights patterns that may be significant for legal proceedings.
        """
        relevance = {
            "data_completeness": {
                "has_timestamps": 'timestamp' in df.columns,
                "has_sender_info": 'sender' in df.columns,
                "has_content": 'content' in df.columns,
                "missing_data_count": df.isnull().sum().sum()
            },
            "notable_patterns": []
        }
        
        # Check for significant patterns
        if 'timestamp' in df.columns and not df.empty:
            # Late night communications (between 11 PM and 5 AM)
            if 'hour' not in df.columns:
                df['hour'] = df['timestamp'].dt.hour
            
            late_night = df[(df['hour'] >= 23) | (df['hour'] < 5)]
            if len(late_night) > 0:
                relevance['notable_patterns'].append({
                    "pattern": "late_night_communication",
                    "count": len(late_night),
                    "percentage": len(late_night) / len(df) * 100
                })
            
            # Sudden changes in communication frequency
            if 'date' in df.columns:
                daily = df.groupby('date').size()
                if len(daily) > 7:  # Need at least a week of data
                    rolling_avg = daily.rolling(window=7, min_periods=1).mean()
                    spikes = daily[daily > rolling_avg * 2]
                    if len(spikes) > 0:
                        relevance['notable_patterns'].append({
                            "pattern": "communication_spikes",
                            "count": len(spikes),
                            "dates": [str(d) for d in spikes.index[:5]]  # First 5 spike dates
                        })
        
        # One-sided communication
        if 'sender' in df.columns:
            sender_counts = df['sender'].value_counts()
            if len(sender_counts) >= 2:
                ratio = sender_counts.iloc[0] / sender_counts.iloc[1] if sender_counts.iloc[1] > 0 else float('inf')
                if ratio > 3:  # One person sends 3x more messages
                    relevance['notable_patterns'].append({
                        "pattern": "one_sided_communication",
                        "dominant_sender": sender_counts.index[0],
                        "ratio": ratio
                    })
        
        return relevance
    
    def generate_metrics_report(self, metrics: Dict[str, Any], output_path: Optional[Path] = None) -> Path:
        """
        Generate a metrics report file.
        Creates a JSON report for use in legal proceedings (FRE 803(6) business records).
        
        Args:
            metrics: Metrics dictionary from analyze_messages
            output_path: Optional output path
            
        Returns:
            Path to the generated report
        """
        import json
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.forensic.output_dir / f"communication_metrics_{timestamp}.json"
        
        # Add metadata for legal compliance
        report = {
            "report_type": "Communication Metrics Analysis",
            "generated_at": datetime.now().isoformat(),
            "generator": "CommunicationMetricsAnalyzer v1.0",
            "legal_notice": (
                "This metrics report was generated from message data for legal analysis. "
                "All metrics are calculated objectively from available data. "
                "Statistical methods are reproducible and follow Daubert reliability standards."
            ),
            "metrics": metrics
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Record report generation
        self.forensic.record_action(
            "metrics_report_generated",
            f"Generated communication metrics report",
            {"output_path": str(output_path), "message_count": metrics.get('total_messages', 0)}
        )
        
        return output_path


# Alias for backward compatibility - THIS IS THE FIX!
CommunicationMetrics = CommunicationMetricsAnalyzer

__all__ = ['CommunicationMetricsAnalyzer', 'CommunicationMetrics']