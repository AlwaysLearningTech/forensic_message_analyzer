"""
Timeline generation module.
Creates visual timelines for court presentation.
"""

import logging
from pathlib import Path
from datetime import datetime
import pandas as pd

class TimelineGenerator:
    """Generate visual timelines from message data."""
    
    def __init__(self, forensic):
        """Initialize timeline generator."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
    
    def create_timeline(self, df: pd.DataFrame, output_path: Path):
        """
        Create HTML timeline visualization.
        
        Args:
            df: DataFrame with messages
            output_path: Where to save timeline
        """
        # Create HTML timeline
        html_content = self.generate_html_timeline(df)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        self.logger.info(f"Generated timeline: {output_path}")
        
        self.forensic.record_action(
            "TIMELINE_GENERATED",
            "visualization",
            f"Timeline created with {len(df)} events"
        )
    
    def generate_html_timeline(self, df: pd.DataFrame) -> str:
        """Generate HTML timeline content."""
        events = []
        
        # Build filter for significant events
        filter_mask = (df.get('threat_detected', pd.Series([False] * len(df))) == True) | \
                      (df.get('patterns_detected', pd.Series([''] * len(df))) != '')
        
        # Add sentiment filter only if column exists
        if 'sentiment_score' in df.columns:
            filter_mask = filter_mask | (df['sentiment_score'].abs() > 0.7)
        
        # Focus on significant events
        significant_df = df[filter_mask]
        
        for _, row in significant_df.iterrows():
            event = {
                'date': row['timestamp'],
                'content': row.get('content', '')[:100],
                'type': self.determine_event_type(row),
                'sender': row.get('sender', 'Unknown')
            }
            events.append(event)
        
        # Sort by date
        events.sort(key=lambda x: x['date'])
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Forensic Timeline</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .timeline {{ position: relative; padding: 20px 0; }}
                .event {{ margin: 20px 0; padding: 15px; border-left: 3px solid #007bff; }}
                .threat {{ border-color: #dc3545; background: #f8d7da; }}
                .pattern {{ border-color: #ffc107; background: #fff3cd; }}
                .sentiment {{ border-color: #17a2b8; background: #d1ecf1; }}
                .date {{ font-weight: bold; color: #666; }}
                .content {{ margin-top: 5px; }}
                .sender {{ font-style: italic; color: #999; }}
            </style>
        </head>
        <body>
            <h1>Forensic Analysis Timeline</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total significant events: {len(events)}</p>
            <div class="timeline">
        """
        
        for event in events:
            html += f"""
                <div class="event {event['type']}">
                    <div class="date">{event['date']}</div>
                    <div class="sender">From: {event['sender']}</div>
                    <div class="content">{event['content']}...</div>
                </div>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html
    
    def determine_event_type(self, row) -> str:
        """Determine CSS class for event type."""
        if row.get('threat_detected'):
            return 'threat'
        elif row.get('patterns_detected'):
            return 'pattern'
        elif abs(row.get('sentiment_score', 0)) > 0.7:
            return 'sentiment'
        return ''