"""
Sentiment analysis module.
Analyzes emotional tone of messages.
"""

import logging
import pandas as pd
from typing import Dict, Any
from textblob import TextBlob
import re

class SentimentAnalyzer:
    """Analyze sentiment in messages."""
    
    def __init__(self, forensic):
        """Initialize sentiment analyzer."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        
        self.forensic.record_action(
            "SENTIMENT_ANALYZER_INIT",
            "Initialized sentiment analyzer"
        )
    
    def analyze_sentiment(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Analyze sentiment for all messages.
        
        Args:
            df: DataFrame with messages
            
        Returns:
            DataFrame with sentiment scores added
        """
        df['sentiment_score'] = 0.0
        df['sentiment_polarity'] = ''
        df['sentiment_subjectivity'] = 0.0
        
        for idx, row in df.iterrows():
            if pd.isna(row.get('content')):
                continue
            
            text = str(row['content'])
            
            # Clean text for analysis
            text_cleaned = self._clean_text(text)
            
            try:
                # Analyze with TextBlob
                blob = TextBlob(text_cleaned)
                
                # Get sentiment scores
                polarity = blob.sentiment.polarity  # -1 to 1
                subjectivity = blob.sentiment.subjectivity  # 0 to 1
                
                # Store results
                df.at[idx, 'sentiment_score'] = polarity
                df.at[idx, 'sentiment_subjectivity'] = subjectivity
                
                # Categorize polarity
                if polarity > 0.1:
                    df.at[idx, 'sentiment_polarity'] = 'positive'
                elif polarity < -0.1:
                    df.at[idx, 'sentiment_polarity'] = 'negative'
                else:
                    df.at[idx, 'sentiment_polarity'] = 'neutral'
                    
            except Exception as e:
                self.logger.error(f"Failed to analyze sentiment for message {idx}: {e}")
        
        # Log summary
        positive_count = (df['sentiment_polarity'] == 'positive').sum()
        negative_count = (df['sentiment_polarity'] == 'negative').sum()
        neutral_count = (df['sentiment_polarity'] == 'neutral').sum()
        
        self.logger.info(f"Sentiment analysis complete: {positive_count} positive, {negative_count} negative, {neutral_count} neutral")
        
        self.forensic.record_action(
            "SENTIMENT_ANALYSIS_COMPLETE",
            f"Analyzed {len(df)} messages: {positive_count} pos, {negative_count} neg, {neutral_count} neutral"
        )
        
        return df
    
    def _clean_text(self, text: str) -> str:
        """Clean text for sentiment analysis."""
        # Remove URLs
        text = re.sub(r'http\S+|www.\S+', '', text)
        
        # Remove excessive punctuation
        text = re.sub(r'[!?]{2,}', '!', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    def generate_sentiment_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate sentiment analysis summary."""
        if 'sentiment_score' not in df.columns:
            return {}
        
        summary = {
            'average_sentiment': df['sentiment_score'].mean(),
            'sentiment_std': df['sentiment_score'].std(),
            'most_positive': {
                'score': df['sentiment_score'].max(),
                'message': df.loc[df['sentiment_score'].idxmax(), 'content'][:100] if len(df) > 0 else ''
            },
            'most_negative': {
                'score': df['sentiment_score'].min(),
                'message': df.loc[df['sentiment_score'].idxmin(), 'content'][:100] if len(df) > 0 else ''
            },
            'polarity_distribution': {
                'positive': (df['sentiment_polarity'] == 'positive').sum(),
                'negative': (df['sentiment_polarity'] == 'negative').sum(),
                'neutral': (df['sentiment_polarity'] == 'neutral').sum()
            },
            'average_subjectivity': df['sentiment_subjectivity'].mean()
        }
        
        # Sentiment over time
        if 'timestamp' in df.columns:
            df_sorted = df.sort_values('timestamp')
            # Split into quarters
            quarter_size = len(df_sorted) // 4
            if quarter_size > 0:
                summary['sentiment_by_quarter'] = {
                    'Q1': df_sorted.iloc[:quarter_size]['sentiment_score'].mean(),
                    'Q2': df_sorted.iloc[quarter_size:2*quarter_size]['sentiment_score'].mean(),
                    'Q3': df_sorted.iloc[2*quarter_size:3*quarter_size]['sentiment_score'].mean(),
                    'Q4': df_sorted.iloc[3*quarter_size:]['sentiment_score'].mean()
                }
        
        return summary
