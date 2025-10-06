"""
Manual review management system.
Handles queuing and tracking of manual review decisions.
"""

import json
import logging
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
import pandas as pd

class ManualReviewManager:
    """Manages manual review of flagged messages."""
    
    def __init__(self, forensic):
        """Initialize review manager with forensic tracking."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        self.reviews = {}
        self.review_file = Path("output/manual_reviews.json")
        self.review_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing reviews if available
        self.load_reviews()
        
        self.forensic.record_action(
            "REVIEW_MANAGER_INIT",
            "manual_review",
            f"Initialized with {len(self.reviews)} existing reviews"
        )
    
    def load_reviews(self):
        """Load existing review decisions from file."""
        if self.review_file.exists():
            try:
                with open(self.review_file, 'r') as f:
                    self.reviews = json.load(f)
                self.logger.info(f"Loaded {len(self.reviews)} existing reviews")
            except Exception as e:
                self.logger.error(f"Failed to load reviews: {e}")
                self.reviews = {}
    
    def save_reviews(self):
        """Save review decisions to file."""
        try:
            with open(self.review_file, 'w') as f:
                json.dump(self.reviews, f, indent=2, default=str)
            self.logger.info(f"Saved {len(self.reviews)} reviews")
            
            self.forensic.record_action(
                "REVIEWS_SAVED",
                "manual_review",
                f"Persisted {len(self.reviews)} review decisions"
            )
        except Exception as e:
            self.logger.error(f"Failed to save reviews: {e}")
    
    def get_messages_for_review(self, df: pd.DataFrame, threshold: float = 0.5) -> List[Dict[str, Any]]:
        """
        Select messages that need manual review.
        
        Args:
            df: DataFrame with analyzed messages
            threshold: Confidence threshold for automatic inclusion
            
        Returns:
            List of messages requiring review
        """
        messages_to_review = []
        
        for idx, row in df.iterrows():
            # Skip if already reviewed
            msg_id = row.get('message_id')
            if msg_id and str(msg_id) in self.reviews:
                continue
            
            # Check if message needs review
            needs_review = False
            
            # Threat detected but low confidence
            if row.get('threat_detected') and row.get('threat_confidence', 0) < threshold:
                needs_review = True
            
            # High sentiment score
            if abs(row.get('sentiment_score', 0)) > 0.8:
                needs_review = True
            
            # Harmful content flagged
            if row.get('harmful_content'):
                needs_review = True
            
            if needs_review:
                messages_to_review.append({
                    'message_id': msg_id,
                    'content': row.get('content'),
                    'timestamp': row.get('timestamp'),
                    'sender': row.get('sender'),
                    'threat_categories': row.get('threat_categories'),
                    'sentiment_score': row.get('sentiment_score'),
                    'threat_confidence': row.get('threat_confidence')
                })
        
        self.logger.info(f"Identified {len(messages_to_review)} messages for review")
        
        self.forensic.record_action(
            "REVIEW_QUEUE_CREATED",
            "manual_review",
            f"Queued {len(messages_to_review)} messages for manual review"
        )
        
        return messages_to_review
    
    def conduct_interactive_review(self, messages: List[Dict[str, Any]]):
        """
        Conduct interactive review session.
        
        Args:
            messages: List of messages to review
        """
        print("\n" + "="*60)
        print("MANUAL REVIEW SESSION")
        print("="*60)
        print(f"Messages to review: {len(messages)}")
        print("Commands: [y]es to include, [n]o to exclude, [s]kip, [q]uit")
        print("="*60 + "\n")
        
        for i, msg in enumerate(messages, 1):
            print(f"\n[{i}/{len(messages)}] Message ID: {msg['message_id']}")
            print(f"Timestamp: {msg['timestamp']}")
            print(f"Sender: {msg.get('sender', 'Unknown')}")
            print(f"Content: {msg['content'][:200]}...")
            
            if msg.get('threat_categories'):
                print(f"Threats Detected: {msg['threat_categories']}")
            if msg.get('sentiment_score'):
                print(f"Sentiment Score: {msg['sentiment_score']:.2f}")
            
            while True:
                decision = input("\nDecision [y/n/s/q]: ").lower().strip()
                
                if decision == 'y':
                    self.record_review_decision(msg['message_id'], 'include')
                    print("✓ Marked for inclusion")
                    break
                elif decision == 'n':
                    notes = input("Reason for exclusion (optional): ").strip()
                    self.record_review_decision(msg['message_id'], 'exclude', notes)
                    print("✗ Marked for exclusion")
                    break
                elif decision == 's':
                    print("⊘ Skipped")
                    break
                elif decision == 'q':
                    self.save_reviews()
                    print("\nReview session saved and ended.")
                    return
                else:
                    print("Invalid input. Please use y/n/s/q")
        
        self.save_reviews()
        print("\n" + "="*60)
        print("REVIEW SESSION COMPLETE")
        print(f"Total reviews saved: {len(self.reviews)}")
        print("="*60)
    
    def record_review_decision(self, message_id: str, decision: str, notes: str = ""):
        """
        Record a manual review decision.
        
        Args:
            message_id: Unique message identifier
            decision: Review decision (include/exclude)
            notes: Optional reviewer notes
        """
        self.reviews[str(message_id)] = {
            'decision': decision,
            'notes': notes,
            'reviewed_at': datetime.now().isoformat(),
            'reviewer': 'forensic_analyst'
        }
        
        self.forensic.record_action(
            "REVIEW_DECISION_RECORDED",
            "manual_review",
            f"Message {message_id}: {decision}"
        )
    
    def apply_reviews_to_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply review decisions to DataFrame.
        
        Args:
            df: DataFrame with messages
            
        Returns:
            DataFrame with review decisions applied
        """
        df['manual_review'] = ''
        df['include_as_evidence'] = None
        
        for idx, row in df.iterrows():
            msg_id = str(row.get('message_id'))
            if msg_id in self.reviews:
                review = self.reviews[msg_id]
                df.at[idx, 'manual_review'] = review['decision']
                df.at[idx, 'include_as_evidence'] = (review['decision'] == 'include')
        
        reviewed_count = df['manual_review'].notna().sum()
        self.logger.info(f"Applied {reviewed_count} review decisions to DataFrame")
        
        return df
    
    def export_review_summary(self, filepath: Path):
        """Export summary of review decisions."""
        summary = {
            'total_reviews': len(self.reviews),
            'included': sum(1 for r in self.reviews.values() if r['decision'] == 'include'),
            'excluded': sum(1 for r in self.reviews.values() if r['decision'] == 'exclude'),
            'review_date': datetime.now().isoformat(),
            'reviews': self.reviews
        }
        
        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        self.logger.info(f"Exported review summary to {filepath}")