import pandas as pd
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import logging
import hashlib

from .config import config
from .forensic_utils import ForensicIntegrity

class ManualReviewManager:
    """
    Manages manual review of flagged messages while preserving forensic integrity.
    Allows reuse of previous reviews when forensically sound.
    """
    
    def __init__(self, forensic_integrity: ForensicIntegrity):
        self.forensic = forensic_integrity
        self.review_file = config.backup_dir / 'manual_reviews.json'
        self.backup_file = config.backup_dir / 'manual_reviews_backup.json'
        self.reviews = self._load_existing_reviews()
        
    def _load_existing_reviews(self) -> Dict[str, Dict]:
        """
        Load existing manual reviews if available and valid.
        """
        if self.backup_file.exists():
            try:
                with open(self.backup_file, 'r') as f:
                    reviews = json.load(f)
                logging.info(f"Loaded {len(reviews)} existing manual reviews")
                return reviews
            except Exception as e:
                logging.warning(f"Could not load existing reviews: {e}")
        
        return {}
    
    def get_messages_for_review(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Get messages that require manual review.
        """
        # Flag messages for review based on multiple criteria
        review_criteria = (
            (df['requires_manual_review'] == True) |
            (df['harmful_content'] == True) |
            (df['threat_detected'] == True) |
            (df['sentiment'] == 'hostile') |
            (df['sentiment_score'] < config.sentiment_threshold_hostile)
        )
        
        messages_to_review = df[review_criteria].copy()
        
        # Check if we have existing reviews for these messages
        messages_to_review['has_existing_review'] = messages_to_review['unique_id'].apply(
            lambda x: x in self.reviews
        )
        
        # Apply existing reviews where available
        reviewed_count = 0
        for idx, row in messages_to_review.iterrows():
            if row['has_existing_review']:
                existing_review = self.reviews[row['unique_id']]
                
                # Verify message hasn't changed (forensic integrity)
                content_hash = hashlib.sha256(str(row['content']).encode()).hexdigest()
                if existing_review.get('content_hash') == content_hash:
                    # Apply existing review
                    df.at[idx, 'manual_review_decision'] = existing_review['decision']
                    df.at[idx, 'manual_review_notes'] = existing_review['notes']
                    df.at[idx, 'manual_review_timestamp'] = existing_review['timestamp']
                    df.at[idx, 'manual_review_applied'] = True
                    reviewed_count += 1
                else:
                    logging.warning(f"Content changed for message {row['unique_id']}, review invalidated")
        
        logging.info(f"Applied {reviewed_count} existing manual reviews")
        
        # Return messages still needing review
        still_needs_review = messages_to_review[~messages_to_review['has_existing_review']]
        return still_needs_review
    
    def save_review(self, message_id: str, content: str, decision: str, notes: str):
        """
        Save a manual review decision with forensic metadata.
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        review = {
            'message_id': message_id,
            'content_hash': content_hash,
            'decision': decision,  # 'harmful', 'not_harmful', 'unclear'
            'notes': notes,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'reviewer': 'Manual Review Process'
        }
        
        self.reviews[message_id] = review
        
        # Save to file
        self._save_reviews()
        
        # Log for forensic trail
        self.forensic.log_operation('Manual Review Saved', {
            'message_id': message_id,
            'decision': decision,
            'content_hash': content_hash[:16]
        })
    
    def _save_reviews(self):
        """
        Save reviews to file with backup.
        """
        # Create backup of existing file
        if self.review_file.exists():
            backup_path = self.review_file.with_suffix('.bak')
            self.review_file.rename(backup_path)
        
        # Save current reviews
        with open(self.review_file, 'w') as f:
            json.dump(self.reviews, f, indent=2)
        
        # Also save to backup location
        with open(self.backup_file, 'w') as f:
            json.dump(self.reviews, f, indent=2)
    
    def export_review_summary(self, output_path: Path):
        """
        Export summary of manual reviews for legal documentation.
        """
        summary = {
            'total_reviews': len(self.reviews),
            'decisions': {
                'harmful': sum(1 for r in self.reviews.values() if r['decision'] == 'harmful'),
                'not_harmful': sum(1 for r in self.reviews.values() if r['decision'] == 'not_harmful'),
                'unclear': sum(1 for r in self.reviews.values() if r['decision'] == 'unclear')
            },
            'review_dates': {
                'earliest': min((r['timestamp'] for r in self.reviews.values()), default='N/A'),
                'latest': max((r['timestamp'] for r in self.reviews.values()), default='N/A')
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Create human-readable version
        txt_path = output_path.with_suffix('.txt')
        with open(txt_path, 'w') as f:
            f.write("MANUAL REVIEW SUMMARY\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Total Reviews Completed: {summary['total_reviews']}\n\n")
            f.write("Decision Breakdown:\n")
            f.write(f"  Harmful: {summary['decisions']['harmful']}\n")
            f.write(f"  Not Harmful: {summary['decisions']['not_harmful']}\n")
            f.write(f"  Unclear: {summary['decisions']['unclear']}\n\n")
            f.write(f"Review Period: {summary['review_dates']['earliest']} to {summary['review_dates']['latest']}\n")
    
    def conduct_interactive_review(self, messages_df: pd.DataFrame) -> pd.DataFrame:
        """
        Conduct interactive manual review of flagged messages.
        """
        if messages_df.empty:
            logging.info("No messages require manual review")
            return messages_df
        
        print("\n" + "=" * 80)
        print("MANUAL REVIEW REQUIRED")
        print("=" * 80)
        print(f"\n{len(messages_df)} messages flagged for manual review\n")
        
        for idx, row in messages_df.iterrows():
            print("\n" + "-" * 60)
            print(f"Message ID: {row['unique_id']}")
            print(f"Timestamp: {row['timestamp']}")
            print(f"Sender: {row['sender']}")
            print(f"AI Assessment: Sentiment={row['sentiment']}, Harmful={row['harmful_content']}")
            print(f"\nContent:\n{row['content'][:500]}")
            
            if row.get('analysis_notes'):
                print(f"\nAI Notes: {row['analysis_notes']}")
            
            print("\n" + "-" * 60)
            print("Review Decision:")
            print("1. Harmful/Threatening")
            print("2. Not Harmful")
            print("3. Unclear/Needs Context")
            print("4. Skip (review later)")
            
            while True:
                choice = input("\nEnter decision (1-4): ").strip()
                
                if choice == '1':
                    decision = 'harmful'
                    break
                elif choice == '2':
                    decision = 'not_harmful'
                    break
                elif choice == '3':
                    decision = 'unclear'
                    break
                elif choice == '4':
                    print("Skipping message...")
                    decision = None
                    break
                else:
                    print("Invalid choice. Please enter 1-4.")
            
            if decision:
                notes = input("Add notes (optional): ").strip()
                self.save_review(row['unique_id'], row['content'], decision, notes)
                
                # Update DataFrame
                messages_df.at[idx, 'manual_review_decision'] = decision
                messages_df.at[idx, 'manual_review_notes'] = notes
                messages_df.at[idx, 'manual_review_timestamp'] = datetime.utcnow().isoformat()
                messages_df.at[idx, 'manual_review_applied'] = True
        
        print("\n" + "=" * 80)
        print("Manual review complete")
        print("=" * 80)
        
        return messages_df
