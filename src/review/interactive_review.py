#!/usr/bin/env python3
"""
Interactive manual review workflow.
Shows flagged messages in context and allows simple confirmation.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import pandas as pd
import pytz

from ..config import Config
from .manual_review_manager import ManualReviewManager

logger = logging.getLogger(__name__)


class InteractiveReview:
    """Interactive review process for flagged items."""

    def __init__(self, review_manager: ManualReviewManager, config: Config = None):
        """Initialize interactive review."""
        self.review_manager = review_manager
        self.config = config if config is not None else Config()
        self._tz = pytz.timezone(self.config.timezone)

    def _format_local_ts(self, ts) -> str:
        """Convert a UTC timestamp to local timezone string for display."""
        if ts is None or ts == 'N/A':
            return 'N/A'
        if isinstance(ts, str) and not ts.strip():
            return 'N/A'
        try:
            parsed = pd.to_datetime(ts, utc=True)
            if pd.isna(parsed):
                return str(ts)
            local_dt = parsed.to_pydatetime().astimezone(self._tz)
            return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        except Exception:
            return str(ts)
    
    def review_flagged_items(self, messages: List[Dict], flagged_items: List[Dict]) -> Dict:
        """
        Conduct interactive review of flagged items.
        
        Args:
            messages: All messages (for context)
            flagged_items: Items flagged for review
            
        Returns:
            dict: Review statistics
        """
        if not flagged_items:
            print("\n[*] No items flagged for review")
            return {'total': 0, 'confirmed': 0, 'rejected': 0}

        reviewer = (self.config.examiner_name or "").strip()
        if not reviewer:
            reviewer = input("Reviewer name (required for audit trail): ").strip()
            if not reviewer:
                print("\n[!] Reviewer name is required. Set EXAMINER_NAME in .env or enter at the prompt.")
                return {'total': 0, 'confirmed': 0, 'rejected': 0}
            self.config.examiner_name = reviewer

        print(f"\n{'='*80}")
        print(f" INTERACTIVE MANUAL REVIEW")
        print(f"{'='*80}")
        print(f"\nReviewer: {reviewer}")
        print(f"Total items flagged: {len(flagged_items)}")
        print(f"\nFor each flagged message, you'll see:")
        print(f"  - 5 messages BEFORE for context")
        print(f"  - The FLAGGED message (highlighted)")
        print(f"  - 5 messages AFTER for context")
        print(f"\nYou'll be asked to confirm: Is this truly concerning? (Y/N)")
        print(f"  Y = Confirm as concerning (flag for legal team)")
        print(f"  N = False positive (not actually concerning)")
        print(f"\nProgress is auto-saved after each decision.")
        print(f"{'='*80}\n")
        
        input("Press ENTER to begin review...")
        
        # Create message index for quick lookup by message_id
        msg_index = {msg.get('message_id'): i for i, msg in enumerate(messages)}

        stats = {'total': len(flagged_items), 'confirmed': 0, 'rejected': 0}

        for idx, item in enumerate(flagged_items, 1):
            print(f"\n{'='*80}")
            print(f"Item {idx} of {len(flagged_items)}")
            print(f"{'='*80}")

            # Find this message in context — try message_id index first
            item_content = item.get('content', '')
            item_msg_id = item.get('id') or item.get('message_id')
            msg_position = msg_index.get(item_msg_id) if item_msg_id else None

            # Fallback: exact content match
            if msg_position is None:
                for i, msg in enumerate(messages):
                    if msg.get('content', '') == item_content:
                        msg_position = i
                        break

            if msg_position is None and item_content:
                # Fallback: partial match (guard against empty prefix)
                prefix = item_content[:50]
                if prefix:
                    for i, msg in enumerate(messages):
                        if prefix in msg.get('content', ''):
                            msg_position = i
                            break

            if msg_position is None:
                logger.warning(f"Message not found for review item {item.get('id', idx)}")
                print(f"\n  [!] Could not locate message in context. Showing flagged content:")
                print(f"  Content: {item_content[:200]}")
                print(f"  Categories: {item.get('categories', 'N/A')}")
                print(f"  Confidence: {item.get('confidence', 'N/A')}")
            else:
                flagged_msg = messages[msg_position]

                # Show context (5 before, flagged, 5 after)
                context_start = max(0, msg_position - 5)
                context_end = min(len(messages), msg_position + 6)

                print(f"\nCONTEXT (showing messages {context_start+1} to {context_end}):\n")

                for i in range(context_start, context_end):
                    msg = messages[i]
                    is_flagged = (i == msg_position)

                    # Format message
                    timestamp = self._format_local_ts(msg.get('timestamp'))
                    sender = msg.get('sender', 'Unknown')
                    content = msg.get('content', '')[:100]  # Truncate long messages

                    if is_flagged:
                        print(f"\n{'*' * 80}")
                        print(f">>> FLAGGED MESSAGE <<<")
                        print(f"{'*' * 80}")
                        print(f"[{timestamp}] {sender}:")
                        print(f"  {content}")
                        if msg.get('attachment'):
                            print(f"  PHOTO: {msg['attachment']}")
                        print(f"\nThreat: {item.get('threat_type', 'N/A')}")
                        print(f"Confidence: {item.get('confidence', 'N/A')}")
                        print(f"{'*' * 80}\n")
                    else:
                        print(f"[{timestamp}] {sender}: {content}")
                        if msg.get('attachment'):
                            print(f"  PHOTO: {msg['attachment']}")

            # Get decision
            while True:
                decision_input = input(f"\nConfirm as concerning? (Y/N, or Q to quit): ").strip().upper()

                if decision_input == 'Q':
                    print("\n[*] Review stopped. Progress has been saved.")
                    return stats

                if decision_input in ['Y', 'N']:
                    break

                print("  Invalid input. Please enter Y, N, or Q.")

            # Record decision
            if decision_input == 'Y':
                decision = 'relevant'
                notes = f"Confirmed via interactive review on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                stats['confirmed'] += 1
                print("  ✓ Confirmed as concerning")
            else:
                decision = 'not_relevant'
                print("  Enter a short reason for rejecting this item (required):")
                reason = input("    > ").strip()
                while not reason:
                    print("  A reason is required for 'not relevant' decisions.")
                    reason = input("    > ").strip()
                notes = f"Rejected as false positive via interactive review on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. Reason: {reason}"
                stats['rejected'] += 1
                print("  ✗ Marked as false positive")

            # Save decision (auto-backup)
            try:
                self.review_manager.add_review(
                    item_id=item.get('id', f'item_{idx}'),
                    item_type='threat',
                    decision=decision,
                    notes=notes,
                    reviewer=reviewer,
                )
            except ValueError as exc:
                print(f"  [!] Could not record decision: {exc}")
                continue
        
        print(f"\n{'='*80}")
        print(f" REVIEW COMPLETE")
        print(f"{'='*80}")
        print(f"\nTotal reviewed: {stats['total']}")
        print(f"Confirmed as concerning: {stats['confirmed']}")
        print(f"Rejected as false positives: {stats['rejected']}")
        print(f"\nAll decisions have been saved.")
        print(f"{'='*80}\n")
        
        return stats
    
    def review_specific_item(self, messages: List[Dict], msg_id: str) -> Optional[str]:
        """
        Review a specific message interactively.
        
        Args:
            messages: All messages
            msg_id: Message ID to review
            
        Returns:
            str: Decision ('relevant', 'not_relevant', or None if skipped)
        """
        # Create message index
        msg_index = {msg.get('message_id'): i for i, msg in enumerate(messages)}
        
        if msg_id not in msg_index:
            logger.error(f"Message {msg_id} not found")
            return None
        
        msg_position = msg_index[msg_id]
        flagged_msg = messages[msg_position]
        
        # Show context
        context_start = max(0, msg_position - 5)
        context_end = min(len(messages), msg_position + 6)
        
        print(f"\nCONTEXT:\n")
        
        for i in range(context_start, context_end):
            msg = messages[i]
            is_flagged = (i == msg_position)
            
            timestamp = self._format_local_ts(msg.get('timestamp'))
            sender = msg.get('sender', 'Unknown')
            content = msg.get('content', '')[:100]
            
            if is_flagged:
                print(f"\n>>> FLAGGED <<<")
                print(f"[{timestamp}] {sender}: {content}")
                if msg.get('attachment'):
                    print(f"  PHOTO: {msg['attachment']}")
                print(f">>> END FLAGGED <<<\n")
            else:
                print(f"[{timestamp}] {sender}: {content}")
                if msg.get('attachment'):
                    print(f"  PHOTO: {msg['attachment']}")
        
        # Get decision
        decision_input = input(f"\nFlag for legal review? (Y/N): ").strip().upper()
        
        if decision_input == 'Y':
            return 'relevant'
        elif decision_input == 'N':
            return 'not_relevant'
        else:
            return None
