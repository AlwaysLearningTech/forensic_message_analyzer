"""
Manual review manager for handling manual review decisions.

This module provides the `ManualReviewManager` class, which is responsible
for managing the manual review process of messages flagged by the system.
It handles the loading, saving, and tracking of manual review decisions,
as well as the interaction with the forensic recording system.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
from ..forensic_utils import ForensicRecorder
from ..config import Config


class ManualReviewManager:
    """
    Manages manual review decisions for flagged messages.

    This class handles the persistence and retrieval of manual review decisions
    made by analysts on messages flagged by the automated analysis system.
    """

    def __init__(self, review_dir: Optional[Path] = None, session_id: Optional[str] = None,
                 config: Config = None, forensic_recorder: ForensicRecorder = None):
        """
        Initialize the ManualReviewManager.

        Args:
            review_dir: Directory for storing review decisions.
                       Defaults to config.review_dir if not provided.
            session_id: Optional session ID to resume a previous session.
                       If provided, loads existing reviews from that session.
            config: Configuration instance. If None, creates a new one.
            forensic_recorder: Optional ForensicRecorder to share with the pipeline.
                              If None, creates a new one.
        """
        self._config = config if config is not None else Config()
        self.review_dir = review_dir or Path(self._config.review_dir)
        self.review_dir.mkdir(parents=True, exist_ok=True)
        self.forensic = forensic_recorder if forensic_recorder is not None else ForensicRecorder()

        if session_id:
            self.session_id = session_id
            self.reviews = self.load_reviews(session_id)
        else:
            self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.reviews = []

        # Record initialization
        resumed = f" (resumed {len(self.reviews)} reviews)" if session_id else ""
        self.forensic.record_action(
            "manual_review_initialized",
            f"Manual review manager initialized with session {self.session_id}{resumed}",
            {"review_dir": str(self.review_dir), "resumed": bool(session_id), "loaded_reviews": len(self.reviews)}
        )
    
    # Decisions whose forensic weight demands a written justification. A reviewer who marks an item not_relevant or uncertain must explain why, because that decision is what keeps the item OUT of the final report; opposing counsel will want to see the reasoning.
    _DECISIONS_REQUIRING_NOTES = frozenset({"not_relevant", "uncertain"})
    _VALID_DECISIONS = frozenset({"relevant", "not_relevant", "uncertain"})

    def add_review(self, item_id: str, item_type: str, decision: str, notes: str = "", reviewer: Optional[str] = None, source: str = "unknown", method: str = ""):
        """
        Add a manual review decision.

        Args:
            item_id: Unique identifier for the reviewed item.
            item_type: Type of item (e.g., 'threat', 'pattern', 'behavioral').
            decision: Review decision ('relevant', 'not_relevant', 'uncertain').
            notes: Notes about the decision. Required when decision is not_relevant or uncertain.
            reviewer: Name/identifier of the reviewer. When None, falls back to config.examiner_name. An empty or missing name is rejected — decisions must be attributed to a named person.

        Raises:
            ValueError: if decision is unknown, notes missing on a rejection/uncertain, reviewer not identified, or the item_id has already been reviewed in this session (use amend_review to change a prior decision).
        """
        if decision not in self._VALID_DECISIONS:
            raise ValueError(f"Invalid decision {decision!r}; expected one of {sorted(self._VALID_DECISIONS)}")

        if decision in self._DECISIONS_REQUIRING_NOTES and not (notes or "").strip():
            raise ValueError(f"A {decision!r} decision requires explanatory notes for defensibility")

        reviewer = (reviewer or getattr(self._config, "examiner_name", "") or "").strip()
        if not reviewer:
            raise ValueError("Reviewer identity is required; set EXAMINER_NAME in .env or pass reviewer=...")

        # Reject duplicate decisions on the same item. Use amend_review() to modify an earlier decision — that path writes a new record rather than overwriting, preserving audit history.
        if item_id in self.reviewed_item_ids:
            raise ValueError(f"Item {item_id!r} already reviewed in this session; use amend_review() to change it")

        review = {
            "item_id": item_id,
            "item_type": item_type,
            "source": source,
            "method": method,
            "decision": decision,
            "notes": notes,
            "timestamp": datetime.now().isoformat(),
            "reviewer": reviewer,
            "session_id": self.session_id,
            "amended": False,
            "supersedes": None,
        }

        self.reviews.append(review)

        # Record the review action
        self.forensic.record_action(
            "manual_review_added",
            f"Manual review added for {item_type} item {item_id} by {reviewer}",
            {
                "item_id": item_id,
                "decision": decision,
                "source": source,
                "has_notes": bool(notes),
                "reviewer": reviewer,
            }
        )

        # Auto-save after each review
        self._save_reviews()

    def amend_review(self, item_id: str, decision: str, notes: str, reviewer: Optional[str] = None):
        """Amend a prior review decision with a new, fully-attributed record.

        Prior decisions are never mutated: this appends a new record that supersedes the previous one, with 'amended=True' and 'supersedes' pointing back. Notes are always required on an amendment — the reviewer must explain why they changed their mind.
        """
        if decision not in self._VALID_DECISIONS:
            raise ValueError(f"Invalid decision {decision!r}")
        if not (notes or "").strip():
            raise ValueError("Amendments require notes explaining the change")
        reviewer = (reviewer or getattr(self._config, "examiner_name", "") or "").strip()
        if not reviewer:
            raise ValueError("Reviewer identity is required to amend a review")

        prior = None
        for r in reversed(self.reviews):
            if r.get("item_id") == item_id and not r.get("superseded_by"):
                prior = r
                break
        if prior is None:
            raise ValueError(f"No prior review found for item {item_id!r}")

        prior["superseded_by"] = datetime.now().isoformat()

        review = {
            "item_id": item_id,
            "item_type": prior.get("item_type"),
            "decision": decision,
            "notes": notes,
            "timestamp": datetime.now().isoformat(),
            "reviewer": reviewer,
            "session_id": self.session_id,
            "amended": True,
            "supersedes": prior.get("timestamp"),
        }
        self.reviews.append(review)
        self.forensic.record_action(
            "manual_review_amended",
            f"Amended review for {item_id}: {prior.get('decision')} -> {decision} by {reviewer}",
            {"item_id": item_id, "from": prior.get("decision"), "to": decision, "reviewer": reviewer},
        )
        self._save_reviews()
    
    @property
    def reviewed_item_ids(self) -> set:
        """Return set of item_ids whose most recent decision is still active (not superseded)."""
        return {r['item_id'] for r in self.reviews if not r.get('superseded_by')}

    def get_reviews_by_decision(self, decision: str) -> List[Dict]:
        """
        Get all reviews with a specific decision.
        
        Args:
            decision: The decision to filter by ('relevant', 'not_relevant', 'uncertain')
            
        Returns:
            List of review dictionaries matching the decision
        """
        return [r for r in self.reviews if r['decision'] == decision]
    
    def get_reviews_by_type(self, item_type: str) -> List[Dict]:
        """
        Get all reviews for a specific item type.
        
        Args:
            item_type: The type to filter by (e.g., 'threat', 'pattern')
            
        Returns:
            List of review dictionaries matching the item type
        """
        return [r for r in self.reviews if r['item_type'] == item_type]
    
    def get_review_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all review decisions.
        
        Returns:
            Dictionary with review statistics and breakdowns
        """
        total = len(self.reviews)
        
        # Count by decision
        decisions = {
            'relevant': len(self.get_reviews_by_decision('relevant')),
            'not_relevant': len(self.get_reviews_by_decision('not_relevant')),
            'uncertain': len(self.get_reviews_by_decision('uncertain'))
        }
        
        # Count by type
        types = {}
        for review in self.reviews:
            item_type = review['item_type']
            types[item_type] = types.get(item_type, 0) + 1
        
        return {
            'total_reviews': total,
            'decisions': decisions,
            'types': types,
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat()
        }
    
    def _save_reviews(self):
        """
        Save current reviews to a JSON file.
        """
        output_file = self.review_dir / f"reviews_{self.session_id}.json"
        
        data = {
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat(),
            'reviews': self.reviews,
            'summary': self.get_review_summary()
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Compute hash for integrity
        file_hash = self._compute_hash(output_file)
        
        self.forensic.record_action(
            "reviews_saved",
            f"Saved {len(self.reviews)} reviews to {output_file.name}",
            {"file": str(output_file), "hash": file_hash}
        )
    
    def load_reviews(self, session_id: str) -> List[Dict]:
        """
        Load reviews from a previous session.
        
        Args:
            session_id: The session ID to load
            
        Returns:
            List of review dictionaries from that session
        """
        input_file = self.review_dir / f"reviews_{session_id}.json"
        
        if not input_file.exists():
            self.forensic.record_action(
                "reviews_not_found",
                f"No reviews found for session {session_id}",
                {"file": str(input_file)}
            )
            return []
        
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        reviews = data.get('reviews', [])
        
        self.forensic.record_action(
            "reviews_loaded",
            f"Loaded {len(reviews)} reviews from session {session_id}",
            {"file": str(input_file), "count": len(reviews)}
        )
        
        return reviews
    
    def _compute_hash(self, file_path: Path) -> str:
        """
        Compute SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Hexadecimal hash string
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def export_for_report(self) -> Dict[str, Any]:
        """
        Export review data formatted for reporting.
        
        Returns:
            Dictionary with review data formatted for reports
        """
        summary = self.get_review_summary()
        
        # Group reviews by decision and type for easier reporting
        relevant_items = []
        not_relevant_items = []
        uncertain_items = []
        
        for review in self.reviews:
            item = {
                'id': review['item_id'],
                'type': review['item_type'],
                'notes': review['notes'],
                'timestamp': review['timestamp']
            }
            
            if review['decision'] == 'relevant':
                relevant_items.append(item)
            elif review['decision'] == 'not_relevant':
                not_relevant_items.append(item)
            else:
                uncertain_items.append(item)
        
        return {
            'summary': summary,
            'relevant_items': relevant_items,
            'not_relevant_items': not_relevant_items,
            'uncertain_items': uncertain_items,
            'all_reviews': self.reviews
        }