"""Manual review module."""
from .manual_review_manager import ManualReviewManager

# WebReview requires Flask; import on demand to avoid hard dependency
# Usage: from src.review.web_review import WebReview

__all__ = ['ManualReviewManager']