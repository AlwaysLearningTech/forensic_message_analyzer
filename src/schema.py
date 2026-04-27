"""Shared TypedDict definitions for the core data shapes.

These types document the contract between extractors, analyzers, review, and reporters. They are NotRequired-heavy on purpose: extractors may populate a subset of fields depending on the source (iMessage rows carry edit history; WhatsApp rows don't). Treat these as documentation + type-checker hints; runtime code should keep using dict.get() with sensible defaults rather than relying on presence.

Added in one place so downstream changes (new extractor fields, new finding sources) have a visible schema to update.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Literal, Optional

if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict
else:  # pragma: no cover - compat shim for older interpreters
    from typing_extensions import NotRequired, TypedDict


# Literal finding sources. Stamped on every review item so reports and reviewers can distinguish deterministic pattern matches from AI-screened flags and raw extracted content.
FindingSource = Literal[
    "pattern_matched",  # deterministic YAML/regex (threat_analyzer, yaml_pattern_analyzer, behavioral_analyzer)
    "ai_screened",      # Anthropic Claude batch API
    "extracted",        # raw message/email surfaced for review (e.g. all emails)
    "derived",          # computed from other findings (escalation timelines, etc.)
    "unknown",
]

ReviewDecision = Literal["relevant", "not_relevant", "uncertain"]


class Message(TypedDict, total=False):
    """A single extracted message after normalization.

    Extractors produce a list of these; the analyzers (DataFrame-based) and reviewers (list-of-dict-based) both operate on this shape. Fields marked NotRequired are populated by specific sources; a WhatsApp message won't have edit_history, an iMessage row won't have a subject line.
    """

    message_id: str
    timestamp: str                 # ISO 8601 UTC
    sender: str                    # mapped display name or raw identifier
    recipient: str
    content: str
    source: str                    # 'imessage' | 'whatsapp' | 'email' | 'teams' | 'screenshot' | 'sms' | 'call' | ...
    sender_raw: NotRequired[Optional[str]]    # raw protocol identifier (phone, email, handle) for sender; None for PERSON1
    recipient_raw: NotRequired[Optional[str]] # raw protocol identifier for recipient; None for PERSON1

    # Optional fields populated by one or more extractors
    attachment: NotRequired[str]
    attachment_name: NotRequired[str]
    subject: NotRequired[str]
    is_from_me: NotRequired[bool]
    is_tapback: NotRequired[bool]
    is_recently_deleted: NotRequired[bool]
    date_edited: NotRequired[str]
    date_retracted: NotRequired[str]
    edit_history: NotRequired[List[Dict[str, Any]]]
    was_downgraded: NotRequired[bool]
    is_sos: NotRequired[bool]
    is_shared_location: NotRequired[bool]
    location_name: NotRequired[str]
    location_address: NotRequired[str]
    rich_link_title: NotRequired[str]
    rich_link_site_name: NotRequired[str]
    rich_link_url: NotRequired[str]
    thread_originator_guid: NotRequired[str]
    reactions: NotRequired[str]
    file: NotRequired[str]


class Finding(TypedDict, total=False):
    """A single review candidate. Constructed in main.run_review_phase and passed to the review UI."""

    id: str
    type: str                      # 'threat' | 'ai_threat' | 'ai_coercive_control' | 'email' | 'third_party_email' | 'user_flagged'
    source: FindingSource
    method: NotRequired[str]       # 'yaml_patterns' | 'claude-haiku-4-5' | 'email_import' | ...
    content: str
    categories: NotRequired[str]
    confidence: NotRequired[float]
    message_id: NotRequired[str]
    severity: NotRequired[str]
    threat_type: NotRequired[str]
    rcw_relevance: NotRequired[str]
    subject: NotRequired[str]


class ReviewRecord(TypedDict, total=False):
    """One row in the manual review log — the audit trail that reports render and opposing counsel will want to inspect."""

    item_id: str
    item_type: str
    source: FindingSource
    method: str
    decision: ReviewDecision
    notes: str
    timestamp: str
    reviewer: str
    session_id: str
    amended: bool
    supersedes: Optional[str]
    superseded_by: NotRequired[str]


class ThreatDetails(TypedDict, total=False):
    """Per-message output of ThreatAnalyzer.detect_threats."""

    message_id: str
    content: str
    sender: str
    recipient: str
    threat_detected: bool
    threat_confidence: float
    threat_categories: str  # comma-joined category names


class SentimentDetails(TypedDict, total=False):
    """Per-message output of SentimentAnalyzer.analyze_sentiment."""

    message_id: str
    sentiment_score: float
    sentiment_polarity: float
    sentiment_subjectivity: float


class AnalysisResults(TypedDict, total=False):
    """The dict ForensicAnalyzer.run_analysis_phase returns; consumed by reporters."""

    threats: Dict[str, Any]         # {'details': List[ThreatDetails], 'summary': {...}}
    sentiment: Dict[str, Any]
    behavioral: Dict[str, Any]
    yaml_patterns: Dict[str, Any]
    communication_metrics: Dict[str, Any]
    screenshots: Dict[str, Any]
    attachments: Dict[str, Any]
    ai_analysis: Dict[str, Any]


__all__ = [
    "FindingSource",
    "ReviewDecision",
    "Message",
    "Finding",
    "ReviewRecord",
    "ThreatDetails",
    "SentimentDetails",
    "AnalysisResults",
]
