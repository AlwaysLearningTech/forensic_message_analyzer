"""Examiner-authored events spanning message ranges.

The automated events timeline surfaces pattern-matched and AI-screened findings one message at a time. Real incidents — the fight that starts on Friday night and trails into Sunday morning — don't live in a single message. This module lets the examiner name those incidents, bracket them to a start/end message range, and attach them to the timeline alongside the auto-detected events.

Persistence mirrors ManualReviewManager and RedactionManager: append-only JSONL-ish semantics where edits and removals write new records rather than mutating prior ones. The audit trail is preserved for opposing counsel.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Config
from ..forensic_utils import ForensicRecorder

logger = logging.getLogger(__name__)


_VALID_CATEGORIES = frozenset({
    "incident",       # a fight / argument / confrontation
    "threat",         # escalated exchange the examiner is calling a threat
    "escalation",     # tone deteriorates
    "de_escalation",  # tone improves, apology, counselor-mediated reset
    "pattern",        # a clustered pattern the examiner is naming as one event
    "milestone",      # factual turning point (court date, move-out, filing)
})

_VALID_SEVERITIES = frozenset({"high", "medium", "low", "info"})


class EventManager:
    """Track manual events that span message ranges, with append-only audit trail."""

    def __init__(
        self,
        review_dir: Optional[Path] = None,
        session_id: Optional[str] = None,
        config: Optional[Config] = None,
        forensic_recorder: Optional[ForensicRecorder] = None,
    ):
        self._config = config if config is not None else Config()
        self.review_dir = Path(review_dir) if review_dir else Path(self._config.review_dir)
        self.review_dir.mkdir(parents=True, exist_ok=True)
        self.forensic = forensic_recorder if forensic_recorder is not None else ForensicRecorder()

        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self._records: List[Dict[str, Any]] = self._load()

    # --- persistence ---------------------------------------------------

    def _file(self) -> Path:
        return self.review_dir / f"manual_events_{self.session_id}.json"

    def _load(self) -> List[Dict[str, Any]]:
        path = self._file()
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text()).get("events", [])
        except Exception:
            return []

    def _save(self):
        path = self._file()
        payload = {
            "session_id": self.session_id,
            "updated_at": datetime.now().isoformat(),
            "events": self._records,
        }
        path.write_text(json.dumps(payload, indent=2, default=str))

    # --- lookups -------------------------------------------------------

    def active_events(self) -> List[Dict[str, Any]]:
        """Return the current state of each event_id — the most recent non-removed record."""
        latest: Dict[str, Dict[str, Any]] = {}
        for record in self._records:
            eid = record.get("event_id")
            if not eid:
                continue
            if record.get("removed_at"):
                latest.pop(eid, None)
            else:
                latest[eid] = record
        return [v for v in latest.values() if not v.get("superseded_by")]

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        for record in reversed(self._records):
            if record.get("event_id") == event_id and not record.get("superseded_by") and not record.get("removed_at"):
                return record
        return None

    def all_records(self) -> List[Dict[str, Any]]:
        """Full append-only history, including superseded and removed entries."""
        return list(self._records)

    # --- mutations -----------------------------------------------------

    def add_event(
        self,
        *,
        title: str,
        start_message_id: str,
        end_message_id: str,
        category: str = "incident",
        severity: str = "medium",
        description: str = "",
        start_timestamp: Optional[str] = None,
        end_timestamp: Optional[str] = None,
        examiner: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new manual event spanning two message_ids."""
        self._require_category_severity(category, severity)
        title = (title or "").strip()
        if not title:
            raise ValueError("Event title is required")
        if not start_message_id or not end_message_id:
            raise ValueError("start_message_id and end_message_id are both required")
        examiner = self._require_examiner(examiner)

        record = {
            "event_id": f"evt_{uuid.uuid4().hex[:10]}",
            "title": title,
            "category": category,
            "severity": severity,
            "description": (description or "").strip(),
            "start_message_id": start_message_id,
            "end_message_id": end_message_id,
            "start_timestamp": start_timestamp,
            "end_timestamp": end_timestamp,
            "examiner": examiner,
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "amended": False,
            "supersedes": None,
            "superseded_by": None,
            "removed_at": None,
        }
        self._records.append(record)
        self._save()
        self.forensic.record_action(
            "manual_event_added",
            f"Manual event {record['event_id']} added by {examiner}: {title}",
            {"event_id": record["event_id"], "title": title, "category": category, "examiner": examiner},
        )
        return record

    def edit_event(
        self,
        event_id: str,
        *,
        title: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        description: Optional[str] = None,
        start_message_id: Optional[str] = None,
        end_message_id: Optional[str] = None,
        start_timestamp: Optional[str] = None,
        end_timestamp: Optional[str] = None,
        reason: str = "",
        examiner: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append a new record that supersedes the prior one; the prior record keeps ``superseded_by`` set.

        At least one field must be provided; a non-empty ``reason`` is required so the audit trail shows why the event was edited.
        """
        prior = self.get_event(event_id)
        if prior is None:
            raise ValueError(f"No active event found for {event_id!r}")
        if not (reason or "").strip():
            raise ValueError("Editing an event requires a reason (opposing counsel will ask)")
        examiner = self._require_examiner(examiner)

        new_category = category if category is not None else prior["category"]
        new_severity = severity if severity is not None else prior["severity"]
        self._require_category_severity(new_category, new_severity)

        now = datetime.now().isoformat()
        prior["superseded_by"] = now

        record = dict(prior)
        record.update({
            "title": (title if title is not None else prior["title"]).strip() or prior["title"],
            "category": new_category,
            "severity": new_severity,
            "description": description if description is not None else prior["description"],
            "start_message_id": start_message_id or prior["start_message_id"],
            "end_message_id": end_message_id or prior["end_message_id"],
            "start_timestamp": start_timestamp if start_timestamp is not None else prior.get("start_timestamp"),
            "end_timestamp": end_timestamp if end_timestamp is not None else prior.get("end_timestamp"),
            "examiner": examiner,
            "timestamp": now,
            "amended": True,
            "supersedes": prior.get("timestamp"),
            "superseded_by": None,
            "removed_at": None,
            "edit_reason": reason,
        })
        self._records.append(record)
        self._save()
        self.forensic.record_action(
            "manual_event_edited",
            f"Event {event_id} edited by {examiner}: {reason}",
            {"event_id": event_id, "examiner": examiner, "reason": reason},
        )
        return record

    def remove_event(self, event_id: str, reason: str, examiner: Optional[str] = None) -> None:
        """Append a removal record. The prior record keeps its state; the examiner's reason is required."""
        prior = self.get_event(event_id)
        if prior is None:
            raise ValueError(f"No active event found for {event_id!r}")
        if not (reason or "").strip():
            raise ValueError("Removing an event requires a reason")
        examiner = self._require_examiner(examiner)

        now = datetime.now().isoformat()
        removal = dict(prior)
        removal.update({
            "timestamp": now,
            "examiner": examiner,
            "amended": False,
            "supersedes": prior.get("timestamp"),
            "superseded_by": None,
            "removed_at": now,
            "remove_reason": reason,
        })
        self._records.append(removal)
        self._save()
        self.forensic.record_action(
            "manual_event_removed",
            f"Event {event_id} removed by {examiner}: {reason}",
            {"event_id": event_id, "examiner": examiner, "reason": reason},
        )

    # --- helpers -------------------------------------------------------

    def _require_examiner(self, examiner: Optional[str]) -> str:
        examiner = (examiner or getattr(self._config, "examiner_name", "") or "").strip()
        if not examiner:
            raise ValueError("Examiner identity is required; set EXAMINER_NAME or pass examiner=...")
        return examiner

    @staticmethod
    def _require_category_severity(category: str, severity: str) -> None:
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid category {category!r}; expected one of {sorted(_VALID_CATEGORIES)}")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity {severity!r}; expected one of {sorted(_VALID_SEVERITIES)}")


__all__ = ["EventManager"]
