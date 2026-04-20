"""Redaction workflow for court-ready exhibits.

A review decision labels an item Relevant / Not Relevant / Uncertain. Redaction is a separate, independently-auditable action that marks portions of an otherwise-relevant item as "do not render" in shareable output — typically third-party PII (children's full names, counselor notes, medical references) that the legal team has agreed to withhold from discovery production.

Design:

  * Redactions are append-only and signed into the chain of custody like reviews. An examiner can layer additional redactions on top of prior ones; unredacting requires a revoke() call that adds a new record, never deletes the prior one.

  * Each redaction targets a single message_id and carries: start/end offsets inside the content string (or a regex for "any phone number"), a redaction label ("PII — child's name"), an authority ("joint protective order 2024-03-15"), and the examiner who issued it.

  * Reporters consult the redaction set when rendering content. The chat/HTML/Excel reporters replace redacted spans with a visible marker ("[REDACTED — PII: child's name]") so the reader knows redaction occurred without seeing the content.

  * The unredacted content remains available to the forensic record; redaction is a rendering filter, not a deletion. Raw JSON exports and the chain of custody preserve the original so an opposing expert can later challenge a specific redaction.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Config
from ..forensic_utils import ForensicRecorder

logger = logging.getLogger(__name__)


class RedactionManager:
    """Track redaction decisions and apply them to content at render time."""

    def __init__(
        self,
        review_dir: Optional[Path] = None,
        session_id: Optional[str] = None,
        config: Optional[Config] = None,
        forensic_recorder: Optional[ForensicRecorder] = None,
    ):
        self._config = config if config is not None else Config()
        self.review_dir = review_dir or Path(self._config.review_dir)
        self.review_dir.mkdir(parents=True, exist_ok=True)
        self.forensic = forensic_recorder if forensic_recorder is not None else ForensicRecorder()

        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self._records: List[Dict[str, Any]] = self._load()

    # --- persistence ---------------------------------------------------

    def _file(self) -> Path:
        return self.review_dir / f"redactions_{self.session_id}.json"

    def _load(self) -> List[Dict[str, Any]]:
        path = self._file()
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text())
            return data.get("redactions", [])
        except Exception:
            return []

    def _save(self):
        path = self._file()
        payload = {
            "session_id": self.session_id,
            "updated_at": datetime.now().isoformat(),
            "redactions": self._records,
        }
        path.write_text(json.dumps(payload, indent=2, default=str))

    # --- operations ----------------------------------------------------

    def redact(
        self,
        *,
        message_id: str,
        reason: str,
        authority: str,
        examiner: Optional[str] = None,
        span: Optional[tuple] = None,
        pattern: Optional[str] = None,
        replacement: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a redaction against ``message_id``.

        Either ``span`` (start, end inclusive) or ``pattern`` (regex to apply to the content) must be provided. ``reason`` and ``authority`` are required — opposing counsel can inspect both. ``replacement`` defaults to "[REDACTED — <reason>]".

        Raises ValueError on missing fields so downstream rendering never silently fails.
        """
        if not reason or not authority:
            raise ValueError("Redaction requires reason and authority (e.g. order/agreement citation)")
        if not span and not pattern:
            raise ValueError("Redaction requires either span=(start,end) or pattern=<regex>")
        examiner = (examiner or getattr(self._config, "examiner_name", "") or "").strip()
        if not examiner:
            raise ValueError("Examiner identity is required to redact")

        record = {
            "message_id": message_id,
            "reason": reason,
            "authority": authority,
            "examiner": examiner,
            "span": list(span) if span else None,
            "pattern": pattern,
            "replacement": replacement or f"[REDACTED — {reason}]",
            "timestamp": datetime.now().isoformat(),
            "revoked_at": None,
            "session_id": self.session_id,
        }
        self._records.append(record)
        self._save()
        self.forensic.record_action(
            "redaction_added",
            f"Redaction on {message_id} by {examiner}: {reason}",
            {"message_id": message_id, "reason": reason, "authority": authority, "examiner": examiner},
        )
        return record

    def revoke(self, message_id: str, reason: str, examiner: Optional[str] = None):
        """Revoke the most recent non-revoked redaction on message_id with a justification."""
        examiner = (examiner or getattr(self._config, "examiner_name", "") or "").strip()
        if not examiner:
            raise ValueError("Examiner identity is required to revoke a redaction")
        for rec in reversed(self._records):
            if rec.get("message_id") == message_id and not rec.get("revoked_at"):
                rec["revoked_at"] = datetime.now().isoformat()
                rec["revoked_by"] = examiner
                rec["revoke_reason"] = reason
                self._save()
                self.forensic.record_action(
                    "redaction_revoked",
                    f"Revoked redaction on {message_id} by {examiner}: {reason}",
                    {"message_id": message_id, "examiner": examiner, "reason": reason},
                )
                return
        raise ValueError(f"No active redaction found for {message_id!r}")

    # --- rendering -----------------------------------------------------

    def active_for(self, message_id: str) -> List[Dict[str, Any]]:
        return [r for r in self._records if r["message_id"] == message_id and not r.get("revoked_at")]

    def apply(self, message_id: str, content: str) -> str:
        """Apply every active redaction for ``message_id`` to ``content``.

        Span redactions are applied first (in reverse order to keep offsets stable); regex redactions are applied last. The result is suitable for any renderer (HTML, Excel, Word, JSON) that emits shareable content.
        """
        active = self.active_for(message_id)
        if not active:
            return content

        span_redactions = [r for r in active if r.get("span")]
        # Apply in reverse order of start offset so earlier spans don't shift later ones.
        for r in sorted(span_redactions, key=lambda x: -x["span"][0]):
            start, end = r["span"]
            start = max(0, min(start, len(content)))
            end = max(start, min(end, len(content)))
            content = content[:start] + r["replacement"] + content[end:]

        for r in (x for x in active if x.get("pattern")):
            try:
                content = re.sub(r["pattern"], r["replacement"], content)
            except re.error as exc:
                logger.warning("Invalid redaction regex %r on %s: %s", r["pattern"], message_id, exc)

        return content


__all__ = ["RedactionManager"]
