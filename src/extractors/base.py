"""Base class for message extractors.

Every extractor previously repeated the same four-argument constructor (source, forensic_recorder, forensic_integrity, config) and the same three-line body. This module centralizes that boilerplate so new extractors only override source-specific behavior. Existing extractors continue to work unchanged; they can migrate to this base opportunistically.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Optional

from ..config import Config
from ..forensic_utils import ForensicIntegrity, ForensicRecorder


class MessageExtractor:
    """Shared init and utilities for per-source extractors.

    Subclasses set ``SOURCE_NAME`` (used in forensic log entries) and implement ``extract_all()`` to return a list of Message-shaped dicts (see src/schema.py).
    """

    #: Human-readable source identifier, e.g. "imessage", "whatsapp", "email".
    SOURCE_NAME: str = "unknown"

    def __init__(
        self,
        source: Optional[str],
        forensic_recorder: ForensicRecorder,
        forensic_integrity: ForensicIntegrity,
        config: Optional[Config] = None,
    ):
        self.config = config if config is not None else Config()
        self.forensic = forensic_recorder
        self.integrity = forensic_integrity
        self.source = Path(source).expanduser() if source else None
        self.logger = logging.getLogger(f"{self.__module__}.{self.__class__.__name__}")

    def extract_all(self) -> List[Any]:
        """Return a list of Message-shaped dicts for this source. Subclasses must override."""
        raise NotImplementedError

    def _record(self, action: str, details: str, metadata: Optional[dict] = None):
        """Forensic log convenience that tags every entry with SOURCE_NAME."""
        md = dict(metadata or {})
        md.setdefault("source_name", self.SOURCE_NAME)
        self.forensic.record_action(action, details, md)


__all__ = ["MessageExtractor"]
