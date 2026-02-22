"""
Third-party contact registry for forensic message analyzer.
Tracks contacts discovered in emails and screenshots that are not in the
configured person mappings (PERSON1/2/3).
"""

import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from .config import Config
from .forensic_utils import ForensicRecorder

logger = logging.getLogger(__name__)

# Phone-like pattern used to classify identifiers
_PHONE_RE = re.compile(r'[\d\+\(\)\-\s]{10,}')


class ThirdPartyRegistry:
    """
    Centralized registry for third-party contacts discovered during
    extraction and analysis.  Provides O(1) dedup by normalised email
    or phone, and logs every registration to ForensicRecorder for
    chain-of-custody compliance.
    """

    def __init__(self, forensic_recorder: ForensicRecorder, config: Optional[Config] = None):
        self.forensic = forensic_recorder
        self.config = config or Config()

        # Build a fast lookup set of all mapped identifiers (lowered)
        self._mapped_ids: set = set()
        for identifiers in self.config.contact_mappings.values():
            for ident in identifiers:
                self._mapped_ids.add(ident.strip().lower())

        # Internal storage: normalised_key -> entry dict
        self._entries: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_mapped(self, identifier: str) -> bool:
        """Return True if *identifier* belongs to a configured person."""
        return identifier.strip().lower() in self._mapped_ids

    def register(self, identifier: str, source: str, context: Optional[str] = None,
                 display_name: Optional[str] = None) -> None:
        """
        Register a third-party contact.

        Deduplication is by normalised identifier (lowercased, stripped).
        If the same identifier is seen from a different source, the entry
        is updated to include both sources.

        Args:
            identifier: Email address, phone number, or name.
            source: Where it was found (e.g. "email", "screenshot").
            context: Optional extra context (e.g. filename, subject line).
            display_name: Optional human-readable name from OCR or header.
        """
        if not identifier or not identifier.strip():
            return

        norm = identifier.strip().lower()

        # Skip if this is a mapped person
        if norm in self._mapped_ids:
            return

        if norm in self._entries:
            entry = self._entries[norm]
            # Merge source
            if source not in entry['sources']:
                entry['sources'].append(source)
            # Merge raw identifiers
            if identifier not in entry['raw_identifiers']:
                entry['raw_identifiers'].append(identifier)
            # Upgrade display_name if we didn't have one
            if display_name and not entry.get('display_name'):
                entry['display_name'] = display_name
            # Append context
            if context and context not in entry.get('contexts', []):
                entry.setdefault('contexts', []).append(context)
        else:
            self._entries[norm] = {
                'identifier': identifier.strip(),
                'normalised': norm,
                'display_name': display_name or '',
                'sources': [source],
                'raw_identifiers': [identifier],
                'first_seen': datetime.now().isoformat(),
                'contexts': [context] if context else [],
            }
            self.forensic.record_action(
                "third_party_registered",
                f"Registered third-party contact: {identifier.strip()}",
                {"identifier": identifier.strip(), "source": source},
            )

    def resolve(self, identifier: str) -> str:
        """
        Return a display label for *identifier*.

        If the identifier was registered and has a display_name, returns
        ``"Third Party: <display_name>"``.  Otherwise returns
        ``"Third Party: <identifier>"``.  If the identifier is a mapped
        person, returns the person name (delegates to config).
        """
        if not identifier:
            return 'Unknown'

        norm = identifier.strip().lower()

        # Check mapped persons first
        for person_name, identifiers in self.config.contact_mappings.items():
            for ident in identifiers:
                if norm == ident.strip().lower():
                    return person_name

        entry = self._entries.get(norm)
        if entry and entry.get('display_name'):
            return f"Third Party: {entry['display_name']}"
        return f"Third Party: {identifier.strip()}"

    def get_all(self) -> List[Dict[str, Any]]:
        """Return all registered third-party contacts as a list of dicts."""
        return list(self._entries.values())

    def get_summary(self) -> Dict[str, Any]:
        """Return summary statistics grouped by source."""
        by_source: Dict[str, int] = {}
        for entry in self._entries.values():
            for src in entry['sources']:
                by_source[src] = by_source.get(src, 0) + 1
        return {
            'total': len(self._entries),
            'by_source': by_source,
        }
