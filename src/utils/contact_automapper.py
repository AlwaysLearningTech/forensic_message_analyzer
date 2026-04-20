"""Contact auto-mapping helpers.

Reduces the number of unmapped third-party contacts surfaced to the reviewer by importing identifiers from external sources the examiner already has access to:

  * vCard (.vcf) files — address book exports from iCloud, Google Contacts, Outlook. Each vCard's FN/N fields provide a display name; TEL and EMAIL fields provide identifiers to match against messages.
  * macOS AddressBook database — optional, only when the examiner is running on the analysis host and grants read access to ~/Library/Application Support/AddressBook/Sources/*/AddressBook-v22.abcddb.

The return value is the same shape the Config layer already consumes: a dict of display_name -> list[identifier]. The caller merges this into config.contact_mappings before extraction runs.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


_VCARD_FIELD_RE = re.compile(r"^(?P<name>[A-Za-z0-9\-]+)(?:;[^:]+)?:(?P<value>.*)$")


def parse_vcard_file(path: Path) -> List[Dict[str, object]]:
    """Parse a .vcf file into a list of contact dicts.

    The parser is intentionally minimal and forgiving — it does not validate vCard 2.1 vs 3.0 vs 4.0 quirks, it only extracts FN, N, TEL, and EMAIL. Anything unrecognized is ignored.
    """
    contacts: List[Dict[str, object]] = []
    current: Dict[str, object] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Could not read vCard %s: %s", path, exc)
        return []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        upper = line.upper()
        if upper == "BEGIN:VCARD":
            current = {"name": "", "phones": [], "emails": []}
            continue
        if upper == "END:VCARD":
            if current.get("phones") or current.get("emails"):
                contacts.append(current)
            current = {}
            continue
        m = _VCARD_FIELD_RE.match(line)
        if not m:
            continue
        tag = m.group("name").upper()
        value = m.group("value").strip()
        if tag == "FN" and value:
            current["name"] = value
        elif tag == "N" and value and not current.get("name"):
            parts = [p for p in value.split(";") if p]
            if parts:
                current["name"] = " ".join(reversed(parts)).strip()
        elif tag == "TEL" and value:
            current.setdefault("phones", []).append(value)
        elif tag == "EMAIL" and value:
            current.setdefault("emails", []).append(value)

    return contacts


def vcards_to_mapping(paths: Iterable[Path]) -> Dict[str, List[str]]:
    """Convert one or more vCard files into a display_name -> [identifiers] mapping.

    Phone identifiers are returned as raw strings; Config._expand_contact_mappings will fan them out to common formats. Contacts without a name (only identifiers) are skipped — we have no display label for them.
    """
    mapping: Dict[str, List[str]] = {}
    for path in paths:
        for contact in parse_vcard_file(Path(path)):
            name = (contact.get("name") or "").strip()
            if not name:
                continue
            ids = list(contact.get("phones") or []) + list(contact.get("emails") or [])
            if not ids:
                continue
            existing = mapping.setdefault(name, [])
            for ident in ids:
                if ident and ident not in existing:
                    existing.append(ident)
    return mapping


def merge_into_config(config, mapping: Dict[str, List[str]], default_person_slot: Optional[str] = None) -> Dict[str, List[str]]:
    """Merge an auto-mapped display_name -> identifiers dict into a Config's contact_mappings.

    Names that already exist in the config (case-insensitive match against person1/2/3_name) have their identifier lists extended. Unknown names are added as third-party entries under their own display name so downstream reports and the registry can surface them without a generic "Unknown" label.

    Returns the dict of entries that were actually added or extended.
    """
    if not mapping:
        return {}

    lower_to_existing = {str(k).lower(): k for k in config.contact_mappings.keys()}
    touched: Dict[str, List[str]] = {}

    for name, identifiers in mapping.items():
        canonical = lower_to_existing.get(name.lower(), name)
        bucket = config.contact_mappings.setdefault(canonical, [])
        added = []
        for ident in identifiers:
            if ident not in bucket:
                bucket.append(ident)
                added.append(ident)
        if added:
            # Keep Config's phone-variation expansion consistent.
            config.contact_mappings[canonical] = config._expand_contact_mappings(bucket)
            touched[canonical] = added

    return touched


def load_vcards_from_dir(source_dir: Path) -> Dict[str, List[str]]:
    """Convenience wrapper: scan a directory for .vcf files and return the merged mapping."""
    if not source_dir or not source_dir.is_dir():
        return {}
    paths = sorted(source_dir.glob("**/*.vcf"))
    if not paths:
        return {}
    logger.info("Auto-mapping: found %d vCard file(s) under %s", len(paths), source_dir)
    return vcards_to_mapping(paths)


__all__ = [
    "parse_vcard_file",
    "vcards_to_mapping",
    "merge_into_config",
    "load_vcards_from_dir",
]
