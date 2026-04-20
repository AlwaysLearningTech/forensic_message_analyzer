"""Call-logs extractor.

Sources supported:

  * iOS CallHistory.storedata — SQLite database at ~/Library/Application Support/CallHistoryDB/ on a Mac that syncs via iCloud, or extracted from an iPhone backup. Schema: ZCALLRECORD table with ZADDRESS (number), ZDATE (Cocoa seconds), ZDURATION, ZORIGINATED (bool), ZANSWERED (bool), ZCALLTYPE.

  * Android "Call Log Backup & Restore" XML — format emitted by the SMS Backup & Restore app (same author's companion product). Root element is <calls>; each <call> has number, date (ms since epoch), duration, type (1=incoming, 2=outgoing, 3=missed, 5=rejected).

  * Generic CSV — minimum columns: timestamp, number, duration_seconds, direction.

Output shape: one dict per call with timestamp (ISO UTC), number, contact (looked up against config.contact_mappings if possible), duration_seconds, direction in {incoming, outgoing, missed, rejected}, source label.
"""

from __future__ import annotations

import csv
import logging
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .base import MessageExtractor

logger = logging.getLogger(__name__)

_APPLE_EPOCH_OFFSET = 978307200  # seconds from Unix epoch to 2001-01-01 UTC


class CallLogsExtractor(MessageExtractor):
    """Parse call-history exports into a unified list of call records."""

    SOURCE_NAME = "call_logs"

    # Android SMS Backup & Restore call types (from the app's docs).
    _ANDROID_TYPE = {
        "1": "incoming",
        "2": "outgoing",
        "3": "missed",
        "4": "voicemail",
        "5": "rejected",
        "6": "refused_blocked",
    }

    # iOS CallHistoryDB ZCALLTYPE (inferred from public reverse-engineering notes).
    _IOS_TYPE = {
        0: "facetime_audio",
        1: "facetime_video",
        8: "cellular",
        16: "voip_other",
    }

    def extract_all(self) -> List[Dict[str, Any]]:
        if not self.source or not self.source.exists():
            self.logger.info("No call-logs source configured; skipping")
            return []

        calls: List[Dict[str, Any]] = []
        files = [self.source] if self.source.is_file() else sorted(self.source.rglob("*"))

        for f in files:
            if not f.is_file():
                continue
            try:
                if f.suffix.lower() in (".storedata", ".sqlite", ".db"):
                    calls.extend(self._parse_ios_callhistory(f))
                elif f.suffix.lower() == ".xml":
                    calls.extend(self._parse_android_xml(f))
                elif f.suffix.lower() == ".csv":
                    calls.extend(self._parse_generic_csv(f))
            except Exception as exc:
                self._record(
                    "calllogs_parse_error",
                    f"Failed to parse {f.name}: {exc}",
                    {"file": str(f), "error": str(exc)},
                )

        self._map_contacts(calls)
        calls.sort(key=lambda c: c.get("timestamp", ""))
        self._record(
            "calllogs_extraction_complete",
            f"Extracted {len(calls)} call records from {self.source}",
            {"count": len(calls), "source": str(self.source)},
        )
        return calls

    # --- iOS ------------------------------------------------------------

    def _parse_ios_callhistory(self, path: Path) -> Iterable[Dict[str, Any]]:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT ZADDRESS, ZDATE, ZDURATION, ZORIGINATED, ZANSWERED, ZCALLTYPE "
                "FROM ZCALLRECORD ORDER BY ZDATE"
            )
            records = []
            for address, z_date, duration, originated, answered, call_type in cur.fetchall():
                ts = None
                if z_date is not None:
                    ts = datetime.fromtimestamp(z_date + _APPLE_EPOCH_OFFSET, tz=timezone.utc).isoformat()
                if originated:
                    direction = "outgoing"
                elif not answered:
                    direction = "missed"
                else:
                    direction = "incoming"
                records.append({
                    "timestamp": ts,
                    "number": address,
                    "duration_seconds": int(duration or 0),
                    "direction": direction,
                    "call_type": self._IOS_TYPE.get(int(call_type) if call_type is not None else -1, "unknown"),
                    "source": "ios_callhistory",
                })
            return records
        finally:
            conn.close()

    # --- Android --------------------------------------------------------

    def _parse_android_xml(self, path: Path) -> Iterable[Dict[str, Any]]:
        tree = ET.parse(path)
        root = tree.getroot()
        records = []
        for call in root.findall("call"):
            number = call.attrib.get("number")
            date_ms = call.attrib.get("date")
            duration = call.attrib.get("duration", "0")
            call_type = call.attrib.get("type", "0")
            if not number or not date_ms:
                continue
            try:
                ts = datetime.fromtimestamp(int(date_ms) / 1000, tz=timezone.utc).isoformat()
            except ValueError:
                ts = None
            records.append({
                "timestamp": ts,
                "number": number,
                "duration_seconds": int(duration),
                "direction": self._ANDROID_TYPE.get(call_type, "unknown"),
                "source": "android_callbackup",
                "contact_name": call.attrib.get("contact_name") or None,
            })
        return records

    # --- Generic CSV ----------------------------------------------------

    def _parse_generic_csv(self, path: Path) -> Iterable[Dict[str, Any]]:
        records = []
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append({
                    "timestamp": row.get("timestamp"),
                    "number": row.get("number"),
                    "duration_seconds": int(row.get("duration_seconds", "0") or 0),
                    "direction": (row.get("direction") or "unknown").lower(),
                    "source": "csv",
                })
        return records

    # --- Contact mapping -----------------------------------------------

    def _map_contacts(self, calls: List[Dict[str, Any]]):
        """Attach a contact display name for any number that resolves to a mapped person."""
        # Build a normalized digit lookup for fast matching.
        digit_map: Dict[str, str] = {}
        for name, identifiers in (self.config.contact_mappings or {}).items():
            for ident in identifiers:
                digits = "".join(ch for ch in str(ident) if ch.isdigit())
                if digits:
                    digit_map.setdefault(digits, name)

        for call in calls:
            number = call.get("number") or ""
            digits = "".join(ch for ch in str(number) if ch.isdigit())
            # Try full match, then 10-digit suffix (strip +1).
            match = digit_map.get(digits)
            if not match and len(digits) > 10:
                match = digit_map.get(digits[-10:])
            if match:
                call["contact"] = match


__all__ = ["CallLogsExtractor"]
