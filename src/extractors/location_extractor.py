"""Location-data extractor.

Parses common export formats produced by Google and Apple:

  * Google Takeout "Semantic Location History" JSON (one file per month).
  * Google Takeout "Location History (Records.json)" — the raw ingest format.
  * Apple "Significant Locations" plist exports (when available).
  * Generic GPX files (widely used by third-party apps).

Output is a list of location dicts with a stable shape — timestamp, lat, lon, accuracy_m, source, and any free-form provenance fields from the input file. Location data is high-leverage in custody and protective-order matters: proximity to a known address, movement during a disputed window, or an unexplained overnight stay can be probative on its own.

This extractor is intentionally conservative. It does not attempt to re-geocode or normalize addresses; every record preserves the identifier the source file used so an opposing expert can cross-reference the original.
"""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .base import MessageExtractor

logger = logging.getLogger(__name__)


class LocationExtractor(MessageExtractor):
    """Parse location history exports into a unified list of point records."""

    SOURCE_NAME = "location"

    # GPX namespace used by Apple Maps, Strava, Garmin, and most GPX writers.
    _GPX_NS = {"g": "http://www.topografix.com/GPX/1/1"}

    def extract_all(self) -> List[Dict[str, Any]]:
        if not self.source or not self.source.exists():
            self.logger.info("No location source configured; skipping")
            return []

        records: List[Dict[str, Any]] = []
        files = [self.source] if self.source.is_file() else sorted(self.source.rglob("*"))
        for f in files:
            if not f.is_file():
                continue
            try:
                if f.suffix.lower() == ".json":
                    records.extend(self._parse_google_json(f))
                elif f.suffix.lower() == ".gpx":
                    records.extend(self._parse_gpx(f))
                elif f.suffix.lower() == ".plist":
                    records.extend(self._parse_apple_plist(f))
            except Exception as exc:
                self._record(
                    "location_parse_error",
                    f"Failed to parse {f.name}: {exc}",
                    {"file": str(f), "error": str(exc)},
                )

        records.sort(key=lambda r: r.get("timestamp", ""))
        self._record(
            "location_extraction_complete",
            f"Extracted {len(records)} location points from {self.source}",
            {"count": len(records), "source": str(self.source)},
        )
        return records

    # --- Google Takeout ------------------------------------------------

    def _parse_google_json(self, path: Path) -> Iterable[Dict[str, Any]]:
        """Parse Google Semantic Location History or Records JSON.

        Semantic History: { "timelineObjects": [{ "placeVisit": {...} }, { "activitySegment": {...} }] }
        Records.json: { "locations": [{ "latitudeE7": ..., "longitudeE7": ..., "timestamp": ... }] }
        """
        with open(path) as f:
            data = json.load(f)

        records: List[Dict[str, Any]] = []

        # Records.json — raw points
        if isinstance(data, dict) and isinstance(data.get("locations"), list):
            for entry in data["locations"]:
                ts = entry.get("timestamp") or entry.get("timestampMs")
                lat = entry.get("latitudeE7")
                lon = entry.get("longitudeE7")
                if lat is None or lon is None:
                    continue
                records.append({
                    "timestamp": self._normalize_ts(ts),
                    "latitude": lat / 1e7,
                    "longitude": lon / 1e7,
                    "accuracy_m": entry.get("accuracy"),
                    "source": "google_records",
                    "raw_id": entry.get("deviceTag"),
                })
            return records

        # Semantic Location History — place visits and activity segments
        if isinstance(data, dict) and isinstance(data.get("timelineObjects"), list):
            for obj in data["timelineObjects"]:
                if "placeVisit" in obj:
                    pv = obj["placeVisit"]
                    loc = pv.get("location", {})
                    dur = pv.get("duration", {})
                    records.append({
                        "timestamp": self._normalize_ts(dur.get("startTimestamp")),
                        "end_timestamp": self._normalize_ts(dur.get("endTimestamp")),
                        "latitude": (loc.get("latitudeE7") or 0) / 1e7 if loc.get("latitudeE7") else None,
                        "longitude": (loc.get("longitudeE7") or 0) / 1e7 if loc.get("longitudeE7") else None,
                        "place_name": loc.get("name"),
                        "place_address": loc.get("address"),
                        "source": "google_semantic_placeVisit",
                    })
                elif "activitySegment" in obj:
                    seg = obj["activitySegment"]
                    start = seg.get("startLocation", {})
                    end = seg.get("endLocation", {})
                    dur = seg.get("duration", {})
                    records.append({
                        "timestamp": self._normalize_ts(dur.get("startTimestamp")),
                        "end_timestamp": self._normalize_ts(dur.get("endTimestamp")),
                        "latitude": (start.get("latitudeE7") or 0) / 1e7 if start.get("latitudeE7") else None,
                        "longitude": (start.get("longitudeE7") or 0) / 1e7 if start.get("longitudeE7") else None,
                        "end_latitude": (end.get("latitudeE7") or 0) / 1e7 if end.get("latitudeE7") else None,
                        "end_longitude": (end.get("longitudeE7") or 0) / 1e7 if end.get("longitudeE7") else None,
                        "activity_type": seg.get("activityType"),
                        "source": "google_semantic_activitySegment",
                    })
            return records

        return records

    # --- GPX -----------------------------------------------------------

    def _parse_gpx(self, path: Path) -> Iterable[Dict[str, Any]]:
        tree = ET.parse(path)
        root = tree.getroot()
        records: List[Dict[str, Any]] = []

        # GPX 1.1 namespace; fall back to no-namespace match for older writers.
        for trkpt in list(root.iter("{http://www.topografix.com/GPX/1/1}trkpt")) + list(root.iter("trkpt")):
            lat = trkpt.attrib.get("lat")
            lon = trkpt.attrib.get("lon")
            if not lat or not lon:
                continue
            ts_el = trkpt.find("{http://www.topografix.com/GPX/1/1}time") or trkpt.find("time")
            records.append({
                "timestamp": self._normalize_ts(ts_el.text if ts_el is not None else None),
                "latitude": float(lat),
                "longitude": float(lon),
                "source": "gpx",
            })
        return records

    # --- Apple plist ---------------------------------------------------

    def _parse_apple_plist(self, path: Path) -> Iterable[Dict[str, Any]]:
        import plistlib
        with open(path, "rb") as f:
            data = plistlib.load(f)
        if not isinstance(data, list):
            return []
        records = []
        for entry in data:
            ts = entry.get("timestamp") or entry.get("date")
            if hasattr(ts, "isoformat"):
                ts = ts.isoformat()
            records.append({
                "timestamp": self._normalize_ts(ts),
                "latitude": entry.get("latitude"),
                "longitude": entry.get("longitude"),
                "accuracy_m": entry.get("horizontalAccuracy"),
                "source": "apple_significant_locations",
            })
        return records

    @staticmethod
    def _normalize_ts(value: Any) -> Optional[str]:
        """Coerce a variety of timestamp representations to ISO 8601 UTC."""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            # Accept ms since epoch if value is suspiciously large.
            if value > 1e12:
                value = value / 1000.0
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        if isinstance(value, str):
            return value
        return str(value)


__all__ = ["LocationExtractor"]
