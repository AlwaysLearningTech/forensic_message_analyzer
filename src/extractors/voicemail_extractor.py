"""Voicemail extractor.

Sources supported:

  * iOS Voicemail.db — SQLite DB at /private/var/mobile/Library/Voicemail/voicemail.db on an iPhone backup. Schema: voicemail table with ROWID, remote_uid, date (Unix seconds), token, sender (number), callback_num, duration, expiration, trashed_date, flags. Audio files live in the same directory with ROWID.amr (pre-iOS 17) or ROWID.wav (VVM).

  * Visual Voicemail Transcription plist — newer iPhones carry a transcription field in the voicemail.db row (column varies by iOS version) and/or a sibling .txt transcript produced by on-device speech recognition.

  * Generic directory of audio files with a manifest CSV (timestamp, number, duration_seconds, transcript_path, audio_path) — the path most third-party backup tools use.

Output shape: one dict per voicemail with timestamp (ISO UTC), sender, duration_seconds, audio_path (preserved as absolute file path in the working copy), transcript (if available), and source label.
"""

from __future__ import annotations

import csv
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .base import MessageExtractor

logger = logging.getLogger(__name__)


class VoicemailExtractor(MessageExtractor):
    """Parse iOS voicemail.db plus any sibling transcripts into voicemail records."""

    SOURCE_NAME = "voicemail"

    def extract_all(self) -> List[Dict[str, Any]]:
        if not self.source or not self.source.exists():
            self.logger.info("No voicemail source configured; skipping")
            return []

        records: List[Dict[str, Any]] = []
        files = [self.source] if self.source.is_file() else sorted(self.source.rglob("*"))

        for f in files:
            if not f.is_file():
                continue
            try:
                if f.name == "voicemail.db" or f.suffix.lower() in (".sqlite", ".db"):
                    records.extend(self._parse_ios_db(f))
                elif f.suffix.lower() == ".csv":
                    records.extend(self._parse_manifest_csv(f))
            except Exception as exc:
                self._record(
                    "voicemail_parse_error",
                    f"Failed to parse {f.name}: {exc}",
                    {"file": str(f), "error": str(exc)},
                )

        records.sort(key=lambda r: r.get("timestamp", ""))
        self._record(
            "voicemail_extraction_complete",
            f"Extracted {len(records)} voicemail records from {self.source}",
            {"count": len(records), "source": str(self.source)},
        )
        return records

    def _parse_ios_db(self, path: Path) -> Iterable[Dict[str, Any]]:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            cur = conn.cursor()
            # Discover columns to be resilient to iOS version differences.
            cur.execute("PRAGMA table_info(voicemail)")
            cols = {row[1] for row in cur.fetchall()}
            if not cols:
                return []

            select = ["ROWID"]
            for c in ("date", "sender", "callback_num", "duration", "trashed_date", "flags", "transcription"):
                if c in cols:
                    select.append(c)
            cur.execute(f"SELECT {', '.join(select)} FROM voicemail")
            rows = cur.fetchall()

            parent_dir = path.parent
            records = []
            for row in rows:
                d = dict(zip(select, row))
                rowid = d.get("ROWID")
                ts_raw = d.get("date")
                ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc).isoformat() if ts_raw else None

                # Find the audio file next to the db (rowid.amr or rowid.wav).
                audio_path = None
                for ext in (".amr", ".wav", ".m4a"):
                    candidate = parent_dir / f"{rowid}{ext}"
                    if candidate.exists():
                        audio_path = str(candidate)
                        break

                records.append({
                    "timestamp": ts,
                    "sender": d.get("sender") or d.get("callback_num"),
                    "duration_seconds": int(d.get("duration") or 0),
                    "audio_path": audio_path,
                    "transcript": d.get("transcription"),
                    "trashed": bool(d.get("trashed_date")),
                    "source": "ios_voicemail_db",
                    "rowid": rowid,
                })
            return records
        finally:
            conn.close()

    def _parse_manifest_csv(self, path: Path) -> Iterable[Dict[str, Any]]:
        records = []
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append({
                    "timestamp": row.get("timestamp"),
                    "sender": row.get("number") or row.get("sender"),
                    "duration_seconds": int(row.get("duration_seconds", "0") or 0),
                    "audio_path": row.get("audio_path"),
                    "transcript": row.get("transcript"),
                    "source": "voicemail_csv",
                })
        return records


__all__ = ["VoicemailExtractor"]
