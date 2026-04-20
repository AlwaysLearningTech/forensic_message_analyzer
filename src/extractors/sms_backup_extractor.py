"""SMS backup extractor (Android "SMS Backup & Restore" XML).

Format: root element is <smses> with count attribute; each child is either <sms> or <mms>.

  <sms protocol="0" address="+15551234567" date="1704067200000" type="2" body="Hello" read="1" toa="0" sc_toa="0" date_sent="1704067199000"/>
  <mms address="..." date="..." ct_t="application/vnd.wap.multipart.related" m_type="132" ...>
    <parts><part ct="image/jpeg" name="photo.jpg" data="base64..."/></parts>
    <addrs><addr address="..." type="151"/></addrs>
  </mms>

Type values (date_received / transport):
  1 = received, 2 = sent, 3 = draft, 4 = outbox, 5 = failed, 6 = queued

Output is Message-shaped (see src/schema.py): message_id, timestamp (ISO UTC), sender, recipient, content, source='sms', attachment if MMS, subject for MMS with a subject field.
"""

from __future__ import annotations

import base64
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .base import MessageExtractor

logger = logging.getLogger(__name__)


class SMSBackupExtractor(MessageExtractor):
    """Parse Android SMS Backup & Restore XML archives."""

    SOURCE_NAME = "sms_backup"

    _SMS_TYPE = {
        "1": "received",
        "2": "sent",
        "3": "draft",
        "4": "outbox",
        "5": "failed",
        "6": "queued",
    }

    def extract_all(self) -> List[Dict[str, Any]]:
        if not self.source or not self.source.exists():
            self.logger.info("No SMS backup source configured; skipping")
            return []

        messages: List[Dict[str, Any]] = []
        files = [self.source] if self.source.is_file() else sorted(self.source.rglob("*.xml"))
        for f in files:
            if not f.is_file():
                continue
            try:
                messages.extend(self._parse_xml(f))
            except Exception as exc:
                self._record(
                    "sms_backup_parse_error",
                    f"Failed to parse {f.name}: {exc}",
                    {"file": str(f), "error": str(exc)},
                )

        messages.sort(key=lambda m: m.get("timestamp", ""))
        self._record(
            "sms_backup_extraction_complete",
            f"Extracted {len(messages)} SMS/MMS from {self.source}",
            {"count": len(messages), "source": str(self.source)},
        )
        return messages

    def _parse_xml(self, path: Path) -> Iterable[Dict[str, Any]]:
        tree = ET.parse(path)
        root = tree.getroot()
        records: List[Dict[str, Any]] = []
        idx = 0
        for child in root:
            idx += 1
            tag = child.tag.lower()
            try:
                if tag == "sms":
                    records.append(self._sms_to_record(child, idx))
                elif tag == "mms":
                    record = self._mms_to_record(child, idx, attachment_dir=path.parent / "mms_attachments")
                    if record:
                        records.append(record)
            except Exception as exc:
                self.logger.warning("skipping malformed %s: %s", tag, exc)
        return records

    def _sms_to_record(self, el, idx: int) -> Dict[str, Any]:
        address = el.attrib.get("address", "")
        date_ms = el.attrib.get("date", "0")
        sms_type = el.attrib.get("type", "1")
        body = el.attrib.get("body", "")
        contact_name = el.attrib.get("contact_name")

        try:
            ts = datetime.fromtimestamp(int(date_ms) / 1000, tz=timezone.utc).isoformat()
        except ValueError:
            ts = None

        is_sent = sms_type == "2"
        person1 = getattr(self.config, "person1_name", "Me")

        return {
            "message_id": f"sms_{idx}",
            "timestamp": ts,
            "sender": person1 if is_sent else (contact_name or address),
            "recipient": (contact_name or address) if is_sent else person1,
            "content": body,
            "source": "sms",
            "is_from_me": is_sent,
            "sms_type": self._SMS_TYPE.get(sms_type, "unknown"),
        }

    def _mms_to_record(self, el, idx: int, attachment_dir: Path) -> Optional[Dict[str, Any]]:
        address = el.attrib.get("address", "")
        date_ms = el.attrib.get("date", "0")
        msg_box = el.attrib.get("msg_box", "1")  # 1=received, 2=sent
        subject = el.attrib.get("sub")
        contact_name = el.attrib.get("contact_name")

        try:
            ts = datetime.fromtimestamp(int(date_ms) / 1000, tz=timezone.utc).isoformat()
        except ValueError:
            ts = None

        is_sent = msg_box == "2"
        person1 = getattr(self.config, "person1_name", "Me")

        # Extract text parts and the first media part (if any) for attachment.
        text_parts: List[str] = []
        attachment_path: Optional[str] = None
        parts = el.find("parts")
        if parts is not None:
            for part in parts.findall("part"):
                ct = part.attrib.get("ct", "")
                if ct.startswith("text/"):
                    text_parts.append(part.attrib.get("text", ""))
                elif part.attrib.get("data") and attachment_path is None:
                    name = part.attrib.get("name") or f"mms_{idx}.bin"
                    attachment_dir.mkdir(parents=True, exist_ok=True)
                    out_path = attachment_dir / name
                    try:
                        out_path.write_bytes(base64.b64decode(part.attrib["data"]))
                        attachment_path = str(out_path)
                    except Exception:
                        pass

        record = {
            "message_id": f"mms_{idx}",
            "timestamp": ts,
            "sender": person1 if is_sent else (contact_name or address),
            "recipient": (contact_name or address) if is_sent else person1,
            "content": "\n".join(t for t in text_parts if t),
            "source": "sms",
            "is_from_me": is_sent,
            "sms_type": "mms_sent" if is_sent else "mms_received",
        }
        if subject:
            record["subject"] = subject
        if attachment_path:
            record["attachment"] = attachment_path
            record["attachment_name"] = Path(attachment_path).name
        return record


__all__ = ["SMSBackupExtractor"]
