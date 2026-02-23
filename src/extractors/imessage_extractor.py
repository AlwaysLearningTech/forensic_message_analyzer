#!/usr/bin/env python3
"""
iMessage extraction module.
Extracts messages from iMessage chat.db database with full forensic column
coverage, tapback/reaction linking, and robust attributedBody parsing.
"""

import sqlite3
import logging
from pathlib import Path
import pandas as pd

from ..config import Config
from ..forensic_utils import ForensicRecorder, ForensicIntegrity

# Initialize config
config = Config()

logger = logging.getLogger(__name__)

# Tapback type code -> emoji mapping
TAPBACK_MAP = {
    2000: '\u2764\ufe0f',   # Love ❤️
    2001: '\U0001f44d',     # Like 👍
    2002: '\U0001f44e',     # Dislike 👎
    2003: '\U0001f602',     # Laugh 😂
    2004: '\u203c\ufe0f',   # Emphasis ‼️
    2005: '\u2753',         # Question ❓
}
# 3000-3005 = remove the corresponding 2000-2005 reaction
REMOVE_TAPBACK_MAP = {3000 + i: emoji for i, emoji in enumerate(TAPBACK_MAP.values())}

# Date columns requiring Apple epoch nanosecond conversion in SQL
_DATE_COLUMNS = [
    'date_read', 'date_delivered', 'date_edited', 'date_retracted',
]

# Non-date columns to add to the SELECT (beyond the core set)
_EXTRA_COLUMNS = [
    'is_read', 'reply_to_guid', 'thread_originator_guid', 'thread_originator_part',
    'subject', 'item_type', 'is_audio_message', 'expressive_send_style_id',
    'was_detonated', 'destination_caller_id', 'was_downgraded', 'is_sos',
    'balloon_bundle_id', 'group_title', 'group_action_type',
    'associated_message_guid', 'associated_message_emoji',
]

# Extra attachment columns beyond the core set
_EXTRA_ATTACHMENT_COLUMNS = [
    'uti', 'is_sticker', 'hide_attachment', 'transfer_state',
    'is_outgoing', 'created_date', 'original_guid',
]


class IMessageExtractor:
    """
    Extracts messages from iMessage chat.db database.
    Handles both SMS and iMessage conversations.
    Includes attributedBody decoding via pytypedstream library with
    legacy heuristic fallbacks.
    """

    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.heic', '.heif', '.webp', '.tiff', '.bmp'}

    def __init__(self, db_path: str, forensic_recorder: ForensicRecorder, forensic_integrity: ForensicIntegrity):
        self.db_path = Path(db_path) if db_path else None
        self.forensic = forensic_recorder
        self.integrity = forensic_integrity

        if self.db_path and not self.db_path.exists():
            raise FileNotFoundError(f"iMessage database not found: {self.db_path}")

    # ------------------------------------------------------------------
    # attributedBody parsers
    # ------------------------------------------------------------------

    def decode_attributed_body(self, blob_data):
        """
        Decode text from attributedBody BLOB data.

        Priority chain:
          1. pytypedstream library (full typedstream deserialization)
          2. Legacy streamtyped heuristic
          3. Legacy typedstream heuristic
        """
        if not blob_data:
            return None

        # 1. pytypedstream library — proper NSAttributedString deserialization
        try:
            text = self._parse_typedstream_library(blob_data)
            if text:
                return text
        except Exception:
            pass

        # 2. Legacy streamtyped heuristic (byte pattern matching)
        try:
            text = self._parse_streamtyped(blob_data)
            if text:
                return text
        except Exception:
            pass

        # 3. Legacy typedstream heuristic (printable text extraction)
        try:
            text = self._parse_typedstream_heuristic(blob_data)
            if text:
                return text
        except Exception:
            pass

        return None

    def _parse_typedstream_library(self, data):
        """
        Parse attributedBody using the pytypedstream library.
        Extracts the NSString content from the NSAttributedString archive.
        """
        try:
            import typedstream
        except ImportError:
            return None  # Library not installed; fall through to heuristics

        # High-level unarchive: gives us the NSAttributedString as a
        # GenericArchivedObject whose first content value is the NSString.
        result = typedstream.unarchive_from_data(data)
        if hasattr(result, 'contents') and result.contents:
            first = result.contents[0]
            if hasattr(first, 'value') and hasattr(first.value, 'value'):
                text = first.value.value
                if isinstance(text, str) and text.strip():
                    return text.strip()

        # Low-level fallback: iterate stream events for the first bytes value
        # after an NSString class declaration.
        from typedstream.stream import TypedStreamReader
        reader = TypedStreamReader.from_data(data)
        found_nsstring = False
        for event in reader:
            if hasattr(event, 'name') and event.name == b'NSString':
                found_nsstring = True
            if found_nsstring and isinstance(event, bytes) and len(event) > 0:
                try:
                    text = event.decode('utf-8').strip()
                    if text:
                        return text
                except UnicodeDecodeError:
                    continue
        return None

    def _parse_streamtyped(self, data):
        """Parse legacy streamtyped format (byte pattern matching)."""
        START_PATTERN = b'\x01\x2b'
        END_PATTERN = b'\x86\x84'

        start_idx = -1
        for i in range(len(data) - 1):
            if data[i:i + 2] == START_PATTERN:
                start_idx = i + 2
                break
        if start_idx == -1:
            return None

        end_idx = -1
        for i in range(start_idx, len(data) - 1):
            if data[i:i + 2] == END_PATTERN:
                end_idx = i
                break
        if end_idx == -1:
            return None

        text_data = data[start_idx:end_idx]
        try:
            text = text_data.decode('utf-8')
            if len(text) > 1:
                return text[1:].strip()
            return text.strip()
        except UnicodeDecodeError:
            text = text_data.decode('utf-8', errors='replace')
            if len(text) > 3:
                return text[3:].strip()
            return text.strip()

    def _parse_typedstream_heuristic(self, data):
        """Parse typedstream format via printable-text extraction heuristic."""
        try:
            text_str = data.decode('utf-8', errors='ignore')
            nsstring_marker = "NSString"
            if nsstring_marker in text_str:
                parts = text_str.split(nsstring_marker)
                if len(parts) > 1:
                    cleaned = ''.join(c for c in parts[1] if c.isprintable())
                    if len(cleaned) > 2:
                        return cleaned.strip()

            readable_parts = []
            current_text = ""
            for byte in data:
                char = chr(byte)
                if char.isprintable() and not char.isspace():
                    current_text += char
                elif char in ' \n\r\t':
                    if current_text:
                        current_text += char
                else:
                    if len(current_text) > 3:
                        readable_parts.append(current_text.strip())
                    current_text = ""
            if len(current_text) > 3:
                readable_parts.append(current_text.strip())

            if readable_parts:
                longest = max(readable_parts, key=len)
                if len(longest) > 5:
                    return longest
        except Exception:
            pass
        return None

    def extract_text_with_fallback(self, text, attributed_body):
        """Extract text with fallback to attributedBody decoding."""
        if text and str(text).strip():
            return str(text).strip()
        if attributed_body:
            decoded = self.decode_attributed_body(attributed_body)
            if decoded and decoded.strip():
                return decoded.strip()
        return None

    # ------------------------------------------------------------------
    # Schema discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _discover_columns(cursor, table_name):
        """Return set of column names available in a table."""
        cursor.execute(f"PRAGMA table_info({table_name})")
        return {row[1] for row in cursor.fetchall()}

    # ------------------------------------------------------------------
    # Attachment extraction
    # ------------------------------------------------------------------

    def _get_attachments_for_message(self, cursor, message_rowid: int, available_att_cols: set) -> list:
        """
        Query attachments for a given message using message_attachment_join.

        Args:
            cursor: SQLite cursor on the open chat.db connection.
            message_rowid: The ROWID of the message.
            available_att_cols: Set of column names in the attachment table.
        """
        # Core columns always present
        select_parts = ['a.rowid', 'a.filename', 'a.mime_type', 'a.transfer_name', 'a.total_bytes']

        # Extra columns if available in this schema
        extra_available = [c for c in _EXTRA_ATTACHMENT_COLUMNS if c in available_att_cols]
        for col in extra_available:
            select_parts.append(f'a.{col}')

        query = f"""
        SELECT {', '.join(select_parts)}
        FROM message_attachment_join j
        LEFT JOIN attachment a ON j.attachment_id = a.ROWID
        WHERE j.message_id = ?
        """
        try:
            cursor.execute(query, (message_rowid,))
            rows = cursor.fetchall()
        except Exception:
            return []

        attachments = []
        home_dir = str(Path.home())
        for row in rows:
            # Core fields (always present)
            rowid = row[0]
            filename = row[1]
            mime_type = row[2]
            transfer_name = row[3]
            total_bytes = row[4]

            if not filename:
                continue

            resolved = filename.replace('~', home_dir, 1) if filename.startswith('~') else filename
            display_name = transfer_name or Path(resolved).name

            att = {
                'path': resolved,
                'name': display_name,
                'mime_type': mime_type or '',
                'size_bytes': total_bytes or 0,
            }

            # Extra fields (positional after the 5 core fields)
            for idx, col in enumerate(extra_available):
                val = row[5 + idx]
                if col in ('is_sticker', 'hide_attachment', 'is_outgoing'):
                    att[col] = bool(val) if val else False
                else:
                    att[col] = val
            attachments.append(att)
        return attachments

    # ------------------------------------------------------------------
    # Main extraction
    # ------------------------------------------------------------------

    def extract_messages(self) -> list:
        """
        Extract messages from iMessage database with full forensic column
        coverage, tapback inclusion, and reaction linking.
        """
        if not self.db_path:
            logger.warning("No iMessage database path configured")
            return []

        try:
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            try:
                cursor = conn.cursor()

                # Discover available columns for schema safety
                msg_cols = self._discover_columns(cursor, 'message')
                att_cols = self._discover_columns(cursor, 'attachment')

                # Get all participant handles from config
                all_handles = []
                for person_mappings in config.contact_mappings.values():
                    all_handles.extend(person_mappings)

                if not all_handles:
                    logger.warning("No contact mappings configured — cannot filter iMessages")
                    return []

                placeholders = ','.join('?' * len(all_handles))

                # Build dynamic SELECT with schema-safe column discovery
                select_parts = [
                    'm.ROWID as message_id',
                    'm.guid',
                    'm.text',
                    'm.attributedBody',
                    'm.is_from_me',
                    'h.id as handle',
                    'c.chat_identifier',
                    "datetime(m.date/1000000000 + strftime('%s','2001-01-01'), 'unixepoch') as timestamp",
                    'm.service',
                    'm.associated_message_type',
                    '(SELECT COUNT(*) FROM message_attachment_join a WHERE m.ROWID = a.message_id) as num_attachments',
                ]

                # Date columns — convert Apple epoch nanoseconds to ISO datetime
                date_conv = "datetime(m.{col}/1000000000 + strftime('%s','2001-01-01'), 'unixepoch')"
                for col in _DATE_COLUMNS:
                    if col in msg_cols:
                        select_parts.append(f"{date_conv.format(col=col)} as {col}")
                    else:
                        select_parts.append(f"NULL as {col}")

                # Non-date extra columns
                for col in _EXTRA_COLUMNS:
                    if col in msg_cols:
                        select_parts.append(f"m.{col}")
                    else:
                        select_parts.append(f"NULL as {col}")

                select_clause = ',\n                    '.join(select_parts)

                # No tapback filter — all messages including reactions are extracted.
                # Both incoming AND outgoing messages are filtered to mapped contacts.
                query = f"""
                SELECT
                    {select_clause}
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id
                LEFT JOIN chat c ON cmj.chat_id = c.ROWID
                WHERE (h.id IN ({placeholders})
                       OR (m.is_from_me = 1 AND c.chat_identifier IN ({placeholders})))
                ORDER BY m.date ASC
                """

                cursor.execute(query, all_handles + all_handles)

                # Map column names for named access
                col_names = [desc[0] for desc in cursor.description]

                messages = []
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))

                    # Determine if this is a tapback
                    assoc_type = r['associated_message_type']
                    is_tapback = assoc_type is not None and 2000 <= assoc_type <= 3007

                    # Extract text with fallback to attributedBody
                    content = self.extract_text_with_fallback(r['text'], r['attributedBody'])

                    # Skip empty non-tapback messages with no attachments
                    if not content and r['num_attachments'] == 0 and not is_tapback:
                        continue

                    # For tapbacks, generate descriptive content
                    is_removal = False
                    tapback_emoji = ''
                    if is_tapback:
                        is_removal = assoc_type is not None and 3000 <= assoc_type <= 3005
                        tapback_emoji = r.get('associated_message_emoji') or ''
                        if not tapback_emoji:
                            tapback_emoji = TAPBACK_MAP.get(assoc_type) or REMOVE_TAPBACK_MAP.get(assoc_type, '?')
                        action = 'Removed' if is_removal else 'Reacted'
                        content = f"{action} {tapback_emoji} to message"

                    # Determine sender and recipient
                    handle = r['handle']
                    chat_id = r['chat_identifier']
                    if r['is_from_me'] == 1:
                        sender = 'Me'
                        recipient_handle = handle or chat_id
                        recipient = recipient_handle
                        for person_name, person_handles in config.contact_mappings.items():
                            if recipient_handle in person_handles:
                                recipient = person_name
                                break
                    else:
                        recipient = 'Me'
                        sender = handle
                        for person_name, person_handles in config.contact_mappings.items():
                            if handle in person_handles:
                                sender = person_name
                                break

                    timestamp_dt = pd.to_datetime(r['timestamp'], utc=True) if r['timestamp'] else None

                    msg_dict = {
                        # Core fields
                        'message_id': r['message_id'],
                        'guid': r['guid'],
                        'content': content or '',
                        'sender': sender,
                        'recipient': recipient,
                        'timestamp': timestamp_dt,
                        'service': r['service'],
                        'source': 'imessage',

                        # Forensic timestamps
                        'date_read': pd.to_datetime(r['date_read'], utc=True) if r.get('date_read') else None,
                        'date_delivered': pd.to_datetime(r['date_delivered'], utc=True) if r.get('date_delivered') else None,
                        'is_read': bool(r.get('is_read')) if r.get('is_read') is not None else None,
                        'date_edited': pd.to_datetime(r['date_edited'], utc=True) if r.get('date_edited') else None,
                        'date_retracted': pd.to_datetime(r['date_retracted'], utc=True) if r.get('date_retracted') else None,

                        # Threading
                        'reply_to_guid': r.get('reply_to_guid'),
                        'thread_originator_guid': r.get('thread_originator_guid'),
                        'thread_originator_part': r.get('thread_originator_part'),

                        # Content classification
                        'subject': r.get('subject'),
                        'item_type': r.get('item_type'),
                        'is_audio_message': bool(r.get('is_audio_message')) if r.get('is_audio_message') else False,
                        'expressive_send_style_id': r.get('expressive_send_style_id'),
                        'was_detonated': bool(r.get('was_detonated')) if r.get('was_detonated') else False,

                        # Delivery metadata
                        'destination_caller_id': r.get('destination_caller_id'),
                        'was_downgraded': bool(r.get('was_downgraded')) if r.get('was_downgraded') else False,

                        # Emergency and app extensions
                        'is_sos': bool(r.get('is_sos')) if r.get('is_sos') else False,
                        'balloon_bundle_id': r.get('balloon_bundle_id'),

                        # Group management
                        'group_title': r.get('group_title'),
                        'group_action_type': r.get('group_action_type'),

                        # Tapback fields
                        'associated_message_type': assoc_type,
                        'associated_message_guid': r.get('associated_message_guid'),
                        'associated_message_emoji': r.get('associated_message_emoji'),
                        'is_tapback': is_tapback,
                        'is_tapback_removal': is_removal if is_tapback else False,
                        'reactions': [],
                    }

                    # Query attachments
                    if r['num_attachments'] > 0:
                        attachments = self._get_attachments_for_message(cursor, r['message_id'], att_cols)
                        for att in attachments:
                            ext = Path(att['path']).suffix.lower()
                            if ext in self.IMAGE_EXTENSIONS and Path(att['path']).exists():
                                msg_dict['attachment'] = att['path']
                                msg_dict['attachment_name'] = att['name']
                                break
                        if attachments:
                            msg_dict['attachments'] = attachments

                    messages.append(msg_dict)

                # --- Tapback linking pass ---
                self._link_tapbacks(messages)

            finally:
                conn.close()

            # Record extraction with detailed metadata
            tapback_count = sum(1 for m in messages if m.get('is_tapback'))
            edited_count = sum(1 for m in messages if m.get('date_edited'))
            retracted_count = sum(1 for m in messages if m.get('date_retracted'))
            sos_count = sum(1 for m in messages if m.get('is_sos'))

            self.forensic.record_action(
                "imessage_extraction",
                f"Extracted {len(messages)} messages ({tapback_count} tapbacks, "
                f"{edited_count} edited, {retracted_count} retracted/unsent, "
                f"{sos_count} SOS) from iMessage database",
                {
                    "path": str(self.db_path),
                    "message_count": len(messages),
                    "tapback_count": tapback_count,
                    "edited_count": edited_count,
                    "retracted_count": retracted_count,
                    "sos_count": sos_count,
                    "participants": list(config.contact_mappings.keys()),
                }
            )

            logger.info(f"Extracted {len(messages)} iMessages from database")
            return messages

        except Exception as e:
            logger.error(f"Error extracting iMessage data: {e}")
            self.forensic.record_action(
                "imessage_extraction_error",
                f"Failed to extract iMessage data: {str(e)}",
                {"error": str(e)}
            )
            return []

    # ------------------------------------------------------------------
    # Tapback linking
    # ------------------------------------------------------------------

    @staticmethod
    def _link_tapbacks(messages):
        """
        Link tapback messages to their parents.

        For each tapback, enriches its content with a snippet of the parent
        message and adds a reaction entry to the parent's reactions list.
        """
        # Build guid -> message index
        guid_to_msg = {}
        for msg in messages:
            if msg.get('guid'):
                guid_to_msg[msg['guid']] = msg

        for msg in messages:
            if not msg.get('is_tapback'):
                continue
            assoc_guid = msg.get('associated_message_guid')
            if not assoc_guid:
                continue

            # Strip prefix: "p:0/GUID", "p:1/GUID", "bp:GUID" -> GUID
            parent_guid = assoc_guid
            if '/' in assoc_guid:
                parent_guid = assoc_guid.split('/', 1)[1]
            elif assoc_guid.startswith('bp:'):
                parent_guid = assoc_guid[3:]

            parent_msg = guid_to_msg.get(parent_guid)
            if not parent_msg:
                continue

            # Enrich tapback content with parent snippet
            parent_snippet = (parent_msg.get('content') or '')[:100]
            is_removal = msg.get('is_tapback_removal', False)

            # Extract emoji from the already-generated content
            tapback_emoji = msg.get('associated_message_emoji') or ''
            if not tapback_emoji:
                assoc_type = msg.get('associated_message_type', 0)
                tapback_emoji = TAPBACK_MAP.get(assoc_type) or REMOVE_TAPBACK_MAP.get(assoc_type, '?')

            if parent_snippet:
                action = 'Removed' if is_removal else 'Reacted'
                msg['content'] = f'{action} {tapback_emoji} to: "{parent_snippet}"'

            # Add reaction to parent (only for additions, not removals)
            if not is_removal:
                parent_msg['reactions'].append({
                    'type': tapback_emoji,
                    'sender': msg['sender'],
                    'timestamp': msg['timestamp'],
                    'message_id': msg['message_id'],
                })


# Maintain backward compatibility
iMessageExtractor = IMessageExtractor
