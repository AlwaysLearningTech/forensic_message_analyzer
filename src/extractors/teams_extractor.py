"""
Microsoft Teams personal export extraction module.
Processes TAR archives containing messages.json from Teams personal exports.
"""

import re
import json
import tarfile
import logging
from html import unescape
from pathlib import Path
from typing import List, Dict, Optional, Any

from ..config import Config
from ..forensic_utils import ForensicRecorder, ForensicIntegrity

config = Config()

logger = logging.getLogger(__name__)

# Message types that contain actual user content
_CONTENT_TYPES = frozenset({
    'Text',
    'RichText',
    'RichText/Html',
    'RichText/UriObject',
})

# Regex to strip HTML tags
_HTML_TAG_RE = re.compile(r'<[^>]+>')


class TeamsExtractor:
    """
    Extracts messages from a Microsoft Teams personal export.

    The export is a TAR archive containing ``messages.json`` with the
    structure::

        {
          "userId": "8:live:tanikir",
          "exportDate": "...",
          "conversations": [ ... ]
        }

    Each conversation contains a ``MessageList`` of message objects.
    """

    def __init__(
        self,
        source_dir: str,
        forensic_recorder: ForensicRecorder,
        forensic_integrity: ForensicIntegrity,
        third_party_registry=None,
    ):
        self.source_dir = Path(source_dir) if source_dir else None
        self.forensic = forensic_recorder
        self.integrity = forensic_integrity
        self.third_party_registry = third_party_registry

        # Build a lower-cased lookup for mapped identifiers → person name
        self._id_to_person: Dict[str, str] = {}
        for person_name, identifiers in config.contact_mappings.items():
            for ident in identifiers:
                self._id_to_person[ident.strip().lower()] = person_name

        # Also build a set of all mapped person names (lowered) for display-name matching
        self._person_names_lower: Dict[str, str] = {}
        for person_name in config.contact_mappings:
            self._person_names_lower[person_name.strip().lower()] = person_name

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_all(self) -> List[Dict[str, Any]]:
        """Extract all relevant messages from TAR exports in source_dir."""
        if not self.source_dir or not self.source_dir.exists():
            logger.warning(f"Teams source directory not found: {self.source_dir}")
            return []

        all_messages: List[Dict[str, Any]] = []

        tar_files = list(self.source_dir.glob("*.tar"))
        if not tar_files:
            logger.warning(f"No TAR files found in {self.source_dir}")
            return []

        for tar_path in tar_files:
            messages = self._extract_from_tar(tar_path)
            all_messages.extend(messages)

        if all_messages:
            all_messages.sort(key=lambda m: m['timestamp'])
            self.forensic.record_action(
                "teams_extraction",
                f"Extracted {len(all_messages)} Teams messages from {len(tar_files)} archive(s)",
                {"archive_count": len(tar_files), "message_count": len(all_messages)},
            )
            logger.info(f"Extracted {len(all_messages)} Teams messages")

        return all_messages

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_from_tar(self, tar_path: Path) -> List[Dict[str, Any]]:
        """Open a TAR archive, parse messages.json, return messages."""
        try:
            with tarfile.open(tar_path, 'r') as tar:
                member = None
                for m in tar.getmembers():
                    if m.name.endswith('messages.json'):
                        member = m
                        break
                if member is None:
                    logger.warning(f"No messages.json in {tar_path.name}")
                    return []
                f = tar.extractfile(member)
                if f is None:
                    logger.warning(f"Could not read messages.json from {tar_path.name}")
                    return []
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read TAR {tar_path.name}: {e}")
            self.forensic.record_action(
                "teams_tar_error",
                f"Failed to read Teams archive: {tar_path.name}: {e}",
                {"file": str(tar_path), "error": str(e)},
            )
            return []

        user_id: str = data.get('userId', '')
        conversations: list = data.get('conversations', [])

        # Determine the person name for the export owner
        owner_person = self._resolve_user_id(user_id)

        all_messages: List[Dict[str, Any]] = []

        for conv in conversations:
            msgs = self._process_conversation(conv, user_id, owner_person)
            all_messages.extend(msgs)

        self.forensic.record_action(
            "teams_tar_parsed",
            f"Parsed {tar_path.name}: {len(conversations)} conversations, "
            f"{len(all_messages)} relevant messages",
            {"file": str(tar_path), "conversations": len(conversations),
             "messages": len(all_messages)},
        )
        return all_messages

    def _process_conversation(
        self, conv: dict, user_id: str, owner_person: str,
    ) -> List[Dict[str, Any]]:
        """Process a single conversation, returning messages involving mapped persons."""
        conv_id = conv.get('id', '')
        conv_display = conv.get('displayName', '') or ''
        message_list = conv.get('MessageList', [])

        if not message_list:
            return []

        # Determine who participates in this conversation.
        # We consider it relevant if at least one mapped person is involved.
        members = self._get_conversation_members(conv, message_list, user_id, owner_person)
        mapped_members = {m for m in members if m != 'Unknown'}

        # At minimum the export owner participates
        if owner_person and owner_person != 'Unknown':
            mapped_members.add(owner_person)

        # Check if any mapped person is in this conversation
        mapped_in_conv = {m for m in mapped_members
                         if m in config.contact_mappings or m == 'Me'}
        if not mapped_in_conv:
            return []

        # Determine the "other person" for 1:1 conversations.
        # In 1:1, unidentified senders can be inferred.
        thread_props = conv.get('threadProperties') or {}
        member_count = 2  # default assumption
        try:
            member_count = int(thread_props.get('membercount', 2))
        except (TypeError, ValueError):
            pass

        is_one_to_one = member_count == 2
        # In a 1:1 conversation, the other person is whoever isn't the owner
        other_person = None
        if is_one_to_one:
            non_owner = mapped_members - {owner_person, 'Me'}
            if len(non_owner) == 1:
                other_person = non_owner.pop()
            elif conv_display:
                # Try to resolve the conversation display name
                other_person = self._resolve_display_name(conv_display)

        messages: List[Dict[str, Any]] = []
        for msg in message_list:
            parsed = self._parse_message(msg, user_id, owner_person,
                                         is_one_to_one, other_person, conv_id)
            if parsed:
                messages.append(parsed)

        return messages

    def _parse_message(
        self,
        msg: dict,
        user_id: str,
        owner_person: str,
        is_one_to_one: bool,
        other_person: Optional[str],
        conv_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Parse a single Teams message dict into our standard format."""
        msg_type = msg.get('messagetype', '')
        if msg_type not in _CONTENT_TYPES:
            return None

        content = msg.get('content', '')
        if not content or not content.strip():
            return None

        # Strip HTML tags from RichText/Html
        if msg_type in ('RichText/Html', 'RichText', 'RichText/UriObject'):
            content = _HTML_TAG_RE.sub('', content)
            content = unescape(content)

        content = content.strip()
        if not content:
            return None

        # Determine sender
        msg_from = msg.get('from')
        display_name = msg.get('displayName')

        if msg_from and msg_from == user_id:
            # Export owner sent this
            sender = owner_person or 'Me'
        elif display_name:
            # Another person sent this (name known)
            sender = self._resolve_display_name(display_name)
        elif is_one_to_one and other_person:
            # Infer sender in 1:1: must be the other person
            sender = other_person
        else:
            # Cannot identify sender
            sender = 'Unknown'

        # Determine recipient (simplified: in 1:1 it's the other party)
        if sender == owner_person or sender == 'Me':
            recipient = other_person or 'Unknown'
        elif is_one_to_one:
            recipient = owner_person or 'Me'
        else:
            # Group chat: recipient is the conversation itself
            recipient = other_person or 'Unknown'

        # Skip if neither sender nor recipient is a mapped person
        sender_mapped = sender in config.contact_mappings or sender == 'Me'
        recipient_mapped = recipient in config.contact_mappings or recipient == 'Me'
        if not sender_mapped and not recipient_mapped:
            return None

        # Register unmapped contacts
        if self.third_party_registry:
            if not sender_mapped and sender != 'Unknown':
                self.third_party_registry.register(
                    sender, source='teams', context=f"conversation:{conv_id}",
                )
            if not recipient_mapped and recipient != 'Unknown':
                self.third_party_registry.register(
                    recipient, source='teams', context=f"conversation:{conv_id}",
                )

        timestamp = msg.get('originalarrivaltime', '')

        return {
            'message_id': f"teams_{msg.get('id', '')}",
            'timestamp': timestamp,
            'sender': sender,
            'recipient': recipient,
            'content': content,
            'source': 'teams',
            'conversation_id': conv_id,
        }

    # ------------------------------------------------------------------
    # Name / ID resolution
    # ------------------------------------------------------------------

    def _resolve_user_id(self, user_id: str) -> str:
        """
        Map a Teams userId (e.g. ``8:live:tanikir``) to a person name.

        Strategy: extract the local part from ``8:live:<username>`` and check
        if it matches the local part of any email in the contact mappings.
        Also check the userId directly against mappings.
        """
        if not user_id:
            return 'Me'

        # Direct lookup
        low = user_id.strip().lower()
        if low in self._id_to_person:
            return self._id_to_person[low]

        # Extract local part: "8:live:tanikir" → "tanikir"
        parts = user_id.split(':')
        local_part = parts[-1].lower() if parts else ''

        if not local_part:
            return 'Me'

        # Check against email local parts in mappings
        for person_name, identifiers in config.contact_mappings.items():
            for ident in identifiers:
                ident_low = ident.strip().lower()
                if '@' in ident_low:
                    email_local = ident_low.split('@')[0]
                    if email_local == local_part:
                        return person_name
                # Also check direct local-part match
                if ident_low == local_part:
                    return person_name

        return 'Me'

    def _resolve_display_name(self, name: str) -> str:
        """
        Resolve a display name to a mapped person name, or return it as-is.
        """
        if not name:
            return 'Unknown'

        stripped = name.strip()
        low = stripped.lower()

        # Check person names directly (case-insensitive)
        if low in self._person_names_lower:
            return self._person_names_lower[low]

        # Check against all mapped identifiers
        if low in self._id_to_person:
            return self._id_to_person[low]

        return stripped

    def _get_conversation_members(
        self, conv: dict, message_list: list, user_id: str, owner_person: str,
    ) -> set:
        """
        Determine who participates in a conversation by examining:
        1. threadProperties.members
        2. Conversation displayName
        3. Identified senders in the message list
        """
        members: set = set()

        # 1. threadProperties.members (comma-separated or list)
        thread_props = conv.get('threadProperties') or {}
        raw_members = thread_props.get('members')
        if isinstance(raw_members, str):
            for m in raw_members.split(','):
                resolved = self._resolve_display_name(m.strip())
                if resolved != 'Unknown':
                    members.add(resolved)
        elif isinstance(raw_members, list):
            for m in raw_members:
                name = m if isinstance(m, str) else str(m)
                resolved = self._resolve_display_name(name.strip())
                if resolved != 'Unknown':
                    members.add(resolved)

        # 2. Conversation displayName
        conv_display = conv.get('displayName', '') or ''
        if conv_display:
            resolved = self._resolve_display_name(conv_display)
            if resolved != 'Unknown':
                members.add(resolved)

        # 3. Identified senders from first N messages (avoid scanning all)
        scan_limit = min(50, len(message_list))
        for msg in message_list[:scan_limit]:
            dn = msg.get('displayName')
            if dn:
                resolved = self._resolve_display_name(dn)
                if resolved != 'Unknown':
                    members.add(resolved)

        return members
