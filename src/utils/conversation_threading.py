"""
Conversation threading and message context system.

Groups flat message lists into threaded conversations, provides context
windows around individual messages, and generates conversation summaries.
This addresses the core pain point of not being able to see message context.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ConversationThreader:
    """
    Groups messages into conversations, detects threads, and provides
    context windows around individual messages.

    Messages are expected to be dicts with at minimum:
        message_id, content, sender, recipient, timestamp, source

    Optional analysis fields that are used when available:
        sentiment_score, threat_detected, threat_categories, threat_confidence
    """

    def __init__(self, default_gap_hours: float = 2.0):
        """
        Initialize the threader.

        Args:
            default_gap_hours: Default time gap (in hours) used to split
                conversations into separate threads.
        """
        self.default_gap_hours = default_gap_hours

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _participant_key(sender: str, recipient: str) -> str:
        """
        Return a canonical, order-independent key for a participant pair.

        Uses a sorted tuple so that ("Alice", "Bob") and ("Bob", "Alice")
        both produce the same key.
        """
        pair = tuple(sorted([sender, recipient]))
        return f"{pair[0]} <-> {pair[1]}"

    @staticmethod
    def _parse_timestamp(ts) -> Optional[datetime]:
        """
        Flexibly parse a timestamp that may be a string, datetime, or None.
        Returns a datetime object or None on failure.
        """
        if ts is None:
            return None
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            try:
                return datetime.fromtimestamp(ts)
            except (OSError, ValueError, OverflowError):
                return None
        # String parsing -- try common ISO formats
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
        ):
            try:
                return datetime.strptime(str(ts), fmt)
            except (ValueError, TypeError):
                continue
        logger.debug(f"Could not parse timestamp: {ts}")
        return None

    def _sorted_messages(self, messages: List[Dict]) -> List[Dict]:
        """Return a copy of *messages* sorted by timestamp (earliest first)."""
        def _sort_key(msg):
            dt = self._parse_timestamp(msg.get("timestamp"))
            # Push unparseable timestamps to the end
            return dt if dt is not None else datetime.max
        return sorted(messages, key=_sort_key)

    # ------------------------------------------------------------------
    # 1. Group messages into conversations
    # ------------------------------------------------------------------

    def group_into_conversations(self, messages: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group messages into conversations between the same pair of
        participants.  Within each conversation the messages are sorted
        chronologically.

        Args:
            messages: Flat list of message dicts.

        Returns:
            Dict mapping a participant-pair key (e.g. "Alice <-> Bob") to
            a chronologically-sorted list of messages.
        """
        conversations: Dict[str, List[Dict]] = {}

        for msg in messages:
            sender = msg.get("sender", "Unknown")
            recipient = msg.get("recipient", "Unknown")
            key = self._participant_key(sender, recipient)

            if key not in conversations:
                conversations[key] = []
            conversations[key].append(msg)

        # Sort each conversation chronologically
        for key in conversations:
            conversations[key] = self._sorted_messages(conversations[key])

        return conversations

    # ------------------------------------------------------------------
    # 2. Context window around a single message
    # ------------------------------------------------------------------

    def get_message_context(
        self,
        messages: List[Dict],
        message_id: str,
        window: int = 5,
    ) -> Dict:
        """
        Given a target message_id, return up to *window* messages before
        and after it **within the same conversation** (participant pair).

        Args:
            messages:   Full flat list of messages.
            message_id: The message_id of the target message.
            window:     Number of surrounding messages on each side.

        Returns:
            Dict with keys:
                target       -- the target message dict (or None)
                before       -- list of up to *window* preceding messages
                after        -- list of up to *window* following messages
                conversation_key -- the participant-pair key
                total_in_conversation -- total messages in that conversation
        """
        # Find the target message
        target_msg = None
        for msg in messages:
            if msg.get("message_id") == message_id:
                target_msg = msg
                break

        if target_msg is None:
            return {
                "target": None,
                "before": [],
                "after": [],
                "conversation_key": None,
                "total_in_conversation": 0,
            }

        # Build the conversation this message belongs to
        sender = target_msg.get("sender", "Unknown")
        recipient = target_msg.get("recipient", "Unknown")
        conv_key = self._participant_key(sender, recipient)

        conversations = self.group_into_conversations(messages)
        conv_messages = conversations.get(conv_key, [])

        # Locate the index of the target inside the sorted conversation
        target_index = None
        for idx, msg in enumerate(conv_messages):
            if msg.get("message_id") == message_id:
                target_index = idx
                break

        if target_index is None:
            # Shouldn't happen, but handle gracefully
            return {
                "target": target_msg,
                "before": [],
                "after": [],
                "conversation_key": conv_key,
                "total_in_conversation": len(conv_messages),
            }

        before = conv_messages[max(0, target_index - window):target_index]
        after = conv_messages[target_index + 1:target_index + 1 + window]

        return {
            "target": target_msg,
            "before": before,
            "after": after,
            "conversation_key": conv_key,
            "total_in_conversation": len(conv_messages),
        }

    # ------------------------------------------------------------------
    # 3. Thread detection
    # ------------------------------------------------------------------

    def detect_threads(
        self,
        messages: List[Dict],
        gap_hours: Optional[float] = None,
    ) -> List[Dict]:
        """
        Split conversations into discrete *threads* based on a time-gap
        heuristic.  Messages in the same participant-pair conversation
        that are separated by more than *gap_hours* of silence start a
        new thread.

        Args:
            messages:   Flat list of message dicts.
            gap_hours:  Maximum gap (hours) between consecutive messages
                        before a new thread is started.  Falls back to
                        self.default_gap_hours when None.

        Returns:
            List of thread dicts, each containing:
                thread_id          -- unique string identifier
                conversation_key   -- participant-pair key
                participants       -- list of participant names
                messages           -- chronologically-sorted messages
                start_time         -- earliest timestamp string
                end_time           -- latest timestamp string
                message_count      -- number of messages
        """
        if gap_hours is None:
            gap_hours = self.default_gap_hours

        gap_delta = timedelta(hours=gap_hours)
        conversations = self.group_into_conversations(messages)
        threads: List[Dict] = []
        thread_counter = 0

        for conv_key, conv_messages in conversations.items():
            if not conv_messages:
                continue

            current_thread_msgs: List[Dict] = [conv_messages[0]]
            prev_ts = self._parse_timestamp(conv_messages[0].get("timestamp"))

            for msg in conv_messages[1:]:
                msg_ts = self._parse_timestamp(msg.get("timestamp"))

                # If either timestamp is unparseable, keep in the same thread
                if prev_ts is not None and msg_ts is not None:
                    if (msg_ts - prev_ts) > gap_delta:
                        # Flush the current thread
                        threads.append(
                            self._build_thread_dict(
                                thread_counter, conv_key, current_thread_msgs
                            )
                        )
                        thread_counter += 1
                        current_thread_msgs = []

                current_thread_msgs.append(msg)
                if msg_ts is not None:
                    prev_ts = msg_ts

            # Flush remaining thread
            if current_thread_msgs:
                threads.append(
                    self._build_thread_dict(
                        thread_counter, conv_key, current_thread_msgs
                    )
                )
                thread_counter += 1

        # Sort threads by start_time so the output is chronological
        threads.sort(
            key=lambda t: self._parse_timestamp(t["start_time"]) or datetime.max
        )
        return threads

    def _build_thread_dict(
        self, thread_id: int, conv_key: str, msgs: List[Dict]
    ) -> Dict:
        """Build the standard thread metadata dict."""
        participants = set()
        for m in msgs:
            participants.add(m.get("sender", "Unknown"))
            participants.add(m.get("recipient", "Unknown"))

        timestamps = [
            self._parse_timestamp(m.get("timestamp")) for m in msgs
        ]
        valid_ts = [t for t in timestamps if t is not None]
        start_time = str(min(valid_ts)) if valid_ts else "Unknown"
        end_time = str(max(valid_ts)) if valid_ts else "Unknown"

        return {
            "thread_id": f"thread_{thread_id:04d}",
            "conversation_key": conv_key,
            "participants": sorted(participants),
            "messages": msgs,
            "start_time": start_time,
            "end_time": end_time,
            "message_count": len(msgs),
        }

    # ------------------------------------------------------------------
    # 4. Conversation / thread summaries
    # ------------------------------------------------------------------

    def generate_conversation_summaries(
        self, messages: List[Dict]
    ) -> List[Dict]:
        """
        Generate a summary for every detected thread.

        Each summary contains:
            thread_id, conversation_key, participants, start_time, end_time,
            message_count, avg_sentiment (float or None),
            threats_detected (bool), threat_count (int)

        Args:
            messages: Flat list of message dicts.

        Returns:
            List of summary dicts, one per thread.
        """
        threads = self.detect_threads(messages)
        summaries: List[Dict] = []

        for thread in threads:
            thread_msgs = thread["messages"]

            # Sentiment (use sentiment_score if present)
            sentiment_values = [
                m["sentiment_score"]
                for m in thread_msgs
                if isinstance(m.get("sentiment_score"), (int, float))
            ]
            avg_sentiment = (
                round(sum(sentiment_values) / len(sentiment_values), 4)
                if sentiment_values
                else None
            )

            # Threats
            threat_msgs = [
                m for m in thread_msgs if m.get("threat_detected") is True
            ]
            threat_count = len(threat_msgs)

            summaries.append(
                {
                    "thread_id": thread["thread_id"],
                    "conversation_key": thread["conversation_key"],
                    "participants": ", ".join(thread["participants"]),
                    "start_time": thread["start_time"],
                    "end_time": thread["end_time"],
                    "message_count": thread["message_count"],
                    "avg_sentiment": avg_sentiment,
                    "threats_detected": threat_count > 0,
                    "threat_count": threat_count,
                }
            )

        return summaries

    # ------------------------------------------------------------------
    # 5. Threaded export
    # ------------------------------------------------------------------

    def get_threaded_export(self, messages: List[Dict]) -> Dict:
        """
        Return the full threaded view of all messages, suitable for
        serialisation or further processing.

        Returns:
            Dict with keys:
                total_messages      -- int
                total_threads       -- int
                total_conversations -- int
                threads             -- list of thread dicts (with messages)
                summaries           -- list of summary dicts
        """
        threads = self.detect_threads(messages)
        summaries = self.generate_conversation_summaries(messages)
        conversations = self.group_into_conversations(messages)

        return {
            "total_messages": len(messages),
            "total_threads": len(threads),
            "total_conversations": len(conversations),
            "threads": threads,
            "summaries": summaries,
        }
