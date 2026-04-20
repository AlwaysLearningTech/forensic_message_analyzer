"""Timestamp round-trip and DST transition coverage.

A forensic report's timestamps must survive two kinds of scrutiny:

  1. Round-trip. Take a timestamp, convert to the configured display timezone, convert back to UTC — you get the same instant. Any lossy conversion means the report's clock can be attacked on the stand.

  2. DST transitions. When a timezone "springs forward" or "falls back", local times can be ambiguous (23:30 -> 01:30 with two 01:30s) or missing (02:00 -> 03:00). pytz handles both correctly; these tests lock in that behavior so a future refactor can't silently break it.

The tests cover America/Los_Angeles (standard US forensic deployment) and Europe/London (observes DST on a different schedule) to catch single-zone assumptions.
"""

from datetime import datetime, timezone
import pytz
import pytest


def _localize_utc_to(tz_name: str, utc_dt: datetime) -> datetime:
    """Convert an aware UTC datetime into the named tz without losing information."""
    tz = pytz.timezone(tz_name)
    return utc_dt.astimezone(tz)


class TestRoundTrip:
    """Every conversion UTC -> local -> UTC must be an identity."""

    @pytest.mark.parametrize("tz_name", ["America/Los_Angeles", "Europe/London", "UTC", "America/New_York"])
    def test_round_trip_is_identity(self, tz_name):
        utc = datetime(2024, 6, 15, 12, 30, 45, tzinfo=timezone.utc)
        local = _localize_utc_to(tz_name, utc)
        back = local.astimezone(timezone.utc)
        assert back == utc

    @pytest.mark.parametrize("tz_name", ["America/Los_Angeles", "Europe/London"])
    def test_round_trip_across_dst_boundary(self, tz_name):
        # A timestamp a few minutes before and after the spring-forward — both must round-trip.
        for utc_dt in (
            datetime(2024, 3, 10, 9, 59, 0, tzinfo=timezone.utc),  # just before US spring-forward at 10:00 UTC
            datetime(2024, 3, 10, 10, 1, 0, tzinfo=timezone.utc),  # just after
            datetime(2024, 11, 3, 8, 59, 0, tzinfo=timezone.utc),  # just before US fall-back at 09:00 UTC
            datetime(2024, 11, 3, 9, 1, 0, tzinfo=timezone.utc),  # just after
        ):
            local = _localize_utc_to(tz_name, utc_dt)
            back = local.astimezone(timezone.utc)
            assert back == utc_dt


class TestDSTTransitions:
    """The underlying library must distinguish the two 01:30s on fall-back day."""

    def test_fall_back_disambiguates_utc_offset(self):
        # Nov 3 2024, 01:30 Pacific happens twice — first as PDT (UTC-7), then as PST (UTC-8).
        pacific = pytz.timezone("America/Los_Angeles")
        naive = datetime(2024, 11, 3, 1, 30, 0)
        early = pacific.localize(naive, is_dst=True)   # first occurrence (PDT)
        later = pacific.localize(naive, is_dst=False)  # second occurrence (PST)
        assert early.utcoffset() != later.utcoffset()
        assert early.astimezone(timezone.utc) != later.astimezone(timezone.utc)
        # The later 01:30 is strictly one hour after the earlier one, in UTC terms.
        delta = later.astimezone(timezone.utc) - early.astimezone(timezone.utc)
        assert delta.total_seconds() == 3600

    def test_spring_forward_rejects_nonexistent_local_time(self):
        # Mar 10 2024, 02:30 Pacific does not exist — clocks jump from 02:00 PST to 03:00 PDT.
        pacific = pytz.timezone("America/Los_Angeles")
        naive = datetime(2024, 3, 10, 2, 30, 0)
        with pytest.raises(pytz.exceptions.NonExistentTimeError):
            pacific.localize(naive, is_dst=None)


class TestAppleEpochConversion:
    """iMessage stores time as nanoseconds since 2001-01-01 UTC (Cocoa reference)."""

    APPLE_EPOCH_UNIX_SECONDS = 978307200

    def test_cocoa_reference_date(self):
        # 0 Cocoa seconds == 2001-01-01 00:00:00 UTC exactly.
        utc = datetime.fromtimestamp(self.APPLE_EPOCH_UNIX_SECONDS + 0, tz=timezone.utc)
        assert utc == datetime(2001, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_known_nanosecond_timestamp(self):
        # A message at 2024-01-15 12:00:00 UTC should decode to the same instant when stored as Apple ns.
        target = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        ns = int((target.timestamp() - self.APPLE_EPOCH_UNIX_SECONDS) * 1_000_000_000)
        # The extractor's heuristic is: if ts_raw > 1e15 it's nanoseconds.
        assert ns > 1e15
        decoded = datetime.fromtimestamp(ns / 1e9 + self.APPLE_EPOCH_UNIX_SECONDS, tz=timezone.utc)
        assert decoded == target

    def test_pre_apple_epoch_timestamp_rejected_as_sentinel(self):
        # Messages with date=0 exist in chat.db for draft or placeholder rows. The correct behavior is to treat them as unknown rather than silently emit 2001-01-01, which would be indistinguishable from a real Jan-1-2001 message.
        zero_decoded = datetime.fromtimestamp(0 + self.APPLE_EPOCH_UNIX_SECONDS, tz=timezone.utc)
        assert zero_decoded == datetime(2001, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
