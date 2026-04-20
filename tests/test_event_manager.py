"""Round-trip coverage for the manual-events workflow.

Locks in the append-only semantics: edits and removals write new records rather than mutating prior ones, so opposing counsel can always trace a final event back to its original form.
"""

import os
from pathlib import Path

import pytest

os.environ.setdefault("EXAMINER_NAME", "Test Examiner")


def _make_manager(tmp_path: Path):
    from src.forensic_utils import ForensicRecorder
    from src.review.event_manager import EventManager

    review_dir = tmp_path / "review"
    output_dir = tmp_path / "output"
    recorder = ForensicRecorder(output_dir)
    return EventManager(
        review_dir=review_dir,
        session_id="session_20260101_000000",
        forensic_recorder=recorder,
    )


def test_add_lists_and_edits_retain_prior_record(tmp_path):
    em = _make_manager(tmp_path)

    created = em.add_event(
        title="September 4 dispute",
        start_message_id="msg-001",
        end_message_id="msg-004",
        category="incident",
        severity="high",
        description="original description",
    )
    assert created["title"] == "September 4 dispute"
    assert len(em.active_events()) == 1

    em.edit_event(
        created["event_id"],
        description="expanded after second read",
        reason="added context",
    )
    active = em.active_events()
    assert len(active) == 1
    assert active[0]["description"] == "expanded after second read"
    # Prior record is preserved, just marked superseded.
    history = em.all_records()
    assert len(history) == 2
    assert history[0]["superseded_by"]
    assert history[1]["amended"] is True


def test_edit_requires_reason(tmp_path):
    em = _make_manager(tmp_path)
    created = em.add_event(
        title="X", start_message_id="m1", end_message_id="m2", severity="low",
    )
    with pytest.raises(ValueError):
        em.edit_event(created["event_id"], title="Y")


def test_remove_appends_and_hides(tmp_path):
    em = _make_manager(tmp_path)
    created = em.add_event(
        title="To be removed",
        start_message_id="m1", end_message_id="m3",
    )
    em.remove_event(created["event_id"], reason="was duplicate")
    assert em.active_events() == []
    # Full history still shows the original add and the removal record.
    assert len(em.all_records()) == 2
    assert em.all_records()[-1]["removed_at"]


def test_category_and_severity_validated(tmp_path):
    em = _make_manager(tmp_path)
    with pytest.raises(ValueError):
        em.add_event(
            title="X", start_message_id="a", end_message_id="b",
            category="bogus", severity="medium",
        )
    with pytest.raises(ValueError):
        em.add_event(
            title="X", start_message_id="a", end_message_id="b",
            category="incident", severity="super-critical",
        )


def test_requires_examiner(monkeypatch, tmp_path):
    from src.forensic_utils import ForensicRecorder
    from src.review.event_manager import EventManager

    # Force examiner_name blank — Config falls through the config attribute, so the manager should reject.
    monkeypatch.delenv("EXAMINER_NAME", raising=False)
    recorder = ForensicRecorder(tmp_path / "out")

    class BareConfig:
        review_dir = str(tmp_path / "review")
        examiner_name = ""

    em = EventManager(
        review_dir=tmp_path / "review",
        session_id="s",
        config=BareConfig(),
        forensic_recorder=recorder,
    )
    with pytest.raises(ValueError):
        em.add_event(
            title="X", start_message_id="a", end_message_id="b",
        )
