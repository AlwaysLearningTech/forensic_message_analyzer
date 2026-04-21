"""Force iCloud-evicted attachments back to disk via `brctl download`.

Messages in iCloud can evict attachments without leaving `.icloud` placeholders, so
walking the directory and `brctl download`-ing each subdirectory is the only local
recovery path. Fully-evicted files that iCloud has already purged from the device
cannot be retrieved this way — the user must disable "Optimize Mac Storage" in
Messages and wait for a full sync, or open the affected threads in Messages.app.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


def download_messages_attachments(
    attachments_dir: Path,
    forensic_recorder=None,
    timeout_per_dir: int = 600,
) -> Dict[str, int]:
    """Walk attachments_dir and invoke `brctl download` on each subdirectory.

    Returns a summary dict with counts of directories walked, files present before,
    files present after, and files still missing. The forensic recorder (if provided)
    receives a single `icloud_attachment_download` action carrying the summary.
    """
    attachments_dir = Path(attachments_dir)
    summary = {
        "walked_dirs": 0,
        "files_before": 0,
        "files_after": 0,
        "recovered": 0,
        "still_missing": 0,
        "brctl_failures": 0,
    }

    if not attachments_dir.exists():
        logger.warning(f"[iCloud] Attachments dir does not exist: {attachments_dir}")
        if forensic_recorder:
            forensic_recorder.record_action(
                "icloud_attachment_download",
                "Attachments directory missing — skipped",
                {"attachments_dir": str(attachments_dir), **summary},
            )
        return summary

    logger.info(f"[iCloud] Pre-scanning {attachments_dir} ...")
    before = _scan(attachments_dir)
    summary["files_before"] = before["files"]
    icloud_stubs_before = before["icloud_stubs"]
    logger.info(
        f"[iCloud] Found {before['files']} real files, {icloud_stubs_before} .icloud stubs "
        f"across {before['dirs']} directories"
    )

    logger.info("[iCloud] Running brctl download on each subdirectory (this may take a while)...")
    for sub in _iter_dirs(attachments_dir):
        summary["walked_dirs"] += 1
        try:
            result = subprocess.run(
                ["brctl", "download", str(sub)],
                capture_output=True,
                text=True,
                timeout=timeout_per_dir,
            )
            if result.returncode != 0:
                summary["brctl_failures"] += 1
                logger.debug(f"[iCloud] brctl rc={result.returncode} on {sub}: {result.stderr.strip()[:200]}")
        except subprocess.TimeoutExpired:
            summary["brctl_failures"] += 1
            logger.warning(f"[iCloud] brctl timed out on {sub}")
        except FileNotFoundError:
            logger.error("[iCloud] `brctl` not found. This feature requires macOS.")
            if forensic_recorder:
                forensic_recorder.record_action(
                    "icloud_attachment_download",
                    "brctl not available — aborted",
                    {"attachments_dir": str(attachments_dir), **summary},
                )
            return summary

    after = _scan(attachments_dir)
    summary["files_after"] = after["files"]
    summary["recovered"] = max(0, after["files"] - before["files"])
    summary["still_missing"] = after["icloud_stubs"]

    logger.info(
        f"[iCloud] Download pass complete: {summary['recovered']} recovered, "
        f"{summary['still_missing']} still missing (.icloud stubs remaining), "
        f"{summary['brctl_failures']} brctl failures"
    )
    if summary["still_missing"] > 0:
        logger.info(
            "[iCloud] Fully-evicted Messages attachments cannot be recovered with brctl alone. "
            "Disable 'Optimize Mac Storage' in System Settings → Apple ID → iCloud → Messages "
            "and wait for the full sync, or open the affected conversations in Messages.app."
        )

    if forensic_recorder:
        forensic_recorder.record_action(
            "icloud_attachment_download",
            "Forced iCloud download pass on Messages attachments",
            {"attachments_dir": str(attachments_dir), **summary},
        )

    return summary


def _iter_dirs(root: Path):
    """Yield root plus every descendant directory."""
    yield root
    for p in root.rglob("*"):
        if p.is_dir():
            yield p


def _scan(root: Path) -> Dict[str, int]:
    """Count real files, .icloud stubs, and directories under root."""
    files = 0
    stubs = 0
    dirs = 0
    for p in root.rglob("*"):
        if p.is_dir():
            dirs += 1
        elif p.is_file():
            if p.name.endswith(".icloud") or p.name.startswith("."):
                if p.name.endswith(".icloud"):
                    stubs += 1
            else:
                files += 1
    return {"files": files, "icloud_stubs": stubs, "dirs": dirs}
