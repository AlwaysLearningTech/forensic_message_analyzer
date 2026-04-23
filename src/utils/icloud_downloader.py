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


def _try_fileproviderctl(subdir: Path, timeout: int = 60) -> tuple:
    """Run `fileproviderctl materialize` on a directory. Returns (returncode, output)."""
    try:
        proc = subprocess.run(
            ["fileproviderctl", "materialize", str(subdir)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except FileNotFoundError:
        return -2, "fileproviderctl not found"
    except Exception as exc:
        return -3, str(exc)


def download_messages_attachments(
    attachments_dir: Path,
    forensic_recorder=None,
    timeout_per_dir: int = 600,
) -> Dict[str, int]:
    """Walk attachments_dir and invoke `brctl download` on each subdirectory.

    If brctl fails or recovers 0 files, falls back to `fileproviderctl materialize`
    which targets the File Provider domain used by Messages (brctl targets iCloud Drive).

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
        "fileproviderctl_attempted": False,
        "fileproviderctl_failures": 0,
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

    mid = _scan(attachments_dir)
    brctl_recovered = max(0, mid["files"] - before["files"])

    # If brctl recovered nothing (or failed on most dirs), try fileproviderctl materialize.
    # Messages attachments live under a Files-provider domain, not iCloud Drive, so
    # fileproviderctl is the correct API; brctl targets iCloud Drive only.
    if brctl_recovered == 0 or summary["brctl_failures"] > summary["walked_dirs"] // 2:
        logger.info(
            "[iCloud] brctl recovered 0 files (Messages uses a Files-provider domain, not iCloud Drive). "
            "Falling back to fileproviderctl materialize..."
        )
        summary["fileproviderctl_attempted"] = True
        fp_failures = 0
        for sub in _iter_dirs(attachments_dir):
            rc, out = _try_fileproviderctl(sub, timeout=min(timeout_per_dir, 120))
            if rc == -2:
                # fileproviderctl not available at all — stop trying
                logger.warning("[iCloud] fileproviderctl not found. Skipping.")
                summary["fileproviderctl_failures"] += 1
                break
            if rc != 0:
                fp_failures += 1
                logger.debug(f"[iCloud] fileproviderctl rc={rc} on {sub.name}: {out[:200]}")
        summary["fileproviderctl_failures"] = fp_failures

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
            "[iCloud] Fully-evicted Messages attachments cannot be recovered automatically. "
            "Options:\n"
            "  1. Disable 'Optimize Mac Storage' in System Settings → [Your Name] → iCloud → Drive button.\n"
            "  2. Open affected conversations in Messages.app to trigger manual download.\n"
            "  The forensic report will document how many attachments were unrecoverable."
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
