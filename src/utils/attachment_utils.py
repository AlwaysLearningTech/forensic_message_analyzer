"""Attachment compression helpers used by _preserve_attachments.

Policy (forensic rationale):
  HEIC           — passes through unchanged. iPhone-native format; re-encoding
                   would be a double derivative (lossy AND format-changing).
  PNG / JPEG     — re-encoded only if the source exceeds the configured size
                   threshold; longest edge optionally resized.
  Other types    — passed through unchanged.

Compression happens BEFORE create_working_copy so the run manifest's recorded
hash matches what is actually on disk. The forensic log records both the
original and the compressed hashes, tying the derivative back to the source.

Originals at ~/Library/Messages/Attachments/ are never modified — only the
output/attachments/ working copies.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_COMPRESSIBLE_EXTS = {".png", ".jpg", ".jpeg"}


def should_compress(path: Path, config) -> bool:
    """Return True when the file is a PNG/JPEG over the configured size threshold."""
    if not getattr(config, "compress_attachments", False):
        return False
    ext = path.suffix.lower()
    if ext not in _COMPRESSIBLE_EXTS:
        return False
    try:
        size_mb = path.stat().st_size / (1024 * 1024)
    except OSError:
        return False
    return size_mb >= float(getattr(config, "attachment_compress_threshold_mb", 5.0))


def compress_image(src: Path, dest: Path, config) -> Optional[Dict[str, object]]:
    """Compress src → dest (JPEG). Returns a summary dict, or None on failure.

    The output is always written as JPEG. PNG input is re-encoded to JPEG since
    PNG's lossless compression is what makes it large in the first place.
    """
    try:
        from PIL import Image, ImageOps
    except ImportError:
        logger.warning("Pillow not installed — compression requested but unavailable. Copy original.")
        return None

    original_hash = _sha256(src)
    original_size = src.stat().st_size

    try:
        with Image.open(src) as im:
            im = ImageOps.exif_transpose(im)
            if im.mode not in ("RGB", "L"):
                im = im.convert("RGB")
            max_dim = int(getattr(config, "attachment_max_dimension_px", 2048))
            if max_dim > 0 and (im.width > max_dim or im.height > max_dim):
                im.thumbnail((max_dim, max_dim), Image.LANCZOS)
            dest.parent.mkdir(parents=True, exist_ok=True)
            quality = int(getattr(config, "attachment_jpeg_quality", 75))
            im.save(dest, format="JPEG", quality=quality, optimize=True, progressive=True)
    except Exception as e:
        logger.warning(f"[compress] {src.name}: {e}")
        return None

    compressed_hash = _sha256(dest)
    compressed_size = dest.stat().st_size

    return {
        "original_path": str(src),
        "compressed_path": str(dest),
        "original_hash": original_hash,
        "compressed_hash": compressed_hash,
        "original_size": original_size,
        "compressed_size": compressed_size,
        "ratio": round(compressed_size / original_size, 3) if original_size else None,
        "format": "JPEG",
        "jpeg_quality": int(getattr(config, "attachment_jpeg_quality", 75)),
        "max_dimension_px": int(getattr(config, "attachment_max_dimension_px", 2048)),
    }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
