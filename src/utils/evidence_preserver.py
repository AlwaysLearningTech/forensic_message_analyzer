"""Evidence preservation — hashing, archiving, working copies.

Extracted from ForensicAnalyzer so the orchestrator (main.py) no longer mixes phase control with evidence-preservation bookkeeping. The pre-extraction steps all live here:

  * hash_sources()             — compute and record SHA-256 for every configured source file.
  * preserve_sources()         — zip a copy of every source into run_dir/preserved_sources.zip for chain of custody.
  * route_to_working_copies()  — copy originals into run_dir/working_copies/ and repoint the config so extractors never open originals.
  * apply_contact_automapping() — pull in vCard-based contact identifiers before extraction runs.

Every operation records to the forensic chain. The class holds no state beyond the config and forensic recorder references it was given.
"""

from __future__ import annotations

import logging
import shutil
import zipfile
from pathlib import Path
from typing import Optional


logger = logging.getLogger(__name__)


class EvidencePreserver:
    def __init__(self, config, forensic, integrity, manifest=None):
        self.config = config
        self.forensic = forensic
        self.integrity = integrity
        self.manifest = manifest

    # --- hashing -------------------------------------------------------

    def hash_sources(self):
        """Hash every configured source file and record the hash in the forensic log."""
        logger.info("\n[*] Hashing source files for chain of custody...")
        hashed = 0

        def _hash_one(path: Path, label: str):
            nonlocal hashed
            if not path.exists():
                return
            h = self.forensic.compute_hash(path)
            self.forensic.record_action(
                "source_file_hashed",
                f"Pre-extraction hash of {label}",
                {"file": str(path), "hash": h},
            )
            hashed += 1

        if self.config.messages_db_path:
            _hash_one(Path(self.config.messages_db_path).expanduser(), "iMessage database")

        for attr, label in (
            ("whatsapp_source_dir", "WhatsApp file"),
            ("email_source_dir", "email file"),
            ("teams_source_dir", "Teams file"),
            ("counseling_source_dir", "counseling file"),
        ):
            d = getattr(self.config, attr, None)
            if d:
                p = Path(d).expanduser()
                if p.is_dir():
                    for f in sorted(p.rglob("*")):
                        if f.is_file():
                            _hash_one(f, label)

        ss = getattr(self.config, "screenshot_source_dir", None)
        if ss:
            p = Path(ss).expanduser()
            if p.is_dir():
                for f in sorted(p.iterdir()):
                    if f.is_file():
                        _hash_one(f, "screenshot")

        logger.info(f"    Hashed {hashed} source files")

    # --- archive -------------------------------------------------------

    def preserve_sources(self) -> Optional[Path]:
        """Copy every source file into run_dir/preserved_sources/ and zip it.

        Returns the path to the generated zip or None if nothing was preserved.
        """
        run_dir = Path(self.config.output_dir)
        staging = run_dir / "preserved_sources"
        staging.mkdir(parents=True, exist_ok=True)
        logger.info("\n[*] Preserving source evidence files...")

        preserved_count = 0

        def _copy_and_hash(src: Path, dest: Path, label: str):
            nonlocal preserved_count
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            h = self.forensic.compute_hash(dest)
            self.forensic.record_action(
                "source_preserved",
                f"Preserved {label}: {src.name}",
                {"original": str(src), "preserved": str(dest), "hash": h},
            )
            preserved_count += 1

        # iMessage DB + companions
        for attr in ("messages_db_path", "messages_db_wal", "messages_db_shm"):
            val = getattr(self.config, attr, None)
            if val:
                p = Path(val).expanduser()
                if p.is_file():
                    _copy_and_hash(p, staging / "imessage" / p.name, "iMessage DB")

        # WhatsApp ZIPs only
        wa = self.config.whatsapp_source_dir
        if wa:
            wa_path = Path(wa).expanduser()
            if wa_path.is_dir():
                for f in sorted(wa_path.glob("*.zip")):
                    if f.is_file():
                        _copy_and_hash(f, staging / "whatsapp" / f.name, "WhatsApp ZIP")

        # Email / Teams / counseling / screenshots — recursive
        for attr, sub, label in (
            ("email_source_dir", "email", "email"),
            ("teams_source_dir", "teams", "Teams"),
            ("counseling_source_dir", "counseling", "counseling"),
        ):
            d = getattr(self.config, attr, None)
            if d:
                p = Path(d).expanduser()
                if p.is_dir():
                    for f in sorted(p.rglob("*")):
                        if f.is_file():
                            _copy_and_hash(f, staging / sub / f.relative_to(p), label)

        ss = getattr(self.config, "screenshot_source_dir", None)
        if ss:
            p = Path(ss).expanduser()
            if p.is_dir():
                for f in sorted(p.iterdir()):
                    if f.is_file():
                        _copy_and_hash(f, staging / "screenshots" / f.name, "screenshot")

        if preserved_count == 0:
            logger.info("    No source files found to preserve")
            shutil.rmtree(staging, ignore_errors=True)
            return None

        zip_path = run_dir / "preserved_sources.zip"
        logger.info(f"    Archiving {preserved_count} source files...")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(staging.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(staging))

        archive_hash = self.forensic.compute_hash(zip_path)
        self.forensic.record_action(
            "source_archive_created",
            f"Created source evidence archive with {preserved_count} files",
            {"archive": str(zip_path), "hash": archive_hash, "file_count": preserved_count},
        )
        if self.manifest is not None:
            self.manifest.add_output_file(zip_path)

        shutil.rmtree(staging)
        logger.info(f"    Preserved {preserved_count} source files → {zip_path.name}")
        return zip_path

    # --- working copies -----------------------------------------------

    def route_to_working_copies(self):
        """Repoint every configured source at a hash-verified working copy."""
        run_dir = Path(self.config.output_dir)
        working_root = run_dir / "working_copies"
        working_root.mkdir(parents=True, exist_ok=True)
        logger.info("\n[*] Creating working copies for extraction (originals will not be read)...")

        def _copy_file(src: Path, dest_parent: Path) -> Optional[Path]:
            if not src.exists() or not src.is_file():
                return None
            dest_parent.mkdir(parents=True, exist_ok=True)
            dest = dest_parent / src.name
            try:
                shutil.copy2(src, dest)
            except Exception as exc:
                self.forensic.record_error("working_copy_failed", f"Failed to copy {src} -> {dest}: {exc}", {"source": str(src)})
                return None
            src_hash = self.forensic.compute_hash(src)
            dest_hash = self.forensic.compute_hash(dest)
            if src_hash != dest_hash:
                self.forensic.record_error("working_copy_hash_mismatch", f"Working copy hash mismatch for {src}", {"source": str(src), "src_hash": src_hash, "dest_hash": dest_hash})
                dest.unlink(missing_ok=True)
                return None
            self.forensic.record_action("working_copy_created", f"Working copy verified for {src.name}", {"source": str(src), "copy": str(dest), "hash": src_hash})
            return dest

        def _copy_dir(src: Path, dest_parent: Path) -> Optional[Path]:
            if not src.exists() or not src.is_dir():
                return None
            dest_parent.mkdir(parents=True, exist_ok=True)
            dest_root = dest_parent / src.name
            count = 0
            for f in src.rglob("*"):
                if not f.is_file():
                    continue
                rel = f.relative_to(src)
                copied = _copy_file(f, dest_root / rel.parent)
                if copied is not None:
                    count += 1
            return dest_root if count > 0 else None

        for attr in ("messages_db_path", "messages_db_wal", "messages_db_shm"):
            val = getattr(self.config, attr, None)
            if not val:
                continue
            src = Path(val).expanduser()
            copied = _copy_file(src, working_root / "imessage")
            if copied is not None:
                setattr(self.config, attr, str(copied))

        for attr, subdir in (
            ("email_source_dir", "email"),
            ("teams_source_dir", "teams"),
            ("whatsapp_source_dir", "whatsapp"),
            ("screenshot_source_dir", "screenshots"),
            ("counseling_source_dir", "counseling"),
        ):
            val = getattr(self.config, attr, None)
            if not val:
                continue
            src = Path(val).expanduser()
            copied = _copy_dir(src, working_root / subdir) if src.is_dir() else _copy_file(src, working_root / subdir)
            if copied is not None:
                setattr(self.config, attr, str(copied))

        logger.info(f"    Working copies routed under {working_root}")

    # --- contact auto-mapping -----------------------------------------

    def apply_contact_automapping(self):
        """Merge vCard-derived contacts into config.contact_mappings."""
        vcard_dir = getattr(self.config, "contacts_vcard_dir", None)
        if not vcard_dir:
            return

        from .contact_automapper import load_vcards_from_dir, merge_into_config

        mapping = load_vcards_from_dir(Path(vcard_dir))
        if not mapping:
            self.forensic.record_action(
                "contact_automap_skipped",
                f"No vCards found under {vcard_dir}",
                {"dir": vcard_dir},
            )
            return

        added = merge_into_config(self.config, mapping)
        self.forensic.record_action(
            "contact_automap_applied",
            f"Auto-mapped {len(added)} contact(s) from vCards under {vcard_dir}",
            {"dir": vcard_dir, "entries": {k: v for k, v in added.items()}},
        )
        logger.info(f"\n[*] Auto-mapped {len(added)} contact(s) from vCards")


__all__ = ["EvidencePreserver"]
