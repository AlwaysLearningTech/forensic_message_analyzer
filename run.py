#!/usr/bin/env python3
"""
Forensic Message Analyzer - Main Entry Point
Run this script to perform forensic analysis of messages.
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.main import main
from src.config import config

def _pre_run_validation() -> bool:
    """Fail-fast checks to support legal defensibility and smooth runs.
    - Ensures config validates (paths, creds, mappings)
    - Confirms output directory is writable
    - Logs the fact that validation passed for chain-of-custody context
    """
    errors = config.validate()
    # Allow runs without Azure creds if not using those features
    non_blocking = []
    blocking = []
    for err in errors:
        if "Azure OpenAI credentials" in err:
            non_blocking.append(err)
        else:
            blocking.append(err)

    for warn in non_blocking:
        logging.warning(f"Pre-run warning: {warn} (AI features will be disabled)")

    if blocking:
        logging.error("Pre-run validation failed:")
        for err in blocking:
            logging.error(f" - {err}")
        logging.error("Fix the above issues, then re-run. This protects evidentiary integrity (FRE 901/1002).")
        return False

    # Ensure output dir exists and is writable
    try:
        config.output_dir.mkdir(parents=True, exist_ok=True)
        test_file = config.output_dir / ".writable_check"
        test_file.write_text("ok")
        test_file.unlink(missing_ok=True)
    except Exception as e:
        logging.error(f"Output directory not writable: {config.output_dir} ({e})")
        return False

    logging.info("Pre-run validation passed: configuration and output directory verified.")
    return True


def _post_run_verification() -> None:
    """Lightweight verification that key artifacts were produced.
    Does not fail the run, but logs warnings if expected files are missing.
    """
    required_globs = [
        "chain_of_custody_*.json",
        "run_manifest_*.json",
    ]
    missing = []
    for pattern in required_globs:
        if not any(config.output_dir.glob(pattern)):
            missing.append(pattern)
    if missing:
        logging.warning(
            "Post-run verification: expected artifacts not found in %s: %s",
            config.output_dir,
            ", ".join(missing),
        )
    else:
        logging.info("Post-run verification passed: core artifacts present (manifest, chain of custody).")

if __name__ == "__main__":
    try:
        if not _pre_run_validation():
            sys.exit(2)
        success = main()
        try:
            _post_run_verification()
        except Exception as _e:
            logging.warning(f"Post-run verification encountered a non-fatal issue: {_e}")
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logging.info("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
