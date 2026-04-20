#!/usr/bin/env python3
"""
Forensic Message Analyzer - Main Entry Point
Run this script to perform forensic analysis of messages.

Usage:
    python3 run.py                    # Phases 1-3: extract, analyze, review (then stop)
    python3 run.py --finalize         # Phases 4-7: behavioral, AI, reports, docs
    python3 run.py --finalize <path>  # Same, with explicit run directory
    python3 run.py --resume           # Resume interrupted review session
    python3 run.py --resume <path>    # Resume review in specific run directory
"""

import sys
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.main import main, finalize
from src.config import Config

# Create config instance
config = Config()

# Route library logs to stdout so progress banners (previously print()) are visible by default. Libraries should not assume stdout ownership; the CLI tool owns formatting here.
_log_level = getattr(logging, (config.log_level or "INFO").upper(), logging.INFO)
logging.basicConfig(
    level=_log_level,
    format="%(message)s",
    stream=sys.stdout,
)


def _find_latest_run_dir(base_dir: Path) -> Optional[Path]:
    """Find the most recent run directory with a pipeline state file."""
    run_dirs = sorted(base_dir.glob("run_*"), reverse=True)
    for d in run_dirs:
        state_file = d / "pipeline_state.json"
        if state_file.exists():
            return d
    return None


def _pre_run_validation() -> bool:
    """Fail-fast checks to support legal defensibility and smooth runs.
    - Ensures config validates (paths, creds, mappings)
    - Confirms output directory is writable
    - Logs the fact that validation passed for chain-of-custody context
    """
    is_valid, errors = config.validate()

    # Allow runs without Azure creds if not using those features
    non_blocking = []
    blocking = []
    for err in errors:
        if "API key" in err:
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
        output_path = Path(config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        test_file = output_path / ".writable_check"
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
    output_path = Path(config.output_dir)
    missing = []
    for pattern in required_globs:
        if not any(output_path.glob(pattern)):
            missing.append(pattern)
    if missing:
        logging.warning(
            "Post-run verification: expected artifacts not found in %s: %s",
            config.output_dir,
            ", ".join(missing),
        )
    else:
        logging.info("Post-run verification passed: core artifacts present (manifest, chain of custody).")


def _resolve_run_dir(path_arg: str) -> Path:
    """Resolve a run directory from a CLI argument or auto-detect the latest."""
    if path_arg != "auto":
        run_dir = Path(path_arg)
        if not run_dir.is_dir():
            logging.error(f"Run directory does not exist: {run_dir}")
            sys.exit(2)
        return run_dir

    # Auto-detect: find the latest run_* directory with pipeline state
    run_dir = _find_latest_run_dir(Path(config.output_dir))
    if not run_dir:
        logging.error(
            f"No run directory with pipeline state found in {config.output_dir}.\n"
            f"Specify the run directory explicitly: python3 run.py --finalize <path>"
        )
        sys.exit(2)

    # Show which directory was auto-detected
    state_file = run_dir / "pipeline_state.json"
    with open(state_file) as f:
        state = json.load(f)
    logging.info(f"Auto-detected run directory: {run_dir.name} ({state.get('timestamp', 'unknown')})")
    return run_dir


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Forensic Message Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Workflow:\n"
            "  1. Run 'python3 run.py' to extract, analyze, and review messages (Phases 1-3)\n"
            "  2. Complete manual review when prompted\n"
            "  3. Run 'python3 run.py --finalize' to generate reports (Phases 4-7)\n"
        ),
    )
    parser.add_argument(
        "--finalize", nargs="?", const="auto", default=None, metavar="RUN_DIR",
        help="Run post-review phases (4-7). Optionally specify run directory path."
    )
    parser.add_argument(
        "--resume", nargs="?", const="auto", default=None, metavar="RUN_DIR",
        help="Resume interrupted review session. Optionally specify run directory path."
    )
    args = parser.parse_args()

    try:
        if not _pre_run_validation():
            sys.exit(2)

        if args.finalize is not None:
            # --finalize mode: load existing run directory, run Phases 4-7
            run_dir = _resolve_run_dir(args.finalize)
            config.output_dir = str(run_dir)
            success = finalize(config)
            try:
                _post_run_verification()
            except Exception as _e:
                logging.warning(f"Post-run verification encountered a non-fatal issue: {_e}")
            sys.exit(0 if success else 1)

        elif args.resume is not None:
            # --resume mode: load existing run directory, resume review
            run_dir = _resolve_run_dir(args.resume)
            config.output_dir = str(run_dir)
            success = main(config, resume=True)
            sys.exit(0 if success else 1)

        else:
            # Normal mode: create new run directory, run Phases 1-3
            run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_dir = Path(config.output_dir) / f"run_{run_timestamp}"
            run_dir.mkdir(parents=True, exist_ok=True)
            config.output_dir = str(run_dir)
            success = main(config)
            sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        logging.info("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
