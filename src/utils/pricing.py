"""
Centralized Anthropic model pricing with auto-fetch and YAML cache fallback.

On first call, fetches current pricing from Anthropic's pricing page, parses
the markdown tables, and caches to pricing.yaml. If the fetch fails, falls
back to the cached YAML with a warning.
"""

import re
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import yaml

logger = logging.getLogger(__name__)

# Pricing page URL (redirects from docs.anthropic.com)
_PRICING_URL = "https://platform.claude.com/docs/en/about-claude/pricing"
_YAML_PATH = Path(__file__).resolve().parent.parent.parent / "pricing.yaml"

# Session-level cache: populated once per process
_pricing_cache: Optional[Dict] = None


def _fetch_pricing_page() -> str:
    """Fetch the Anthropic pricing page as text. Returns raw content."""
    import urllib.request
    import urllib.error

    req = urllib.request.Request(_PRICING_URL, headers={"User-Agent": "forensic-message-analyzer/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8")


def _parse_model_table(html: str) -> Dict[str, dict]:
    """Parse model pricing and batch pricing tables from the page content.

    Returns dict keyed by display name, e.g.:
        {"Claude Opus 4.6": {input: 5.0, output: 25.0, cache_write_5m: 6.25,
            cache_write_1h: 10.0, cache_read: 0.5, batch_input: 2.5, batch_output: 12.5}}
    """
    models: Dict[str, dict] = {}

    # --- Parse main model pricing table ---
    # Columns: Model | Base Input | 5m Cache Write | 1h Cache Write | Cache Hits | Output
    # Row example: | Claude Opus 4.7 | $5 / MTok | $6.25 / MTok | $10 / MTok | $0.50 / MTok | $25 / MTok |
    model_row_re = re.compile(
        r'\|\s*(?P<name>Claude\s+\w+\s+[\d.]+)\s*'
        r'(?:\([^)]*\)\s*)?'       # optional "(deprecated)" etc.
        r'\|\s*\$(?P<input>[\d.]+)\s*/\s*MTok'
        r'\s*\|\s*\$(?P<cw5>[\d.]+)\s*/\s*MTok'
        r'\s*\|\s*\$(?P<cw1h>[\d.]+)\s*/\s*MTok'
        r'\s*\|\s*\$(?P<cr>[\d.]+)\s*/\s*MTok'
        r'\s*\|\s*\$(?P<output>[\d.]+)\s*/\s*MTok'
    )
    for m in model_row_re.finditer(html):
        name = m.group("name").strip()
        models[name] = {
            "input": float(m.group("input")),
            "output": float(m.group("output")),
            "cache_write_5m": float(m.group("cw5")),
            "cache_write_1h": float(m.group("cw1h")),
            "cache_read": float(m.group("cr")),
        }

    # --- Parse batch pricing table ---
    # Columns: Model | Batch input | Batch output
    batch_row_re = re.compile(
        r'\|\s*(?P<name>Claude\s+\w+\s+[\d.]+)\s*'
        r'(?:\([^)]*\)\s*)?'
        r'\|\s*\$(?P<bi>[\d.]+)\s*/\s*MTok'
        r'\s*\|\s*\$(?P<bo>[\d.]+)\s*/\s*MTok\s*\|'
    )
    for m in batch_row_re.finditer(html):
        name = m.group("name").strip()
        if name in models:
            models[name]["batch_input"] = float(m.group("bi"))
            models[name]["batch_output"] = float(m.group("bo"))
        else:
            # Batch-only entry (shouldn't happen, but handle gracefully)
            models[name] = {
                "batch_input": float(m.group("bi")),
                "batch_output": float(m.group("bo")),
            }

    return models


def _save_yaml(models: Dict[str, dict]) -> None:
    """Write pricing data to YAML cache file."""
    data = {
        "fetched": datetime.now(timezone.utc).isoformat(),
        "source": _PRICING_URL,
        "models": models,
    }
    with open(_YAML_PATH, "w") as f:
        f.write("# Auto-fetched from Anthropic pricing page — do not edit by hand\n")
        f.write(f"# Last updated: {data['fetched']}\n")
        f.write(f"# Source: {data['source']}\n\n")
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def _load_yaml() -> Optional[Dict[str, dict]]:
    """Load pricing from YAML cache. Returns models dict or None."""
    if not _YAML_PATH.exists():
        return None
    with open(_YAML_PATH) as f:
        data = yaml.safe_load(f)
    if not data or "models" not in data:
        return None

    fetched = data.get("fetched", "unknown date")
    print(
        f"  WARNING: Using cached pricing from {fetched}.\n"
        f"  Verify rates at {_PRICING_URL} and re-run with network access to refresh."
    )
    logger.warning("Using cached pricing from %s (fetch failed)", fetched)
    return data["models"]


def _load_pricing() -> Dict[str, dict]:
    """Fetch pricing from Anthropic, falling back to YAML cache.

    Raises RuntimeError if neither source is available.
    """
    # Try live fetch
    try:
        html = _fetch_pricing_page()
        models = _parse_model_table(html)
        if models:
            _save_yaml(models)
            logger.info("Pricing fetched and cached: %d models", len(models))
            return models
        logger.warning("Pricing page fetched but no models parsed — falling back to cache")
    except Exception as e:
        logger.warning("Failed to fetch pricing page: %s — falling back to cache", e)

    # Fall back to YAML cache
    cached = _load_yaml()
    if cached:
        return cached

    raise RuntimeError(
        "Cannot determine model pricing: fetch failed and no pricing.yaml cache exists. "
        f"Visit {_PRICING_URL} and create pricing.yaml manually, or restore network access."
    )


def _resolve_model(model_id: str, models: Dict[str, dict]) -> dict:
    """Match a model API ID (e.g. 'claude-opus-4-6') to its pricing entry.

    Strategy: extract tier (opus/sonnet/haiku) and version from the model ID,
    then find the best match in the pricing table.
    """
    model_lower = model_id.lower()

    # Determine tier
    if "haiku" in model_lower:
        tier = "Haiku"
    elif "sonnet" in model_lower:
        tier = "Sonnet"
    elif "opus" in model_lower:
        tier = "Opus"
    else:
        tier = None

    if tier:
        # Extract version: "claude-opus-4-6" → "4.6", "claude-haiku-4-5-20251001" → "4.5"
        # Try pattern: tier name followed by version digits
        ver_match = re.search(rf'{tier.lower()}[- ](\d+)[.-](\d+)', model_lower)
        if ver_match:
            version = f"{ver_match.group(1)}.{ver_match.group(2)}"
            target = f"Claude {tier} {version}"
            if target in models:
                return models[target]

        # Broader match: find any entry matching the tier, prefer highest version
        tier_entries = {k: v for k, v in models.items() if tier in k}
        if tier_entries:
            # Sort by version number descending, return best match
            def _ver(name: str) -> float:
                m = re.search(r'(\d+\.\d+)', name)
                return float(m.group(1)) if m else 0.0

            best = max(tier_entries.keys(), key=_ver)
            logger.info("Model %s: no exact match, using %s pricing", model_id, best)
            return tier_entries[best]

    # Last resort: use the first Sonnet entry as a safe default
    for name, rates in models.items():
        if "Sonnet" in name:
            logger.warning("Unknown model %s — falling back to %s pricing", model_id, name)
            return rates

    # Absolute fallback: first entry
    first = next(iter(models.values()))
    logger.warning("Unknown model %s — falling back to first available pricing", model_id)
    return first


def get_pricing(model: str, batch: bool = False) -> dict:
    """Get pricing for a model.

    Args:
        model: Anthropic model ID (e.g. 'claude-opus-4-6', 'claude-sonnet-4-6')
        batch: If True, return batch API rates for input/output

    Returns:
        Dict with keys: input, output, cache_write, cache_read (all per MTok).
        When batch=True, input/output are batch rates.
    """
    global _pricing_cache
    if _pricing_cache is None:
        _pricing_cache = _load_pricing()

    rates = _resolve_model(model, _pricing_cache)

    if batch:
        return {
            "input": rates.get("batch_input", rates.get("input", 3.0) * 0.5),
            "output": rates.get("batch_output", rates.get("output", 15.0) * 0.5),
            "cache_write": rates.get("cache_write_5m", rates.get("input", 3.0) * 1.25),
            "cache_read": rates.get("cache_read", rates.get("input", 3.0) * 0.1),
        }

    return {
        "input": rates.get("input", 3.0),
        "output": rates.get("output", 15.0),
        "cache_write": rates.get("cache_write_5m", rates.get("input", 3.0) * 1.25),
        "cache_read": rates.get("cache_read", rates.get("input", 3.0) * 0.1),
    }
