"""Parse the JavaScript rendered by WebReview._render_review_page with a real JS engine.

Regex-level pattern checks missed a class of bug where the whole `<script>` block
failed to parse, so the review page silently never loaded items. This test hands
the rendered script to `node --check` so any future regression in the template
fails here instead of in a browser tab.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import Config
from src.review.manual_review_manager import ManualReviewManager
from src.review.web_review import WebReview


def _render_script(tmp_path: Path) -> str:
    config = Config()
    config.review_dir = str(tmp_path)
    manager = ManualReviewManager(review_dir=tmp_path, config=config)
    web = WebReview(manager, config=config)
    web.flagged_items = [{"id": "item_0", "content": "sample", "type": "threat", "source": "pattern_matched"}]
    web.messages = []
    html = web._render_review_page()
    match = re.search(r"<script>(.*?)</script>", html, re.S)
    assert match, "rendered page is missing a <script> block"
    return match.group(1)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_rendered_script_parses(tmp_path: Path):
    script = _render_script(tmp_path)
    script_file = tmp_path / "review.js"
    script_file.write_text(script)
    result = subprocess.run(
        ["node", "--check", str(script_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"rendered <script> has a syntax error:\n{result.stderr}"
    )
