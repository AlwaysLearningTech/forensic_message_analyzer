"""
Shared utilities for report generators.
Centralizes functions used across multiple reporters to avoid duplication.
"""

import base64
import io
import re
from pathlib import Path
from typing import Dict, List, Optional

from PIL import Image

# Image handling constants
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.heic', '.webp', '.tiff', '.bmp'}
_HTML_IMG_MAX_DIM = 800
_HTML_IMG_JPEG_QUALITY = 70
_MIME_MAP = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.png': 'image/png', '.gif': 'image/gif',
    '.webp': 'image/webp', '.tiff': 'image/tiff',
    '.bmp': 'image/bmp', '.heic': 'image/heic',
}


def b64_img(path_str: str) -> Optional[str]:
    """Return a resized data-URI for an image file, or None if unreadable.

    Images are resized to fit within _HTML_IMG_MAX_DIM pixels and saved in their original format (PNG stays PNG, JPEG stays JPEG). JPEGs are re-compressed at _HTML_IMG_JPEG_QUALITY. Original files are preserved unmodified in the attachments/ output directory.
    """
    p = Path(path_str)
    if not p.is_file():
        return None
    suffix = p.suffix.lower()
    if suffix not in IMAGE_EXTENSIONS:
        return None
    mime = _MIME_MAP.get(suffix, 'application/octet-stream')
    try:
        img = Image.open(p)
        orig_format = img.format or 'PNG'
        if max(img.size) > _HTML_IMG_MAX_DIM:
            img.thumbnail((_HTML_IMG_MAX_DIM, _HTML_IMG_MAX_DIM), Image.LANCZOS)
        buf = io.BytesIO()
        if orig_format.upper() in ('JPEG', 'JPG'):
            if img.mode not in ('RGB', 'L'):
                img = img.convert('RGB')
            img.save(buf, format='JPEG', quality=_HTML_IMG_JPEG_QUALITY, optimize=True)
        else:
            img.save(buf, format=orig_format, optimize=True)
        encoded = base64.b64encode(buf.getvalue()).decode('ascii')
        return f"data:{mime};base64,{encoded}"
    except Exception:
        try:
            data = p.read_bytes()
            encoded = base64.b64encode(data).decode('ascii')
            return f"data:{mime};base64,{encoded}"
        except Exception:
            return None


def match_quote_to_message(quote: str, messages: list) -> dict:
    """Match an AI-identified quote to its source message via substring matching.

    Returns dict with 'timestamp' and 'sender' if found, empty values otherwise.
    """
    if not quote or not messages:
        return {'timestamp': None, 'sender': ''}
    quote_lower = quote.lower().strip()
    for msg in messages:
        content = msg.get('content', '')
        if content and quote_lower in content.lower():
            return {
                'timestamp': msg.get('timestamp'),
                'sender': msg.get('sender', ''),
            }
    return {'timestamp': None, 'sender': ''}


def generate_limitations(config, analysis_results: Dict) -> List[str]:
    """Generate limitation statements based on available data and features.

    Args:
        config: Config instance with data source and feature settings.
        analysis_results: Analysis phase output dict.

    Returns:
        List of limitation description strings.
    """
    limitations = []

    if not getattr(config, 'enable_sentiment', True):
        limitations.append("Sentiment analysis was disabled for this run.")
    if not getattr(config, 'enable_image_analysis', True):
        limitations.append("Image analysis was disabled for this run.")
    if not getattr(config, 'enable_ocr', True):
        limitations.append("OCR was disabled for this run.")

    ai = analysis_results.get('ai_analysis', {})
    summary = ai.get('conversation_summary', '')
    if not summary or 'not configured' in summary.lower() or 'not available' in summary.lower():
        limitations.append(
            "AI-powered analysis was not available — threat assessment, behavioral analysis, "
            "and conversation summarization were limited to rule-based methods."
        )

    if getattr(config, 'start_date', None) or getattr(config, 'end_date', None):
        start = getattr(config, 'start_date', 'beginning')
        end = getattr(config, 'end_date', 'present')
        limitations.append(
            f"Analysis was filtered to date range: {start} to {end}. "
            f"Messages outside this range were excluded."
        )

    if not limitations:
        limitations.append("No significant limitations identified for this analysis.")

    return limitations


# ---------------------------------------------------------------------------
# Markdown → report format helpers
# ---------------------------------------------------------------------------

def _md_inline_to_html(text: str) -> str:
    """Convert inline markdown (bold, italic) to ReportLab-compatible HTML."""
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<i>\1</i>', text)
    return text


def markdown_to_docx(doc, text: str):
    """Add markdown-formatted text to a python-docx Document.

    Handles headings (# / ##), bold/italic inline, bullet lists (- ),
    and plain paragraphs. Modifies doc in-place.
    """
    for block in text.split('\n\n'):
        for line in block.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            # Headings
            heading_match = re.match(r'^(#{1,3})\s+(.*)', stripped)
            if heading_match:
                level = len(heading_match.group(1))
                doc.add_heading(heading_match.group(2), level=min(level, 3))
                continue

            # Bullet lines
            bullet_match = re.match(r'^[-*]\s+(.*)', stripped)
            if bullet_match:
                _add_md_inline_paragraph(doc, bullet_match.group(1), style='List Bullet')
                continue

            # Numbered list lines
            num_match = re.match(r'^(\d+)\.\s+(.*)', stripped)
            if num_match:
                _add_md_inline_paragraph(doc, stripped)
                continue

            # Regular paragraph with inline formatting
            _add_md_inline_paragraph(doc, stripped)


def _add_md_inline_paragraph(doc, text: str, style=None):
    """Add a paragraph to doc, rendering **bold** and *italic* as Word runs."""
    para = doc.add_paragraph(style=style)
    parts = re.split(r'(\*\*.*?\*\*|\*.*?\*)', text)
    for part in parts:
        if part.startswith('**') and part.endswith('**'):
            run = para.add_run(part[2:-2])
            run.bold = True
        elif part.startswith('*') and part.endswith('*') and not part.startswith('**'):
            run = para.add_run(part[1:-1])
            run.italic = True
        else:
            para.add_run(part)
