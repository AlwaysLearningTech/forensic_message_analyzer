"""
HTML report generation for forensic analysis results.
Renders an HTML report with inline images (WhatsApp/iMessage attachments),
then converts to PDF via WeasyPrint.
"""

import base64
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, BaseLoader

from ..config import Config
from ..forensic_utils import ForensicRecorder
from ..utils.conversation_threading import ConversationThreader

config = Config()
logger = logging.getLogger(__name__)

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.heic', '.webp', '.tiff', '.bmp'}


def _b64_img(path_str: str) -> Optional[str]:
    """Return a data-URI for an image file, or None if unreadable."""
    p = Path(path_str)
    if not p.is_file():
        return None
    suffix = p.suffix.lower()
    mime = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png', '.gif': 'image/gif',
        '.webp': 'image/webp', '.heic': 'image/heic',
        '.tiff': 'image/tiff', '.bmp': 'image/bmp',
    }.get(suffix, 'application/octet-stream')
    try:
        data = p.read_bytes()
        encoded = base64.b64encode(data).decode('ascii')
        return f"data:{mime};base64,{encoded}"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Jinja2 HTML template
# ---------------------------------------------------------------------------
REPORT_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Forensic Analysis Report &mdash; {{ case_name }}</title>
<style>
  @page { size: letter; margin: 1in; }
  body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
         font-size: 11px; color: #222; line-height: 1.5; }
  h1 { font-size: 20px; border-bottom: 2px solid #333; padding-bottom: 6px; }
  h2 { font-size: 16px; color: #444; margin-top: 28px; border-bottom: 1px solid #ccc;
       padding-bottom: 4px; }
  h3 { font-size: 13px; margin-top: 18px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
  th, td { border: 1px solid #bbb; padding: 4px 8px; text-align: left;
           vertical-align: top; font-size: 10px; }
  th { background: #f0f0f0; font-weight: 600; }
  tr:nth-child(even) { background: #fafafa; }
  .threat { background: #fff3cd; }
  .threat-high { background: #f8d7da; }
  .attachment-img { max-width: 320px; max-height: 240px; border: 1px solid #ccc;
                    border-radius: 4px; margin: 4px 0; }
  .overview-grid { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 16px; }
  .overview-card { border: 1px solid #ccc; border-radius: 6px; padding: 12px;
                   min-width: 180px; flex: 1; }
  .overview-card .label { font-size: 10px; color: #666; }
  .overview-card .value { font-size: 18px; font-weight: 700; }
  .legal-notice { font-size: 9px; color: #888; border-top: 1px solid #ccc;
                  margin-top: 40px; padding-top: 8px; }
  .page-break { page-break-before: always; }
</style>
</head>
<body>

<h1>Forensic Digital Communications Analysis Report</h1>

<div class="overview-grid">
  <div class="overview-card">
    <div class="label">Case</div>
    <div class="value">{{ case_number or 'N/A' }}</div>
  </div>
  <div class="overview-card">
    <div class="label">Examiner</div>
    <div class="value">{{ examiner or 'N/A' }}</div>
  </div>
  <div class="overview-card">
    <div class="label">Total Messages</div>
    <div class="value">{{ total_messages }}</div>
  </div>
  <div class="overview-card">
    <div class="label">Threats Detected</div>
    <div class="value">{{ threat_count }}</div>
  </div>
  <div class="overview-card">
    <div class="label">Sources</div>
    <div class="value">{{ sources }}</div>
  </div>
  <div class="overview-card">
    <div class="label">Report Date</div>
    <div class="value">{{ report_date }}</div>
  </div>
</div>

{% if ai_summary %}
<h2>AI Executive Summary</h2>
<p>{{ ai_summary }}</p>
{% endif %}

{% if risk_indicators %}
<h2>Risk Indicators</h2>
<table>
  <tr><th>Severity</th><th>Description</th><th>Recommended Action</th></tr>
  {% for r in risk_indicators %}
  <tr class="{{ 'threat-high' if r.severity|lower in ('high','critical') else 'threat' }}">
    <td>{{ r.severity }}</td><td>{{ r.description }}</td><td>{{ r.action }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

{% if recommendations %}
<h2>Recommendations</h2>
<ol>
{% for rec in recommendations %}
  <li>{{ rec }}</li>
{% endfor %}
</ol>
{% endif %}

{% for person in persons %}
<div class="{{ 'page-break' if not loop.first else '' }}">
<h2>{{ person.name }} &mdash; Messages ({{ person.messages|length }})</h2>
<table>
  <tr>
    <th style="width:120px">Timestamp</th>
    <th style="width:80px">From</th>
    <th style="width:80px">To</th>
    <th>Content</th>
    <th style="width:60px">Source</th>
    <th style="width:80px">Threat</th>
  </tr>
  {% for m in person.messages %}
  <tr class="{{ 'threat-high' if m.threat_confidence and m.threat_confidence >= 0.75 else ('threat' if m.threat_detected else '') }}">
    <td>{{ m.timestamp }}</td>
    <td>{{ m.sender }}</td>
    <td>{{ m.recipient }}</td>
    <td>
      {{ m.content }}
      {% if m.attachment_data_uri %}
      <br><img class="attachment-img" src="{{ m.attachment_data_uri }}"
               alt="{{ m.attachment_name or 'photo' }}">
      {% elif m.attachment_name %}
      <br><em>[Attachment: {{ m.attachment_name }}]</em>
      {% endif %}
    </td>
    <td>{{ m.source }}</td>
    <td>{{ m.threat_categories or '' }}</td>
  </tr>
  {% endfor %}
</table>
</div>
{% endfor %}

{% if threads %}
<div class="page-break">
<h2>Conversation Threads</h2>
<table>
  <tr><th>Thread</th><th>Participants</th><th>Time Range</th>
      <th>Messages</th><th>Threats</th><th>Avg Sentiment</th></tr>
  {% for t in threads %}
  <tr>
    <td>{{ t.thread_id }}</td><td>{{ t.participants }}</td>
    <td>{{ t.start_time }} &ndash; {{ t.end_time }}</td>
    <td>{{ t.message_count }}</td><td>{{ t.threat_count }}</td>
    <td>{{ t.avg_sentiment if t.avg_sentiment is not none else 'N/A' }}</td>
  </tr>
  {% endfor %}
</table>
</div>
{% endif %}

{% if review_decisions %}
<div class="page-break">
<h2>Manual Review Decisions</h2>
<table>
  <tr><th>Item ID</th><th>Decision</th><th>Notes</th><th>Reviewed At</th></tr>
  {% for d in review_decisions %}
  <tr>
    <td>{{ d.item_id }}</td><td>{{ d.decision }}</td>
    <td>{{ d.notes or '' }}</td><td>{{ d.reviewed_at or '' }}</td>
  </tr>
  {% endfor %}
</table>
</div>
{% endif %}

{% if third_party_contacts %}
<h2>Third-Party Contacts</h2>
<table>
  <tr><th>Identifier</th><th>Display Name</th><th>Source</th><th>Context</th></tr>
  {% for c in third_party_contacts %}
  <tr>
    <td>{{ c.identifier }}</td><td>{{ c.display_name }}</td>
    <td>{{ c.source }}</td><td>{{ c.context }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

<div class="legal-notice">
  <p>This report was generated by Forensic Message Analyzer v4.0.0.
  Analysis conducted in compliance with FRE 901, FRE 1001-1008, FRE 803(6), FRE 106,
  the Daubert standard, SWGDE guidelines, and NIST SP 800-86.</p>
</div>

</body>
</html>
"""


class HtmlReporter:
    """Generate HTML reports with inline images, optionally converted to PDF."""

    def __init__(self, forensic_recorder: ForensicRecorder):
        self.forensic = forensic_recorder
        self.output_dir = Path(config.output_dir)
        self.env = Environment(loader=BaseLoader(), autoescape=True)
        self.template = self.env.from_string(REPORT_TEMPLATE)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        extracted_data: Dict,
        analysis_results: Dict,
        review_decisions: Dict,
        output_path: Path,
        pdf: bool = True,
    ) -> Dict[str, Path]:
        """
        Generate an HTML report (and optional PDF).

        Args:
            extracted_data: Extraction phase output.
            analysis_results: Analysis phase output.
            review_decisions: Review phase output.
            output_path: Base path (without extension).
            pdf: If True, also produce a PDF via WeasyPrint.

        Returns:
            Dict mapping format name to file path.
        """
        context = self._build_context(extracted_data, analysis_results, review_decisions)
        html_content = self.template.render(**context)

        html_path = output_path.with_suffix('.html')
        html_path.write_text(html_content, encoding='utf-8')
        self._record_output(html_path, 'html')
        paths: Dict[str, Path] = {'html': html_path}

        if pdf:
            pdf_path = output_path.with_suffix('.pdf')
            try:
                from weasyprint import HTML as WeasyprintHTML
                WeasyprintHTML(string=html_content, base_url=str(html_path.parent)).write_pdf(pdf_path)
                self._record_output(pdf_path, 'pdf')
                paths['pdf'] = pdf_path
            except Exception as e:
                logger.error(f"PDF generation failed (HTML still available): {e}")

        return paths

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _record_output(self, path: Path, fmt: str):
        file_hash = self.forensic.compute_hash(path)
        self.forensic.record_action(
            f"html_report_{fmt}_generated",
            f"Generated {fmt.upper()} report with hash {file_hash}",
            {"path": str(path), "hash": file_hash},
        )
        logger.info(f"Generated {fmt.upper()} report: {path}")

    def _build_context(
        self,
        extracted_data: Dict,
        analysis_results: Dict,
        review_decisions: Dict,
    ) -> Dict[str, Any]:
        messages = extracted_data.get('messages', extracted_data.get('combined', []))
        mapped_persons = list(config.contact_mappings.keys())

        # --- overview stats ---
        sources = set()
        for m in messages:
            src = m.get('source')
            if src:
                sources.add(src)

        threat_details = analysis_results.get('threats', {}).get('details', [])
        threat_count = sum(1 for d in threat_details if d.get('threat_detected'))

        # --- AI analysis ---
        ai = analysis_results.get('ai_analysis', {})
        ai_summary = ai.get('conversation_summary', '')
        if ai_summary and 'not configured' in ai_summary.lower():
            ai_summary = ''

        risk_indicators: List[Dict[str, str]] = []
        for ri in ai.get('risk_indicators', []):
            if isinstance(ri, dict):
                risk_indicators.append({
                    'severity': str(ri.get('severity', '')).upper(),
                    'description': ri.get('indicator', ri.get('description', '')),
                    'action': ri.get('recommended_action', ''),
                })
            else:
                risk_indicators.append({'severity': '', 'description': str(ri), 'action': ''})

        recommendations = ai.get('recommendations', [])

        # --- per-person messages with inline images ---
        persons = self._build_person_data(messages, mapped_persons, analysis_results)

        # --- conversation threads ---
        threads: List[Dict] = []
        if messages:
            try:
                threader = ConversationThreader()
                threads = threader.generate_conversation_summaries(messages)
            except Exception:
                pass

        # --- review decisions ---
        reviews = review_decisions.get('reviews', [])

        # --- third-party contacts ---
        tp = extracted_data.get('third_party_contacts', [])
        tp_rows = []
        for entry in tp:
            tp_rows.append({
                'identifier': entry.get('identifier', ''),
                'display_name': entry.get('display_name', ''),
                'source': ', '.join(entry.get('sources', [])),
                'context': '; '.join(entry.get('contexts', [])),
            })

        return {
            'case_name': config.case_name or 'Forensic Analysis',
            'case_number': config.case_number,
            'examiner': config.examiner_name,
            'total_messages': len(messages),
            'threat_count': threat_count,
            'sources': ', '.join(sorted(sources)),
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ai_summary': ai_summary,
            'risk_indicators': risk_indicators,
            'recommendations': recommendations,
            'persons': persons,
            'threads': threads,
            'review_decisions': reviews,
            'third_party_contacts': tp_rows,
        }

    def _build_person_data(
        self,
        messages: list,
        mapped_persons: list,
        analysis_results: Dict,
    ) -> List[Dict[str, Any]]:
        """Build a per-person list of messages with embedded attachment images."""
        # Build a lookup of threat info by message_id
        threat_lookup: Dict[Any, Dict] = {}
        for d in analysis_results.get('threats', {}).get('details', []):
            mid = d.get('message_id')
            if mid is not None:
                threat_lookup[mid] = d

        persons: List[Dict[str, Any]] = []
        for person in mapped_persons:
            person_msgs = [
                m for m in messages
                if m.get('sender') == person or m.get('recipient') == person
            ]
            if not person_msgs:
                continue

            rows = []
            for m in person_msgs:
                mid = m.get('message_id')
                threat_info = threat_lookup.get(mid, {})

                # Attempt to embed the attachment image as base64
                attachment_data_uri = None
                att_path = m.get('attachment')
                if att_path:
                    attachment_data_uri = _b64_img(att_path)

                rows.append({
                    'timestamp': str(m.get('timestamp', '')),
                    'sender': m.get('sender', ''),
                    'recipient': m.get('recipient', ''),
                    'content': m.get('content', ''),
                    'source': m.get('source', ''),
                    'attachment_name': m.get('attachment_name'),
                    'attachment_data_uri': attachment_data_uri,
                    'threat_detected': threat_info.get('threat_detected', False),
                    'threat_categories': threat_info.get('threat_categories', ''),
                    'threat_confidence': threat_info.get('threat_confidence', 0),
                })

            persons.append({'name': person, 'messages': rows})
        return persons
