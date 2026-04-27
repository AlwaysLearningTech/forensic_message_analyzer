"""
HTML report generation for forensic analysis results.
Renders an HTML report with inline images (WhatsApp/iMessage attachments),
then converts to PDF via WeasyPrint.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, BaseLoader

from src import __version__
from .report_utils import b64_img as _b64_img, generate_limitations

from ..config import Config
from ..forensic_utils import ForensicRecorder
from ..utils.conversation_threading import ConversationThreader
from ..utils.legal_compliance import LegalComplianceManager

logger = logging.getLogger(__name__)


def _fmt(name: str, raw: Optional[str]) -> str:
    """Return 'Name (raw_id)' when raw identifier differs from display name."""
    if raw and raw != name:
        return f"{name} ({raw})"
    return name


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
  .tapback { background: #f0f0f0; font-style: italic; }
  .sos-flag { color: #dc3545; font-weight: bold; }
  .retracted-flag { color: #6c757d; text-decoration: line-through; }
  .downgraded-flag { color: #856404; }
  .edited-flag { color: #0c5460; font-size: 9px; }
  .reactions-list { font-size: 9px; color: #555; margin-top: 2px; }
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
  .src-badge { display: inline-block; padding: 1px 6px; border-radius: 8px; font-size: 9px;
               font-weight: 700; letter-spacing: 0.03em; }
  .src-pattern_matched { background: #e3f2fd; color: #0d47a1; border: 1px solid #bbdefb; }
  .src-ai_screened     { background: #fff3e0; color: #e65100; border: 1px solid #ffcc80; }
  .src-extracted       { background: #f3e5f5; color: #4a148c; border: 1px solid #e1bee7; }
  .src-derived         { background: #eceff1; color: #263238; border: 1px solid #cfd8dc; }
  .src-unknown         { background: #eee; color: #555; border: 1px solid #ccc; }
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
<h2>Executive Summary</h2>
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
    <th style="width:140px">Timestamp ({{ timezone }})</th>
    <th style="width:80px">From</th>
    <th style="width:80px">To</th>
    <th>Content</th>
    <th style="width:60px">Source</th>
    <th style="width:80px">Threat</th>
    <th style="width:60px">Status</th>
  </tr>
  {% for m in person.messages %}
  <tr class="{{ 'tapback' if m.is_tapback else ('threat-high' if m.threat_confidence and m.threat_confidence >= 0.75 else ('threat' if m.threat_detected else '')) }}">
    <td>{{ m.timestamp }}</td>
    <td>{{ m.sender }}</td>
    <td>{{ m.recipient }}</td>
    <td>
      {% if m.date_retracted %}<span class="retracted-flag">{{ m.content }}</span>
      {% else %}{{ m.content }}{% endif %}
      {% if m.attachment_data_uri %}
      <br><img class="attachment-img" src="{{ m.attachment_data_uri }}"
               alt="{{ m.attachment_name or 'photo' }}">
      {% elif m.attachment_name %}
      <br><em>[Attachment: {{ m.attachment_name }}]</em>
      {% endif %}
      {% if m.reactions %}<div class="reactions-list">{{ m.reactions }}</div>{% endif %}
      {% if m.thread_originator_guid %}<div class="edited-flag">Thread: {{ m.thread_originator_guid }}</div>{% endif %}
      {% if m.edit_history and m.edit_history|length > 1 %}
      <div style="margin-top:4px;padding:4px 6px;background:#f8f9fa;border-left:3px solid #dee2e6;font-size:11px;">
        <strong style="color:#6c757d;">Edit history:</strong>
        {% for edit in m.edit_history[:-1] %}
        <div>{{ 'Original' if loop.index0 == 0 else 'Edit ' ~ loop.index0 }}{% if edit.timestamp %} ({{ edit.timestamp }}){% endif %}: {{ edit.content }}</div>
        {% endfor %}
      </div>
      {% endif %}
      {% if m.is_shared_location %}
      <div style="margin-top:4px;padding:4px 6px;background:#e8f5e9;border-left:3px solid #4caf50;font-size:11px;">
        <strong>Shared Location:</strong> {{ m.location_name }}{% if m.location_address %} — {{ m.location_address }}{% endif %}
      </div>
      {% elif m.rich_link_title %}
      <div style="margin-top:4px;padding:4px 6px;background:#e3f2fd;border-left:3px solid #2196f3;font-size:11px;">
        <strong>{{ m.rich_link_title }}</strong>{% if m.rich_link_site_name %} ({{ m.rich_link_site_name }}){% endif %}
        {% if m.rich_link_url %}<br><span style="color:#666;">{{ m.rich_link_url }}</span>{% endif %}
      </div>
      {% endif %}
    </td>
    <td>{{ m.threat_categories or '' }}</td>
    <td>
      {% if m.is_sos %}<span class="sos-flag">SOS</span> {% endif %}
      {% if m.is_recently_deleted %}<span class="retracted-flag">Deleted</span> {% endif %}
      {% if m.date_retracted %}<span class="retracted-flag">Unsent</span> {% endif %}
      {% if m.date_edited %}<span class="edited-flag">Edited</span> {% endif %}
      {% if m.was_downgraded %}<span class="downgraded-flag">SMS</span> {% endif %}
      {% if m.is_tapback %}Tapback{% endif %}
    </td>
  </tr>
  {% else %}
  <tr><td colspan="7" style="text-align:center;color:#888;font-style:italic;padding:16px;">
    No messages found for this contact
  </td></tr>
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
<p class="source-legend" style="font-size:11px;color:#555;margin-bottom:6px;">
  <strong>Source legend:</strong>
  <span class="src-badge src-pattern_matched">PATTERN-MATCHED</span> deterministic YAML/regex;
  <span class="src-badge src-ai_screened">AI-SCREENED</span> LLM flagging (non-evidentiary until confirmed by reviewer);
  <span class="src-badge src-extracted">EXTRACTED</span> raw message/email surfaced for review;
  <span class="src-badge src-derived">DERIVED</span> computed from other findings.
</p>
<table>
  <tr><th>Item ID</th><th>Source</th><th>Method</th><th>Decision</th><th>Reviewer</th><th>Notes</th><th>Reviewed At</th></tr>
  {% for d in review_decisions %}
  <tr>
    <td>{{ d.item_id }}</td>
    <td><span class="src-badge src-{{ d.source or 'unknown' }}">{{ (d.source or 'unknown')|upper|replace('_', '-') }}</span></td>
    <td>{{ d.method or '' }}</td>
    <td>{{ d.decision }}</td>
    <td>{{ d.reviewer or '' }}</td>
    <td>{{ d.notes or '' }}</td>
    <td>{{ d.timestamp or d.reviewed_at or '' }}</td>
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

{% if methodology_sections %}
<div class="page-break">
<h2>Appendix A: Methodology Statement</h2>
{% for section in methodology_sections %}
<h3>{{ section.heading }}</h3>
{% for block in section.blocks %}
{% if block.type == 'paragraph' %}
<p>{{ block.text }}</p>
{% elif block.type == 'bullets' %}
<ul>
  {% for item in block['items'] %}<li>{{ item }}</li>{% endfor %}
</ul>
{% elif block.type == 'definition' %}
<p><strong>{{ block.term }}.</strong> {{ block.text }}</p>
{% endif %}
{% endfor %}
{% endfor %}
</div>
{% endif %}

{% if completeness %}
<div class="page-break">
<h2>Appendix B: Completeness Validation</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Total Messages</td><td>{{ completeness.total_messages }}</td></tr>
  <tr><td>Conversations Analyzed</td><td>{{ completeness.conversations|length }}</td></tr>
  <tr><td>Complete</td><td>{{ 'Yes' if completeness.is_complete else 'No — see issues below' }}</td></tr>
</table>
{% if completeness.gaps_detected %}
<h3>Gaps Detected</h3>
<table>
  <tr><th>Conversation</th><th>Gap Start</th><th>Gap End</th><th>Hours</th></tr>
  {% for gap in completeness.gaps_detected %}
  <tr>
    <td>{{ gap.conversation_id }}</td>
    <td>{{ gap.gap_start }}</td>
    <td>{{ gap.gap_end }}</td>
    <td>{{ gap.gap_hours }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}
{% if completeness.one_sided_conversations %}
<h3>One-Sided Conversations</h3>
<table>
  <tr><th>Conversation</th><th>Sender(s)</th><th>Messages</th></tr>
  {% for c in completeness.one_sided_conversations %}
  <tr>
    <td>{{ c.conversation_id }}</td>
    <td>{{ c.senders|join(', ') }}</td>
    <td>{{ c.message_count }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}
</div>
{% endif %}

{% if limitations %}
<div class="page-break">
<h2>Appendix C: Limitations</h2>
<ul>
{% for item in limitations %}
  <li>{{ item }}</li>
{% endfor %}
</ul>
</div>
{% endif %}

<div class="legal-notice">
  <p>This report was generated by Forensic Message Analyzer v{{ version }}.
  Analysis conducted in compliance with FRE 901, FRE 1001-1008, FRE 803(6), FRE 106,
  the Daubert standard, SWGDE guidelines, and NIST SP 800-86.</p>
</div>

</body>
</html>
"""


class HtmlReporter:
    """Generate HTML reports with inline images, optionally converted to PDF."""

    def __init__(self, forensic_recorder: ForensicRecorder, config: Config = None):
        self.config = config if config is not None else Config()
        self.forensic = forensic_recorder
        self.output_dir = Path(self.config.output_dir)
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
            except ModuleNotFoundError:
                logger.warning(
                    "[!] WeasyPrint not installed — HTML→PDF conversion skipped.\n"
                    "    Install:  pip install weasyprint\n"
                    "    Also requires system libraries:  brew install pango glib gobject-introspection\n"
                    "    (HTML report is still produced.)"
                )
            except Exception as e:
                logger.warning(
                    f"[!] HTML→PDF conversion failed: {e}\n"
                    "    If the error mentions libgobject/pango, run:  brew install pango glib gobject-introspection"
                )

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
        mapped_persons = list(self.config.contact_mappings.keys())
        # Exclude person1 — their messages appear in every other person's section
        person1 = getattr(self.config, 'person1_name', None)
        display_persons = sorted(p for p in mapped_persons if p != person1)

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
                    'description': ri.get('indicator', ri.get('description', ri.get('detail', ''))),
                    'action': ri.get('recommended_action', ''),
                })
            else:
                risk_indicators.append({'severity': '', 'description': str(ri), 'action': ''})

        recommendations = ai.get('recommendations', [])

        # --- per-person messages with inline images ---
        compliance = LegalComplianceManager(config=self.config, forensic_recorder=self.forensic)
        persons = self._build_person_data(messages, display_persons, analysis_results, compliance)

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

        # --- legal appendices ---
        methodology_sections = compliance.generate_methodology_sections()
        completeness = compliance.validate_completeness(messages)
        limitations = self._generate_limitations(analysis_results)

        return {
            'case_name': self.config.case_name or 'Forensic Analysis',
            'case_number': self.config.case_number,
            'examiner': self.config.examiner_name,
            'total_messages': len(messages),
            'threat_count': threat_count,
            'sources': ', '.join(sorted(sources)),
            'report_date': compliance.format_timestamp(),
            'timezone': compliance.tz_abbreviation,
            'ai_summary': ai_summary,
            'risk_indicators': risk_indicators,
            'recommendations': recommendations,
            'persons': persons,
            'threads': threads,
            'review_decisions': reviews,
            'third_party_contacts': tp_rows,
            'methodology_sections': methodology_sections,
            'completeness': completeness,
            'limitations': limitations,
            'version': __version__,
        }

    def _build_person_data(
        self,
        messages: list,
        mapped_persons: list,
        analysis_results: Dict,
        compliance: LegalComplianceManager = None,
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
                persons.append({'name': person, 'messages': []})
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

                # Format reactions list for display
                reactions_display = ''
                reactions = m.get('reactions', [])
                if reactions and isinstance(reactions, list):
                    parts = []
                    for r in reactions:
                        if isinstance(r, dict):
                            parts.append(f"{r.get('type', '')} {r.get('sender', '')}")
                        else:
                            parts.append(str(r))
                    reactions_display = ', '.join(parts)

                # Convert timestamp to local timezone for display
                raw_ts = m.get('timestamp', '')
                display_ts = compliance.convert_to_local(raw_ts) if compliance else str(raw_ts)

                rows.append({
                    'timestamp': display_ts,
                    'sender': _fmt(m.get('sender', ''), m.get('sender_raw')),
                    'recipient': _fmt(m.get('recipient', ''), m.get('recipient_raw')),
                    'content': m.get('content', ''),
                    'source': m.get('source', ''),
                    'attachment_name': m.get('attachment_name'),
                    'attachment_data_uri': attachment_data_uri,
                    'threat_detected': threat_info.get('threat_detected', False),
                    'threat_categories': threat_info.get('threat_categories', ''),
                    'threat_confidence': threat_info.get('threat_confidence', 0),
                    # New forensic fields
                    'is_tapback': m.get('is_tapback', False),
                    'date_edited': m.get('date_edited'),
                    'edit_history': m.get('edit_history', []),
                    'date_retracted': m.get('date_retracted'),
                    'is_sos': m.get('is_sos', False),
                    'is_recently_deleted': m.get('is_recently_deleted', False),
                    'was_downgraded': m.get('was_downgraded', False),
                    'thread_originator_guid': m.get('thread_originator_guid'),
                    'reactions': reactions_display,
                    # Rich link / location fields
                    'is_shared_location': m.get('is_shared_location', False),
                    'location_name': m.get('location_name', ''),
                    'location_address': m.get('location_address', ''),
                    'rich_link_title': m.get('rich_link_title', ''),
                    'rich_link_url': m.get('rich_link_url', ''),
                    'rich_link_site_name': m.get('rich_link_site_name', ''),
                })

            persons.append({'name': person, 'messages': rows})
        return persons

    def _generate_limitations(self, analysis_results: Dict) -> List[str]:
        """Generate a list of limitation statements based on available data and features."""
        return generate_limitations(self.config, analysis_results)
