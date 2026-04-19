import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import logging
import json
import html as html_module
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from ..config import Config
from ..forensic_utils import ForensicRecorder
from ..utils.legal_compliance import LegalComplianceManager
from ..utils.pricing import get_pricing
from .report_utils import match_quote_to_message, generate_limitations

logger = logging.getLogger(__name__)


class ForensicReporter:
    """
    Generate forensic reports in multiple formats.
    Ensures legal defensibility and chain of custody documentation.
    """

    def __init__(self, forensic_recorder: ForensicRecorder, config: Config = None):
        """
        Initialize the forensic reporter.

        Args:
            forensic_recorder: ForensicRecorder instance for chain of custody
            config: Config instance. If None, creates a new one.
        """
        self.config = config if config is not None else Config()
        self.forensic = forensic_recorder
        self.compliance = LegalComplianceManager(config=self.config, forensic_recorder=forensic_recorder)
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_date_range(messages) -> str:
        """Return a 'YYYY-MM-DD to YYYY-MM-DD' string from a list of message dicts."""
        if not messages:
            return 'N/A'
        timestamps = [msg.get('timestamp') for msg in messages if msg.get('timestamp') is not None]
        if not timestamps:
            return 'N/A'
        dt_timestamps = []
        for ts in timestamps:
            try:
                if isinstance(ts, str):
                    parsed = pd.to_datetime(ts, utc=True)
                    if not pd.isna(parsed):
                        dt_timestamps.append(parsed)
                elif hasattr(ts, 'year') and not pd.isna(ts):
                    if hasattr(ts, 'tzinfo') and ts.tzinfo is None:
                        ts = ts.replace(tzinfo=pd.Timestamp.now(tz='UTC').tzinfo)
                    dt_timestamps.append(ts)
            except Exception:
                pass
        if not dt_timestamps:
            return 'N/A'
        return f"{min(dt_timestamps).strftime('%Y-%m-%d')} to {max(dt_timestamps).strftime('%Y-%m-%d')}"

    @staticmethod
    def _esc(text) -> str:
        """Escape text for safe use in ReportLab Paragraph (XML/HTML context)."""
        return html_module.escape(str(text)) if text else ''

    @staticmethod
    def _match_quote_to_message(quote: str, messages: list) -> dict:
        """Match an AI-identified quote to its source message via substring matching."""
        return match_quote_to_message(quote, messages)

    def generate_comprehensive_report(self, 
                                     extracted_data: Dict,
                                     analysis_results: Dict,
                                     review_decisions: Dict) -> Dict[str, Path]:
        """
        Generate comprehensive forensic report in multiple formats.
        
        Args:
            extracted_data: Data from extraction phase
            analysis_results: Results from analysis phase
            review_decisions: Manual review decisions
            
        Returns:
            Dictionary mapping format to output file path
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports = {}

        # Generate legal team summary first (used in Word/PDF reports)
        legal_summary = self._generate_legal_team_summary(
            extracted_data, analysis_results, review_decisions
        )

        # Generate Word report
        try:
            word_path = self._generate_word_report(
                extracted_data, analysis_results, review_decisions, timestamp,
                legal_summary=legal_summary
            )
            reports['word'] = word_path
            logger.info(f"Generated Word report: {word_path}")
        except Exception as e:
            import traceback
            logger.error(f"Failed to generate Word report: {e}")
            logger.error(traceback.format_exc())
            self.forensic.record_action(
                "report_generation_error",
                f"Word report generation failed: {str(e)}"
            )
        
        # Generate PDF report
        try:
            pdf_path = self._generate_pdf_report(
                extracted_data, analysis_results, review_decisions, timestamp,
                legal_summary=legal_summary
            )
            reports['pdf'] = pdf_path
            logger.info(f"Generated PDF report: {pdf_path}")
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            self.forensic.record_action(
                "report_generation_error",
                f"PDF report generation failed: {str(e)}"
            )
        
        # Generate JSON report
        try:
            json_path = self._generate_json_report(
                extracted_data, analysis_results, review_decisions, timestamp,
                legal_summary=legal_summary
            )
            reports['json'] = json_path
            logger.info(f"Generated JSON report: {json_path}")
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            self.forensic.record_action(
                "report_generation_error",
                f"JSON report generation failed: {str(e)}"
            )

        # Store legal summary text for deferred docx generation (after all reports exist)
        self._legal_summary_text = legal_summary

        # Record report generation
        self.forensic.record_action(
            "reports_generated",
            f"Generated {len(reports)} forensic reports",
            {
                "formats": list(reports.keys()),
                "timestamp": timestamp
            }
        )
        
        return reports
    
    def _generate_word_report(self, extracted_data: Dict, analysis_results: Dict,
                            review_decisions: Dict, timestamp: str,
                            legal_summary: str = None) -> Path:
        """Generate Word document report."""
        doc = Document()
        
        # Title page
        title = doc.add_heading('Forensic Message Analysis Report', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        doc.add_paragraph(f'Generated: {self.compliance.format_timestamp()}')
        doc.add_paragraph(f'Case ID: {timestamp}')
        doc.add_page_break()

        # ----- Legal Compliance Header -----
        header = self.compliance.generate_report_header()
        doc.add_heading('Case Information', 1)
        doc.add_paragraph(f"Case Number: {header['case_number']}")
        doc.add_paragraph(f"Case Name: {header['case_name']}")
        doc.add_paragraph(f"Examiner: {header['examiner_name']}")
        doc.add_paragraph(f"Organization: {header['organization']}")
        doc.add_paragraph(f"Date of Examination: {header['date_of_examination']}")
        doc.add_paragraph(f"Tools Used: {header['tools_used']}")

        # Methodology Statement
        doc.add_heading('Methodology', 1)
        methodology = self.compliance.generate_methodology_statement()
        for line in methodology.split('\n'):
            if line.strip():
                doc.add_paragraph(line)

        # Standards Compliance Statement
        doc.add_heading('Standards Compliance', 1)
        compliance_stmt = self.compliance.get_standards_compliance_statement()
        for line in compliance_stmt.split('\n'):
            if line.strip():
                doc.add_paragraph(line)

        # Completeness Validation (FRE 106)
        messages = extracted_data.get('messages', extracted_data.get('combined', []))
        completeness = self.compliance.validate_completeness(messages)
        doc.add_heading('Completeness Validation', 1)
        doc.add_paragraph(
            f"Total messages: {completeness.get('total_messages', 0)}. "
            f"Conversations analyzed: {len(completeness.get('conversations', {}))}. "
            f"Complete: {'Yes' if completeness.get('is_complete') else 'No'}."
        )
        issues = completeness.get('issues', [])
        if issues:
            doc.add_paragraph('Issues detected:')
            for issue in issues:
                doc.add_paragraph(issue, style='List Bullet')

        # Limitations
        doc.add_heading('Limitations', 1)
        limitations = self._generate_limitations(analysis_results)
        for item in limitations:
            doc.add_paragraph(item, style='List Bullet')

        doc.add_page_break()

        # === AI-Powered Findings Summary ===
        ai_analysis = analysis_results.get('ai_analysis', {})
        if ai_analysis and ai_analysis.get('conversation_summary') and \
           'not configured' not in ai_analysis.get('conversation_summary', '').lower():
            doc.add_heading('Findings Summary', 1)
            doc.add_paragraph(
                'This section provides AI-assisted analysis findings for rapid legal team review. '
                'AI findings are supplementary and should be validated against the underlying evidence.'
            )

            # AI Executive Summary
            doc.add_heading('AI Analysis Overview', 2)
            doc.add_paragraph(ai_analysis.get('conversation_summary', 'Not available'))

            # Risk indicators with severity
            risk_indicators = ai_analysis.get('risk_indicators', [])
            if risk_indicators:
                doc.add_heading('Risk Indicators', 2)
                for risk in risk_indicators:
                    if isinstance(risk, dict):
                        severity = str(risk.get('severity', 'unknown')).upper()
                        indicator = risk.get('indicator', risk.get('description', risk.get('detail', '')))
                        action = risk.get('recommended_action', '')
                        doc.add_paragraph(f'[{severity}] {indicator}')
                        if action:
                            doc.add_paragraph(f'    Recommended: {action}')
                    else:
                        doc.add_paragraph(f'  {risk}')

            # AI-Detected Threats with quotes and actions
            threat_assessment = ai_analysis.get('threat_assessment', {})
            if threat_assessment.get('found'):
                doc.add_heading('AI-Detected Threats', 2)
                ai_messages = extracted_data.get('messages', [])
                for detail in threat_assessment.get('details', []):
                    if isinstance(detail, dict):
                        threat_type = detail.get('type', 'Unknown')
                        severity = str(detail.get('severity', 'unknown')).upper()
                        quote = detail.get('quote', '')
                        action = detail.get('recommended_action', '')
                        match = self._match_quote_to_message(quote, ai_messages)
                        ts_str = f" [{match['timestamp']}]" if match['timestamp'] else ''
                        sender_str = f" — {match['sender']}" if match['sender'] else ''
                        doc.add_paragraph(f'[{severity}] {threat_type}{sender_str}{ts_str}')
                        if quote:
                            doc.add_paragraph(f'    "{quote}"')
                        if action:
                            doc.add_paragraph(f'    Recommended: {action}')
                    else:
                        doc.add_paragraph(f'  {detail}')

            # Notable quotes
            notable_quotes = ai_analysis.get('notable_quotes', [])
            if notable_quotes:
                doc.add_heading('Key Excerpts', 2)
                for nq in notable_quotes[:10]:
                    if isinstance(nq, dict):
                        quote = nq.get('quote', '')
                        significance = nq.get('significance', '')
                        if quote:
                            doc.add_paragraph(f'"{quote}"')
                        if significance:
                            doc.add_paragraph(f'    Significance: {significance}')
                    else:
                        doc.add_paragraph(f'"{nq}"')

            # Recommendations
            recommendations = ai_analysis.get('recommendations', [])
            if recommendations:
                doc.add_heading('Recommendations', 2)
                for rec in recommendations:
                    doc.add_paragraph(f'  {rec}')

            doc.add_page_break()

        # === Legal Team Summary ===
        if legal_summary:
            doc.add_heading('Legal Team Summary', 1)
            doc.add_paragraph(
                'This section provides a comprehensive narrative summary of the analysis '
                'results, written for the legal team. It explains the key findings and '
                'how to use the accompanying output files.'
            )
            for paragraph in legal_summary.split('\n\n'):
                stripped = paragraph.strip()
                if stripped:
                    doc.add_paragraph(stripped)
            doc.add_page_break()

        # Executive Summary
        doc.add_heading('Executive Summary', 1)
        doc.add_paragraph(self._generate_executive_summary(
            extracted_data, analysis_results, review_decisions
        ))
        
        # Data Extraction Summary
        doc.add_heading('Data Extraction', 1)

        # Calculate metadata from extracted_data structure
        messages = extracted_data.get('messages', extracted_data.get('combined', []))
        total_messages = len(messages) if isinstance(messages, list) else 0

        date_range = self._compute_date_range(messages)
        sources = set()
        if messages and total_messages > 0:
            for msg in messages:
                if msg.get('source'):
                    sources.add(msg['source'])

        doc.add_paragraph(f"Total messages extracted: {total_messages}")
        doc.add_paragraph(f"Date range: {date_range}")
        doc.add_paragraph(f"Sources: {', '.join(sources) if sources else 'N/A'}")
        
        # Add screenshot count
        screenshots = extracted_data.get('screenshots', [])
        if screenshots:
            doc.add_paragraph(f"Screenshots cataloged: {len(screenshots)}")
        
        # Threat Analysis
        doc.add_heading('Threat Analysis', 1)
        threats = analysis_results.get('threats', {})
        threat_summary = threats.get('summary', {})
        threat_details = threats.get('details', [])
        
        messages_with_threats = threat_summary.get('messages_with_threats', 0)
        doc.add_paragraph(f"Threats detected: {messages_with_threats}")
        
        # Show high priority threats if available
        if threat_details and isinstance(threat_details, list):
            high_priority = [t for t in threat_details if t.get('threat_detected')][:5]
            if high_priority:
                doc.add_heading('High Priority Threats', 2)
                for threat in high_priority:
                    content = threat.get('content', '')[:200]
                    ts = threat.get('timestamp', '')
                    sender = threat.get('sender', '')
                    ts_display = f" [{ts}]" if ts else ''
                    sender_display = f" — {sender}" if sender else ''
                    doc.add_paragraph(f"• {content}{sender_display}{ts_display}")
        
        # Sentiment Analysis
        doc.add_heading('Sentiment Analysis', 1)
        sentiment = analysis_results.get('sentiment', [])
        
        # Calculate sentiment distribution if we have data
        if sentiment and isinstance(sentiment, list):
            positive = sum(1 for s in sentiment if s.get('sentiment_polarity') == 'positive')
            negative = sum(1 for s in sentiment if s.get('sentiment_polarity') == 'negative')
            neutral = sum(1 for s in sentiment if s.get('sentiment_polarity') == 'neutral')

            doc.add_paragraph(f"Sentiment distribution:")
            doc.add_paragraph(f"  • Positive: {positive}")
            doc.add_paragraph(f"  • Neutral: {neutral}")
            doc.add_paragraph(f"  • Negative: {negative}")
        else:
            doc.add_paragraph("Sentiment analysis data not available")

        # Emotional Escalation Patterns from AI
        if ai_analysis:
            sentiment_ai = ai_analysis.get('sentiment_analysis', {})
            shifts = sentiment_ai.get('shifts', [])
            if shifts:
                doc.add_heading('Emotional Escalation Patterns', 2)
                doc.add_paragraph(
                    'The following emotional shifts were detected by AI analysis, '
                    'indicating potential escalation patterns:'
                )
                for shift in shifts:
                    if isinstance(shift, dict):
                        from_state = shift.get('from', 'unknown')
                        to_state = shift.get('to', 'unknown')
                        position = shift.get('approximate_position', '')
                        doc.add_paragraph(f'    {from_state} -> {to_state} ({position})')
                    else:
                        doc.add_paragraph(f'    {shift}')

        # Manual Review Summary
        doc.add_heading('Manual Review', 1)
        doc.add_paragraph(f"Items reviewed: {review_decisions.get('total_reviewed', 0)}")
        doc.add_paragraph(f"Relevant: {review_decisions.get('relevant', 0)}")
        doc.add_paragraph(f"Not relevant: {review_decisions.get('not_relevant', 0)}")
        doc.add_paragraph(f"Uncertain: {review_decisions.get('uncertain', 0)}")

        # Third-Party Contacts
        third_party = extracted_data.get('third_party_contacts', [])
        if third_party:
            doc.add_heading('Third-Party Contacts', 1)
            doc.add_paragraph(
                f'{len(third_party)} third-party contacts were discovered during analysis '
                'from emails and screenshots. These are contacts not included in the '
                'configured person mappings.'
            )
            for entry in third_party:
                ident = entry.get('identifier', '')
                name = entry.get('display_name', '')
                entry_sources = ', '.join(entry.get('sources', []))
                label = f'{name} ({ident})' if name else ident
                doc.add_paragraph(f'  {label}  [source: {entry_sources}]')

        # Chain of Custody
        doc.add_heading('Chain of Custody', 1)
        doc.add_paragraph(
            f"Total recorded actions: {len(self.forensic.actions)}"
        )
        doc.add_paragraph(
            f"Session ID: {self.forensic.session_id}"
        )
        doc.add_paragraph(
            f"Session start: {self.forensic.start_time.isoformat()}"
        )
        doc.add_paragraph('See accompanying chain_of_custody.json for detailed forensic trail.')

        # Save document
        output_path = self.output_dir / f"forensic_report_{timestamp}.docx"
        doc.save(output_path)
        
        # Record hash
        file_hash = self.forensic.compute_hash(output_path)
        self.forensic.record_action(
            "word_report_generated",
            f"Generated Word report with hash {file_hash}",
            {"path": str(output_path), "hash": file_hash}
        )
        
        return output_path
    
    def _generate_pdf_report(self, extracted_data: Dict, analysis_results: Dict,
                           review_decisions: Dict, timestamp: str,
                           legal_summary: str = None) -> Path:
        """Generate PDF report."""
        output_path = self.output_dir / f"forensic_report_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        
        # Title
        elements.append(Paragraph("Forensic Message Analysis Report", title_style))
        elements.append(Spacer(1, 12))

        # Metadata
        elements.append(Paragraph(f"<b>Generated:</b> {self.compliance.format_timestamp()}", styles['Normal']))
        elements.append(Paragraph(f"<b>Case ID:</b> {timestamp}", styles['Normal']))
        elements.append(PageBreak())

        # ----- Legal Compliance Header -----
        header = self.compliance.generate_report_header()
        elements.append(Paragraph("Case Information", styles['Heading1']))
        case_info_data = [
            ['Field', 'Value'],
            ['Case Number', header['case_number']],
            ['Case Name', header['case_name']],
            ['Examiner', header['examiner_name']],
            ['Organization', header['organization']],
            ['Date of Examination', header['date_of_examination']],
            ['Tools Used', header['tools_used']],
        ]
        case_info_table = Table(case_info_data, colWidths=[2.5 * inch, 3.5 * inch])
        case_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4788')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f4fa')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(case_info_table)
        elements.append(Spacer(1, 16))

        # Methodology Statement
        elements.append(Paragraph("Methodology", styles['Heading1']))
        methodology = self.compliance.generate_methodology_statement()
        for line in methodology.split('\n'):
            stripped = line.strip()
            if stripped and stripped != '=' * len(stripped):
                elements.append(Paragraph(stripped, styles['Normal']))
        elements.append(Spacer(1, 12))

        # Standards Compliance Statement
        elements.append(Paragraph("Standards Compliance", styles['Heading1']))
        compliance_stmt = self.compliance.get_standards_compliance_statement()
        for line in compliance_stmt.split('\n'):
            stripped = line.strip()
            if stripped and stripped != '=' * len(stripped):
                elements.append(Paragraph(stripped, styles['Normal']))
        elements.append(PageBreak())

        # === AI-Powered Findings Summary ===
        ai_analysis = analysis_results.get('ai_analysis', {})
        if ai_analysis and ai_analysis.get('conversation_summary') and \
           'not configured' not in ai_analysis.get('conversation_summary', '').lower():
            elements.append(Paragraph("Findings Summary", styles['Heading1']))
            elements.append(Paragraph(
                'This section provides AI-assisted analysis findings for rapid legal team review. '
                'AI findings are supplementary and should be validated against the underlying evidence.',
                styles['Normal']
            ))
            elements.append(Spacer(1, 12))

            # AI Executive Summary
            elements.append(Paragraph("AI Analysis Overview", styles['Heading2']))
            elements.append(Paragraph(
                self._esc(ai_analysis.get('conversation_summary', 'Not available')), styles['Normal']
            ))
            elements.append(Spacer(1, 12))

            # Risk indicators with severity
            risk_indicators = ai_analysis.get('risk_indicators', [])
            if risk_indicators:
                elements.append(Paragraph("Risk Indicators", styles['Heading2']))
                for risk in risk_indicators:
                    if isinstance(risk, dict):
                        severity = str(risk.get('severity', 'unknown')).upper()
                        indicator = risk.get('indicator', risk.get('description', risk.get('detail', '')))
                        action = risk.get('recommended_action', '')
                        elements.append(Paragraph(
                            f"<b>[{self._esc(severity)}]</b> {self._esc(indicator)}", styles['Normal']
                        ))
                        if action:
                            elements.append(Paragraph(
                                f"&nbsp;&nbsp;&nbsp;&nbsp;Recommended: {self._esc(action)}", styles['Normal']
                            ))
                    else:
                        elements.append(Paragraph(f"&nbsp;&nbsp;{self._esc(risk)}", styles['Normal']))
                elements.append(Spacer(1, 12))

            # AI-Detected Threats with quotes and actions
            threat_assessment = ai_analysis.get('threat_assessment', {})
            if threat_assessment.get('found'):
                elements.append(Paragraph("AI-Detected Threats", styles['Heading2']))
                ai_messages = extracted_data.get('messages', [])
                for detail in threat_assessment.get('details', []):
                    if isinstance(detail, dict):
                        threat_type = detail.get('type', 'Unknown')
                        severity = str(detail.get('severity', 'unknown')).upper()
                        quote = detail.get('quote', '')
                        action = detail.get('recommended_action', '')
                        match = self._match_quote_to_message(quote, ai_messages)
                        ts_str = f" [{self._esc(str(match['timestamp']))}]" if match['timestamp'] else ''
                        sender_str = f" &mdash; {self._esc(match['sender'])}" if match['sender'] else ''
                        elements.append(Paragraph(
                            f"<b>[{self._esc(severity)}]</b> {self._esc(threat_type)}{sender_str}{ts_str}", styles['Normal']
                        ))
                        if quote:
                            elements.append(Paragraph(
                                f'&nbsp;&nbsp;&nbsp;&nbsp;"{self._esc(quote)}"', styles['Normal']
                            ))
                        if action:
                            elements.append(Paragraph(
                                f"&nbsp;&nbsp;&nbsp;&nbsp;Recommended: {self._esc(action)}", styles['Normal']
                            ))
                    else:
                        elements.append(Paragraph(f"&nbsp;&nbsp;{self._esc(detail)}", styles['Normal']))
                elements.append(Spacer(1, 12))

            # Recommendations
            recommendations = ai_analysis.get('recommendations', [])
            if recommendations:
                elements.append(Paragraph("Recommendations", styles['Heading2']))
                for rec in recommendations:
                    elements.append(Paragraph(f"&nbsp;&nbsp;{self._esc(rec)}", styles['Normal']))
                elements.append(Spacer(1, 12))

            elements.append(PageBreak())

        # === Legal Team Summary ===
        if legal_summary:
            elements.append(Paragraph("Legal Team Summary", styles['Heading1']))
            elements.append(Paragraph(
                'This section provides a comprehensive narrative summary of the analysis '
                'results, written for the legal team. It explains the key findings and '
                'how to use the accompanying output files.',
                styles['Normal']
            ))
            elements.append(Spacer(1, 12))
            for paragraph in legal_summary.split('\n\n'):
                stripped = paragraph.strip()
                if stripped:
                    elements.append(Paragraph(self._esc(stripped), styles['Normal']))
                    elements.append(Spacer(1, 8))
            elements.append(PageBreak())

        # Executive Summary
        elements.append(Paragraph("Executive Summary", styles['Heading1']))
        summary = self._generate_executive_summary(extracted_data, analysis_results, review_decisions)
        elements.append(Paragraph(self._esc(summary), styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Data Overview Table
        elements.append(Paragraph("Data Overview", styles['Heading1']))
        
        # Calculate metadata from extracted_data structure
        messages = extracted_data.get('messages', extracted_data.get('combined', []))
        total_messages = len(messages) if isinstance(messages, list) else 0

        date_range = self._compute_date_range(messages)
        sources = set()
        if messages and total_messages > 0:
            for msg in messages:
                if msg.get('source'):
                    sources.add(msg['source'])

        overview_data = [
            ['Metric', 'Value'],
            ['Total Messages', str(total_messages)],
            ['Date Range', date_range],
            ['Sources', ', '.join(sources) if sources else 'N/A'],
            ['Threats Detected', str(analysis_results.get('threats', {}).get('summary', {}).get('messages_with_threats', 0))],
            ['Items Reviewed', str(review_decisions.get('total_reviewed', 0))]
        ]
        
        overview_table = Table(overview_data, colWidths=[3*inch, 3*inch])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(overview_table)
        elements.append(Spacer(1, 20))
        
        # Add Screenshots count if available
        screenshots = extracted_data.get('screenshots', [])
        if screenshots:
            elements.append(Paragraph(f"<b>Screenshots cataloged:</b> {len(screenshots)}", styles['Normal']))
            elements.append(Spacer(1, 12))
        
        # Threat Analysis Section
        elements.append(Paragraph("Threat Analysis", styles['Heading1']))
        threats = analysis_results.get('threats', {})
        threat_summary = threats.get('summary', {})
        threat_details = threats.get('details', [])
        
        messages_with_threats = threat_summary.get('messages_with_threats', 0)
        elements.append(Paragraph(f"<b>Threats detected:</b> {messages_with_threats}", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Show high priority threats if available
        if threat_details and isinstance(threat_details, list):
            high_priority = [t for t in threat_details if t.get('threat_detected')][:5]
            if high_priority:
                elements.append(Paragraph("High Priority Threats", styles['Heading2']))
                for threat in high_priority:
                    content = threat.get('content', '')[:200]
                    ts = threat.get('timestamp', '')
                    sender = threat.get('sender', '')
                    ts_display = f" [{self._esc(str(ts))}]" if ts else ''
                    sender_display = f" &mdash; {self._esc(sender)}" if sender else ''
                    elements.append(Paragraph(
                        f"&bull; {self._esc(content)}{sender_display}{ts_display}",
                        styles['Normal']
                    ))
                elements.append(Spacer(1, 12))
        
        # Sentiment Analysis Section
        elements.append(Paragraph("Sentiment Analysis", styles['Heading1']))
        sentiment = analysis_results.get('sentiment', [])
        
        # Calculate sentiment distribution if we have data
        if sentiment and isinstance(sentiment, list):
            positive = sum(1 for s in sentiment if s.get('sentiment_polarity') == 'positive')
            negative = sum(1 for s in sentiment if s.get('sentiment_polarity') == 'negative')
            neutral = sum(1 for s in sentiment if s.get('sentiment_polarity') == 'neutral')
            
            elements.append(Paragraph("<b>Sentiment distribution:</b>", styles['Normal']))
            elements.append(Paragraph(f"• Positive: {positive}", styles['Normal']))
            elements.append(Paragraph(f"• Neutral: {neutral}", styles['Normal']))
            elements.append(Paragraph(f"• Negative: {negative}", styles['Normal']))
            elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("Sentiment analysis data not available", styles['Normal']))
            elements.append(Spacer(1, 12))

        # Emotional Escalation Patterns from AI
        if ai_analysis:
            sentiment_ai = ai_analysis.get('sentiment_analysis', {})
            shifts = sentiment_ai.get('shifts', [])
            if shifts:
                elements.append(Paragraph("Emotional Escalation Patterns", styles['Heading2']))
                elements.append(Paragraph(
                    'The following emotional shifts were detected by AI analysis, '
                    'indicating potential escalation patterns:',
                    styles['Normal']
                ))
                for shift in shifts:
                    if isinstance(shift, dict):
                        from_state = shift.get('from', 'unknown')
                        to_state = shift.get('to', 'unknown')
                        position = shift.get('approximate_position', '')
                        elements.append(Paragraph(
                            f"&nbsp;&nbsp;&nbsp;&nbsp;{self._esc(from_state)} -&gt; {self._esc(to_state)} ({self._esc(position)})",
                            styles['Normal']
                        ))
                    else:
                        elements.append(Paragraph(
                            f"&nbsp;&nbsp;&nbsp;&nbsp;{self._esc(shift)}", styles['Normal']
                        ))
                elements.append(Spacer(1, 12))

        # Manual Review Section
        elements.append(Paragraph("Manual Review", styles['Heading1']))
        elements.append(Paragraph(f"<b>Items reviewed:</b> {review_decisions.get('total_reviewed', 0)}", styles['Normal']))
        elements.append(Paragraph(f"<b>Relevant:</b> {review_decisions.get('relevant', 0)}", styles['Normal']))
        elements.append(Paragraph(f"<b>Not relevant:</b> {review_decisions.get('not_relevant', 0)}", styles['Normal']))
        elements.append(Paragraph(f"<b>Uncertain:</b> {review_decisions.get('uncertain', 0)}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Third-Party Contacts Section
        third_party = extracted_data.get('third_party_contacts', [])
        if third_party:
            elements.append(Paragraph("Third-Party Contacts", styles['Heading1']))
            elements.append(Paragraph(
                f'{len(third_party)} third-party contacts were discovered during analysis '
                'from emails and screenshots. These are contacts not included in the '
                'configured person mappings.',
                styles['Normal'],
            ))
            elements.append(Spacer(1, 8))
            tp_rows = [['Identifier', 'Display Name', 'Source']]
            for entry in third_party:
                ident = entry.get('identifier', '')
                name = entry.get('display_name', '')
                entry_sources = ', '.join(entry.get('sources', []))
                tp_rows.append([ident, name, entry_sources])
            tp_table = Table(tp_rows, colWidths=[2.5 * inch, 2 * inch, 1.5 * inch])
            tp_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f4fa')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(tp_table)
            elements.append(Spacer(1, 20))

        # Chain of Custody Section
        elements.append(Paragraph("Chain of Custody", styles['Heading1']))
        elements.append(Paragraph(
            f"<b>Total recorded actions:</b> {len(self.forensic.actions)}", styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Session ID:</b> {self.forensic.session_id}", styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Session start:</b> {self.forensic.start_time.isoformat()}", styles['Normal']
        ))
        elements.append(Paragraph("See accompanying chain_of_custody.json for detailed forensic trail.", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Build PDF
        doc.build(elements)
        
        # Record hash
        file_hash = self.forensic.compute_hash(output_path)
        self.forensic.record_action(
            "pdf_report_generated",
            f"Generated PDF report with hash {file_hash}",
            {"path": str(output_path), "hash": file_hash}
        )
        
        return output_path
    
    def _generate_json_report(self, extracted_data: Dict, analysis_results: Dict,
                            review_decisions: Dict, timestamp: str,
                            legal_summary: str = None) -> Path:
        """Generate JSON report."""
        report = {
            "metadata": {
                "type": "Forensic Message Analysis Report",
                "generated": datetime.now().isoformat(),
                "case_id": timestamp,
                "version": "1.0"
            },
            "extraction": extracted_data,
            "analysis": analysis_results,
            "review": review_decisions,
            "legal_team_summary": legal_summary,
            "summary": {
                "total_messages": len(extracted_data.get('messages', [])),
                "threats_detected": analysis_results.get('threats', {}).get('summary', {}).get('messages_with_threats', 0),
                "items_reviewed": review_decisions.get('total_reviewed', 0),
                "relevant_items": review_decisions.get('relevant', 0)
            }
        }
        
        output_path = self.output_dir / f"forensic_report_{timestamp}.json"
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Record hash
        file_hash = self.forensic.compute_hash(output_path)
        self.forensic.record_action(
            "json_report_generated",
            f"Generated JSON report with hash {file_hash}",
            {"path": str(output_path), "hash": file_hash}
        )

        return output_path

    def _generate_legal_summary_docx(self, legal_summary: str, output_path: Path,
                                      reports: Dict[str, Any] = None):
        """Generate a formatted Word document from the legal team summary text.

        Parses the AI-generated narrative and produces a professional document
        with case header, formatted paragraphs, an output file reference table,
        and a compliance footer.

        Args:
            legal_summary: Plain text narrative from Claude.
            output_path: Path for the output .docx file.
            reports: Dict mapping report type keys to file paths. Used to build
                     the output file reference table with actual filenames.
        """
        doc = Document()

        # Default font
        style = doc.styles['Normal']
        font = style.font
        font.name = 'Calibri'
        font.size = Pt(11)

        # Title
        title = doc.add_heading('Legal Team Summary', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Case header
        header = self.compliance.generate_report_header()
        doc.add_paragraph(f"Case Number: {header['case_number']}")
        doc.add_paragraph(f"Case Name: {header['case_name']}")
        doc.add_paragraph(f"Generated: {header['date_of_examination']}")
        if header['examiner_name'] != 'Not specified':
            doc.add_paragraph(f"Examiner: {header['examiner_name']}")
        doc.add_paragraph('')  # spacer

        # Body -- split on double newlines for paragraph breaks,
        # preserving single newlines within paragraphs.
        for block in legal_summary.split('\n\n'):
            text = block.strip()
            if not text:
                continue
            doc.add_paragraph(text)

        # Output file reference table
        if reports:
            doc.add_paragraph('')
            doc.add_heading('Output File Reference', level=1)
            doc.add_paragraph(
                'The following files were generated alongside this summary. '
                'All files are in the same output directory.'
            )

            # Define descriptions and guidance for each report type
            file_info = {
                'excel': (
                    'Excel Report',
                    'Start here. Contains per-person tabs with messages, integrated '
                    'threat/sentiment columns, a Findings Summary sheet, Timeline, '
                    'AI Analysis, Conversation Threads, and Third Party Contacts. '
                    'Use filters and search to locate specific conversations.'
                ),
                'word': (
                    'Word Report',
                    'Comprehensive narrative report with case information, methodology, '
                    'legal compliance statements, findings summary, threat analysis, '
                    'and chain of custody reference. Suitable for court filing.'
                ),
                'pdf': (
                    'PDF Report',
                    'Same content as the Word report, formatted for distribution '
                    'and printing. Use this for court submission or sharing with '
                    'opposing counsel.'
                ),
                'html': (
                    'HTML Report',
                    'Interactive report with per-person message tables, inline images, '
                    'conversation threads, risk indicators, and legal appendices '
                    '(Methodology, Completeness Validation, Limitations). Open in any '
                    'web browser.'
                ),
                'html_pdf': (
                    'HTML Report (PDF)',
                    'PDF conversion of the HTML report for printing or court submission.'
                ),
                'chat_html': (
                    'Chat Bubble Report',
                    'iMessage-style conversation view with left/right aligned message '
                    'bubbles, inline attachments, edit history, deleted message badges, '
                    'and URL previews. Best for reviewing conversations in context.'
                ),
                'json': (
                    'JSON Report',
                    'Machine-readable output with all analysis data. Intended for '
                    'technical review or import into other forensic tools.'
                ),
                'forensic_json': (
                    'Forensic JSON Report',
                    'Complete forensic data export with metadata and chain of custody.'
                ),
                'timeline': (
                    'Interactive Timeline',
                    'Chronological visualization of flagged events (threats, SOS, '
                    'patterns) alongside all email communications. Open in any web '
                    'browser. Use this to see the full chronology of events.'
                ),
                'chain_of_custody': (
                    'Chain of Custody',
                    'Complete forensic audit trail with SHA-256 hashes, timestamps, '
                    'and all operations performed. Required for FRE 901 authentication.'
                ),
                'manifest': (
                    'Run Manifest',
                    'Documentation of all inputs processed, outputs generated, and '
                    'processing steps taken. Supports FRE 803(6) business records.'
                ),
            }

            table = doc.add_table(rows=1, cols=3)
            table.style = 'Light Grid Accent 1'

            # Header row
            hdr = table.rows[0].cells
            for i, text in enumerate(['File', 'Type', 'How to Use']):
                hdr[i].text = text
                for paragraph in hdr[i].paragraphs:
                    for run in paragraph.runs:
                        run.bold = True
                        run.font.size = Pt(10)

            for key, path_val in reports.items():
                path = Path(str(path_val))
                filename = path.name

                if key in file_info:
                    label, guidance = file_info[key]
                else:
                    label = key.replace('_', ' ').title()
                    guidance = ''

                row = table.add_row().cells
                # Filename in bold blue
                fn_para = row[0].paragraphs[0]
                fn_run = fn_para.add_run(filename)
                fn_run.bold = True
                fn_run.font.size = Pt(9)
                fn_run.font.color.rgb = RGBColor(0x1F, 0x4E, 0x79)

                # Type label
                type_para = row[1].paragraphs[0]
                type_run = type_para.add_run(label)
                type_run.font.size = Pt(10)

                # Guidance
                guide_para = row[2].paragraphs[0]
                guide_run = guide_para.add_run(guidance)
                guide_run.font.size = Pt(10)

            # Set column widths
            for row in table.rows:
                row.cells[0].width = Inches(2.5)
                row.cells[1].width = Inches(1.3)
                row.cells[2].width = Inches(3.7)

            # Note about files generated after this summary
            note_para = doc.add_paragraph()
            note_run = note_para.add_run(
                'Note: The interactive timeline, chain of custody, and run manifest '
                'are generated after this summary and will also be present in the '
                'output directory.'
            )
            note_run.font.size = Pt(9)
            note_run.font.italic = True

        # Compliance footer
        doc.add_paragraph('')
        footer_para = doc.add_paragraph()
        footer_run = footer_para.add_run(
            'This summary was generated by the Forensic Message Analyzer '
            f"v{header['tools_used'].split('v')[-1] if 'v' in header['tools_used'] else 'N/A'} "
            'using AI-assisted analysis. Findings are supplementary and should be '
            'validated against the underlying evidence and accompanying forensic reports.'
        )
        footer_run.font.size = Pt(9)
        footer_run.font.italic = True

        doc.save(str(output_path))

    def _generate_legal_team_summary(self, extracted_data: Dict,
                                     analysis_results: Dict,
                                     review_decisions: Dict) -> str:
        """
        Generate a comprehensive narrative summary for the legal team using Claude.

        Explains all findings and how to interpret the output files.
        Returns None if AI is not available.
        """
        try:
            from anthropic import Anthropic
        except ImportError:
            logger.info("Anthropic not available, skipping legal team summary")
            return None

        if not self.config.ai_api_key:
            logger.info("AI API key not configured, skipping legal team summary")
            return None

        # Skip API call if there's no actual data to summarize
        messages = extracted_data.get('messages', extracted_data.get('combined', []))
        total_messages = len(messages) if isinstance(messages, list) else 0
        if total_messages == 0:
            logger.info("No messages to summarize, skipping legal team summary")
            return None

        # Source breakdown
        source_counts = {}
        if messages and isinstance(messages, list):
            for msg in messages:
                src = msg.get('source', 'unknown')
                source_counts[src] = source_counts.get(src, 0) + 1

        # Date range
        date_range = self._compute_date_range(messages)

        # Threat stats
        threats = analysis_results.get('threats', {})
        threat_count = threats.get('summary', {}).get('messages_with_threats', 0)
        threat_categories = threats.get('summary', {}).get('category_counts', {})

        # Sentiment stats
        sentiment = analysis_results.get('sentiment', [])
        sentiment_dist = {'positive': 0, 'neutral': 0, 'negative': 0}
        if sentiment and isinstance(sentiment, list):
            for s in sentiment:
                pol = s.get('sentiment_polarity', 'neutral')
                if pol in sentiment_dist:
                    sentiment_dist[pol] += 1

        # AI analysis stats
        ai_analysis = analysis_results.get('ai_analysis', {})
        risk_indicators = ai_analysis.get('risk_indicators', [])
        ai_threat_severity = ai_analysis.get('threat_assessment', {}).get('severity', 'none')
        recommendations = ai_analysis.get('recommendations', [])

        # Review stats
        total_reviewed = review_decisions.get('total_reviewed', 0)
        relevant = review_decisions.get('relevant', 0)

        # Third-party contacts
        third_party = extracted_data.get('third_party_contacts', [])

        # Build the prompt
        context = (
            f"DATASET OVERVIEW:\n"
            f"- Total messages analyzed: {total_messages}\n"
            f"- Date range: {date_range}\n"
            f"- Sources: {', '.join(f'{src}: {count}' for src, count in source_counts.items())}\n"
            f"- Screenshots cataloged: {len(extracted_data.get('screenshots', []))}\n\n"
            f"THREAT ANALYSIS:\n"
            f"- Messages with threats detected: {threat_count}\n"
            f"- Threat categories: {json.dumps(threat_categories) if threat_categories else 'None'}\n\n"
            f"AI RISK ASSESSMENT:\n"
            f"- Overall threat severity: {ai_threat_severity}\n"
            f"- Risk indicators found: {len(risk_indicators)}\n"
        )
        for ri in risk_indicators[:10]:
            if isinstance(ri, dict):
                sev = ri.get('severity', 'unknown')
                desc = ri.get('indicator', ri.get('description', ri.get('detail', '')))
                context += f"  [{sev}] {desc}\n"
            else:
                context += f"  {ri}\n"

        context += (
            f"\nSENTIMENT ANALYSIS:\n"
            f"- Positive messages: {sentiment_dist['positive']}\n"
            f"- Neutral messages: {sentiment_dist['neutral']}\n"
            f"- Negative messages: {sentiment_dist['negative']}\n\n"
            f"MANUAL REVIEW:\n"
            f"- Items reviewed: {total_reviewed}\n"
            f"- Confirmed relevant: {relevant}\n\n"
            f"THIRD-PARTY CONTACTS:\n"
            f"- Unmapped contacts discovered: {len(third_party)}\n\n"
            f"AI RECOMMENDATIONS:\n"
        )
        for rec in recommendations[:10]:
            context += f"- {rec}\n"

        context += (
            f"\nOUTPUT FILES GENERATED:\n"
            f"- Excel report (.xlsx): Contains per-person tabs with filtered messages, "
            f"threat indicators, and sentiment data for each configured party. "
            f"Start here for exploring specific conversations.\n"
            f"- Word report (.docx): Narrative analysis with findings summary, "
            f"risk indicators, threat details, and chain of custody\n"
            f"- PDF report (.pdf): Same content as Word, formatted for court submission\n"
            f"- HTML report (.html): Interactive report with per-person message tables, "
            f"inline images, conversation threads, and legal appendices\n"
            f"- Chat-bubble report (_chat.html): iMessage-style conversation view with "
            f"message bubbles, edit history, deleted message badges, and URL previews. "
            f"Best for reading conversations in context.\n"
            f"- Timeline (.html): Interactive chronological visualization of all messages "
            f"and flagged events\n"
            f"- Chain of custody (.json): Complete forensic audit trail\n"
            f"- Run manifest (.json): Documentation of all inputs, outputs, and processing steps\n"
            f"\nA detailed file reference table with exact filenames and usage guidance "
            f"will be appended to the legal team summary document after this narrative.\n"
        )

        system_prompt = (
            "You are a forensic analyst writing a comprehensive summary for "
            "attorneys and paralegals working on a family law matter. Your summary "
            "should be written in plain, professional language suitable for legal "
            "professionals who are NOT technicians.\n\n"
            "Write a narrative summary that:\n"
            "1. Opens with a brief overview of what was analyzed and the scope of the data\n"
            "2. Summarizes the most important findings — threats, risks, and concerning patterns\n"
            "3. Explains the sentiment analysis results and what they mean for the case\n"
            "4. Notes any third-party contacts discovered that may be relevant\n"
            "5. Describes what each output file contains and how the legal team should use it:\n"
            "   - Which file to open first\n"
            "   - How to find specific conversations in the Excel report\n"
            "   - How to interpret threat and sentiment columns\n"
            "   - When to reference the timeline vs. the Excel report\n"
            "6. Closes with recommended next steps for the legal team\n\n"
            "Keep it to 4-6 paragraphs. Use factual language. Do not speculate beyond "
            "what the data shows. Reference specific numbers from the analysis."
        )

        try:
            client = Anthropic(
                api_key=self.config.ai_api_key,
                base_url="https://api.anthropic.com",
            )
            model = self.config.ai_summary_model or self.config.ai_model or 'claude-sonnet-4-20250514'
            response = client.messages.create(
                model=model,
                system=[{
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": context}],
                temperature=0.3,
                max_tokens=2048,
            )
            result = response.content[0].text

            # Track tokens from this sync API call (standard rates, not batch)
            legal_input = response.usage.input_tokens
            legal_output = response.usage.output_tokens

            rp = get_pricing(model)
            sync_cost = (legal_input / 1_000_000) * rp['input'] + (legal_output / 1_000_000) * rp['output']

            # Update AI processing stats if available
            ai_stats = analysis_results.get('ai_analysis', {}).get('processing_stats')
            if ai_stats is not None:
                ai_stats["input_tokens"] = ai_stats.get("input_tokens", 0) + legal_input
                ai_stats["output_tokens"] = ai_stats.get("output_tokens", 0) + legal_output
                ai_stats["tokens_used"] = ai_stats.get("tokens_used", 0) + legal_input + legal_output
                ai_stats["api_calls"] = ai_stats.get("api_calls", 0) + 1
                ai_stats["legal_summary_sync_cost_usd"] = round(sync_cost, 4)
                ai_stats["estimated_cost_usd"] = round(
                    ai_stats.get("estimated_cost_usd", 0) + sync_cost, 4
                )

            print(f"    Legal team summary: {legal_input:,} input + {legal_output:,} output tokens (~${sync_cost:.4f})")

            self.forensic.record_action(
                "legal_team_summary_generated",
                "Generated AI-powered legal team summary",
                {"model": model, "length": len(result),
                 "input_tokens": legal_input, "output_tokens": legal_output,
                 "estimated_cost_usd": round(sync_cost, 4)}
            )
            return result

        except Exception as e:
            logger.error(f"Failed to generate legal team summary: {e}")
            self.forensic.record_action(
                "legal_team_summary_error",
                f"Error generating legal team summary: {str(e)}",
                {"error": str(e)}
            )
            return None

    def _generate_executive_summary(self, extracted_data: Dict,
                                   analysis_results: Dict,
                                   review_decisions: Dict) -> str:
        """Generate executive summary for legal team review."""
        messages = extracted_data.get('messages', extracted_data.get('combined', []))
        total_messages = len(messages) if isinstance(messages, list) else 0
        threats = analysis_results.get('threats', {}).get('summary', {}).get('messages_with_threats', 0)
        reviewed = review_decisions.get('total_reviewed', 0)
        relevant = review_decisions.get('relevant', 0)

        ai_analysis = analysis_results.get('ai_analysis', {})
        ai_summary = ai_analysis.get('conversation_summary', '')
        risk_count = len(ai_analysis.get('risk_indicators', []))
        ai_threats_found = ai_analysis.get('threat_assessment', {}).get('found', False)
        ai_threat_severity = ai_analysis.get('threat_assessment', {}).get('severity', 'none')

        summary = (
            f"This forensic analysis examined {total_messages} digital communications "
            f"extracted from multiple sources. Pattern-based automated analysis identified "
            f"{threats} messages containing potentially threatening or concerning content. "
        )

        if reviewed > 0:
            summary += (
                f"Of the items flagged for manual review, {reviewed} were examined by "
                f"a qualified analyst, with {relevant} confirmed as relevant to the proceedings. "
            )

        if ai_summary and 'not available' not in ai_summary.lower() and 'not configured' not in ai_summary.lower():
            summary += (
                f"\n\nAI-assisted analysis (Claude Opus) identified {risk_count} distinct risk "
                f"indicators. "
            )
            if ai_threats_found:
                summary += (
                    f"Threats were detected with an overall severity assessment of "
                    f"{ai_threat_severity}. "
                )
            summary += f"\n\n{ai_summary}"

        summary += (
            "\n\nAll data handling maintained forensic integrity through SHA-256 "
            "cryptographic hashing and comprehensive chain of custody documentation. "
            "See the Findings Summary section for detailed risk indicators, key excerpts, "
            "and recommended actions."
        )

        return summary.strip()

    def _generate_limitations(self, analysis_results: Dict) -> list:
        """Generate limitation statements based on available data and features."""
        return generate_limitations(self.config, analysis_results)
