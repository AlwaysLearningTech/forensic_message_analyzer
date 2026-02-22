import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import logging
import json
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from ..config import Config
from ..forensic_utils import ForensicRecorder
from ..utils.legal_compliance import LegalComplianceManager

# Initialize config
config = Config()

logger = logging.getLogger(__name__)


class ForensicReporter:
    """
    Generate forensic reports in multiple formats.
    Ensures legal defensibility and chain of custody documentation.
    """
    
    def __init__(self, forensic_recorder: ForensicRecorder):
        """
        Initialize the forensic reporter.

        Args:
            forensic_recorder: ForensicRecorder instance for chain of custody
        """
        self.forensic = forensic_recorder
        self.compliance = LegalComplianceManager(config=config, forensic_recorder=forensic_recorder)
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
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
        
        # Generate Word report
        try:
            word_path = self._generate_word_report(
                extracted_data, analysis_results, review_decisions, timestamp
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
                extracted_data, analysis_results, review_decisions, timestamp
            )
            reports['pdf'] = pdf_path
            logger.info(f"Generated PDF report: {pdf_path}")
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            self.forensic.record_action(
                "report_generation_error",
                f"PDF report generation failed: {str(e)}"
            )
        
        # Generate JSON report (always succeeds)
        json_path = self._generate_json_report(
            extracted_data, analysis_results, review_decisions, timestamp
        )
        reports['json'] = json_path
        logger.info(f"Generated JSON report: {json_path}")
        
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
                            review_decisions: Dict, timestamp: str) -> Path:
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
                        indicator = risk.get('indicator', risk.get('description', ''))
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
                for detail in threat_assessment.get('details', []):
                    if isinstance(detail, dict):
                        threat_type = detail.get('type', 'Unknown')
                        severity = str(detail.get('severity', 'unknown')).upper()
                        quote = detail.get('quote', '')
                        action = detail.get('recommended_action', '')
                        doc.add_paragraph(f'[{severity}] {threat_type}')
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
        
        # Calculate date range if we have messages
        date_range = 'N/A'
        sources = set()
        if messages and total_messages > 0:
            # Filter out None timestamps first
            timestamps = [msg.get('timestamp') for msg in messages if msg.get('timestamp') is not None]
            if timestamps:
                # Convert string timestamps to datetime if needed
                dt_timestamps = []
                for ts in timestamps:
                    try:
                        if isinstance(ts, str):
                            parsed = pd.to_datetime(ts)
                            if not pd.isna(parsed):
                                dt_timestamps.append(parsed)
                        elif hasattr(ts, 'year') and not pd.isna(ts):
                            dt_timestamps.append(ts)
                    except Exception:
                        pass
                
                if dt_timestamps:
                    min_date = min(dt_timestamps)
                    max_date = max(dt_timestamps)
                    date_range = f"{min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}"
            
            # Get unique sources
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
                    content = threat.get('content', '')[:100]
                    doc.add_paragraph(f"• {content}...")
        
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
                           review_decisions: Dict, timestamp: str) -> Path:
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
                ai_analysis.get('conversation_summary', 'Not available'), styles['Normal']
            ))
            elements.append(Spacer(1, 12))

            # Risk indicators with severity
            risk_indicators = ai_analysis.get('risk_indicators', [])
            if risk_indicators:
                elements.append(Paragraph("Risk Indicators", styles['Heading2']))
                for risk in risk_indicators:
                    if isinstance(risk, dict):
                        severity = str(risk.get('severity', 'unknown')).upper()
                        indicator = risk.get('indicator', risk.get('description', ''))
                        action = risk.get('recommended_action', '')
                        elements.append(Paragraph(
                            f"<b>[{severity}]</b> {indicator}", styles['Normal']
                        ))
                        if action:
                            elements.append(Paragraph(
                                f"&nbsp;&nbsp;&nbsp;&nbsp;Recommended: {action}", styles['Normal']
                            ))
                    else:
                        elements.append(Paragraph(f"&nbsp;&nbsp;{risk}", styles['Normal']))
                elements.append(Spacer(1, 12))

            # AI-Detected Threats with quotes and actions
            threat_assessment = ai_analysis.get('threat_assessment', {})
            if threat_assessment.get('found'):
                elements.append(Paragraph("AI-Detected Threats", styles['Heading2']))
                for detail in threat_assessment.get('details', []):
                    if isinstance(detail, dict):
                        threat_type = detail.get('type', 'Unknown')
                        severity = str(detail.get('severity', 'unknown')).upper()
                        quote = detail.get('quote', '')
                        action = detail.get('recommended_action', '')
                        elements.append(Paragraph(
                            f"<b>[{severity}]</b> {threat_type}", styles['Normal']
                        ))
                        if quote:
                            elements.append(Paragraph(
                                f'&nbsp;&nbsp;&nbsp;&nbsp;"{quote}"', styles['Normal']
                            ))
                        if action:
                            elements.append(Paragraph(
                                f"&nbsp;&nbsp;&nbsp;&nbsp;Recommended: {action}", styles['Normal']
                            ))
                    else:
                        elements.append(Paragraph(f"&nbsp;&nbsp;{detail}", styles['Normal']))
                elements.append(Spacer(1, 12))

            # Recommendations
            recommendations = ai_analysis.get('recommendations', [])
            if recommendations:
                elements.append(Paragraph("Recommendations", styles['Heading2']))
                for rec in recommendations:
                    elements.append(Paragraph(f"&nbsp;&nbsp;{rec}", styles['Normal']))
                elements.append(Spacer(1, 12))

            elements.append(PageBreak())

        # Executive Summary
        elements.append(Paragraph("Executive Summary", styles['Heading1']))
        summary = self._generate_executive_summary(extracted_data, analysis_results, review_decisions)
        elements.append(Paragraph(summary, styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Data Overview Table
        elements.append(Paragraph("Data Overview", styles['Heading1']))
        
        # Calculate metadata from extracted_data structure
        messages = extracted_data.get('messages', extracted_data.get('combined', []))
        total_messages = len(messages) if isinstance(messages, list) else 0
        
        # Calculate date range
        date_range = 'N/A'
        sources = set()
        if messages and total_messages > 0:
            # Filter out None timestamps first
            timestamps = [msg.get('timestamp') for msg in messages if msg.get('timestamp') is not None]
            if timestamps:
                dt_timestamps = []
                for ts in timestamps:
                    try:
                        if isinstance(ts, str):
                            parsed = pd.to_datetime(ts)
                            if not pd.isna(parsed):
                                dt_timestamps.append(parsed)
                        elif hasattr(ts, 'year') and not pd.isna(ts):
                            dt_timestamps.append(ts)
                    except Exception:
                        pass
                
                if dt_timestamps:
                    min_date = min(dt_timestamps)
                    max_date = max(dt_timestamps)
                    date_range = f"{min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}"
            
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
                    content = threat.get('content', '')[:100]
                    elements.append(Paragraph(f"• {content}...", styles['Normal']))
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
                            f"&nbsp;&nbsp;&nbsp;&nbsp;{from_state} -&gt; {to_state} ({position})",
                            styles['Normal']
                        ))
                    else:
                        elements.append(Paragraph(
                            f"&nbsp;&nbsp;&nbsp;&nbsp;{shift}", styles['Normal']
                        ))
                elements.append(Spacer(1, 12))

        # Manual Review Section
        elements.append(Paragraph("Manual Review", styles['Heading1']))
        elements.append(Paragraph(f"<b>Items reviewed:</b> {review_decisions.get('total_reviewed', 0)}", styles['Normal']))
        elements.append(Paragraph(f"<b>Relevant:</b> {review_decisions.get('relevant', 0)}", styles['Normal']))
        elements.append(Paragraph(f"<b>Not relevant:</b> {review_decisions.get('not_relevant', 0)}", styles['Normal']))
        elements.append(Paragraph(f"<b>Uncertain:</b> {review_decisions.get('uncertain', 0)}", styles['Normal']))
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
                            review_decisions: Dict, timestamp: str) -> Path:
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
            "summary": {
                "total_messages": extracted_data.get('total_messages', 0),
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
