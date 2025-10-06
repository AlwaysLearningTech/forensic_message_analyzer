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
            logger.error(f"Failed to generate Word report: {e}")
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
        
        doc.add_paragraph(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        doc.add_paragraph(f'Case ID: {timestamp}')
        doc.add_page_break()
        
        # Executive Summary
        doc.add_heading('Executive Summary', 1)
        doc.add_paragraph(self._generate_executive_summary(
            extracted_data, analysis_results, review_decisions
        ))
        
        # Data Extraction Summary
        doc.add_heading('Data Extraction', 1)
        doc.add_paragraph(f"Total messages extracted: {extracted_data.get('total_messages', 0)}")
        doc.add_paragraph(f"Date range: {extracted_data.get('date_range', 'N/A')}")
        doc.add_paragraph(f"Sources: {', '.join(extracted_data.get('sources', []))}")
        
        # Threat Analysis
        doc.add_heading('Threat Analysis', 1)
        threats = analysis_results.get('threats', {})
        doc.add_paragraph(f"Threats detected: {threats.get('count', 0)}")
        if threats.get('high_priority'):
            doc.add_heading('High Priority Threats', 2)
            for threat in threats['high_priority'][:5]:  # Top 5
                doc.add_paragraph(f"• {threat.get('content', '')[:100]}...")
        
        # Sentiment Analysis
        doc.add_heading('Sentiment Analysis', 1)
        sentiment = analysis_results.get('sentiment', {})
        doc.add_paragraph(f"Overall sentiment: {sentiment.get('overall', 'N/A')}")
        doc.add_paragraph(f"Sentiment distribution:")
        doc.add_paragraph(f"  • Positive: {sentiment.get('positive_count', 0)}")
        doc.add_paragraph(f"  • Neutral: {sentiment.get('neutral_count', 0)}")
        doc.add_paragraph(f"  • Negative: {sentiment.get('negative_count', 0)}")
        
        # Manual Review Summary
        doc.add_heading('Manual Review', 1)
        doc.add_paragraph(f"Items reviewed: {review_decisions.get('total_reviewed', 0)}")
        doc.add_paragraph(f"Relevant: {review_decisions.get('relevant', 0)}")
        doc.add_paragraph(f"Not relevant: {review_decisions.get('not_relevant', 0)}")
        doc.add_paragraph(f"Uncertain: {review_decisions.get('uncertain', 0)}")
        
        # Chain of Custody
        doc.add_heading('Chain of Custody', 1)
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
        elements.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Paragraph(f"<b>Case ID:</b> {timestamp}", styles['Normal']))
        elements.append(PageBreak())
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", styles['Heading1']))
        summary = self._generate_executive_summary(extracted_data, analysis_results, review_decisions)
        elements.append(Paragraph(summary, styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Data Overview Table
        elements.append(Paragraph("Data Overview", styles['Heading1']))
        overview_data = [
            ['Metric', 'Value'],
            ['Total Messages', str(extracted_data.get('total_messages', 0))],
            ['Date Range', extracted_data.get('date_range', 'N/A')],
            ['Sources', ', '.join(extracted_data.get('sources', []))],
            ['Threats Detected', str(analysis_results.get('threats', {}).get('count', 0))],
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
                "threats_detected": analysis_results.get('threats', {}).get('count', 0),
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
        """Generate executive summary text."""
        total_messages = extracted_data.get('total_messages', 0)
        threats = analysis_results.get('threats', {}).get('count', 0)
        reviewed = review_decisions.get('total_reviewed', 0)
        relevant = review_decisions.get('relevant', 0)
        
        summary = f"""
        This forensic analysis examined {total_messages} messages extracted from multiple sources.
        The automated analysis identified {threats} potential threats requiring review.
        Manual review was conducted on {reviewed} flagged items, with {relevant} deemed relevant
        to the investigation. All data handling maintained forensic integrity through
        cryptographic hashing and chain of custody documentation.
        """
        
        return summary.strip()
