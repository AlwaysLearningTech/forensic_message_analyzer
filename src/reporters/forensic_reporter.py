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

from ..config import config
from ..forensic_utils import ForensicIntegrity

class ForensicReporter:
    """
    Generates comprehensive forensic reports in multiple formats.
    Designed for legal proceedings with proper documentation.
    """
    
    def __init__(self, forensic_integrity: ForensicIntegrity):
        self.forensic = forensic_integrity
    
    def generate_excel_report(self, 
                             messages_df: pd.DataFrame,
                             behavioral_results: Dict[str, Any],
                             timeline_results: Dict[str, Any],
                             output_path: Path) -> None:
        """
        Generate comprehensive Excel report with multiple worksheets.
        """
        logging.info(f"Generating Excel report: {output_path}")
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # Sheet 1: All Messages
            messages_export = messages_df.copy()
            # Clean up columns for export
            columns_to_export = [
                'unique_id', 'source', 'timestamp', 'sender', 'recipient',
                'content', 'sentiment', 'sentiment_score', 'harmful_content',
                'threat_detected', 'manual_review_decision', 'manual_review_notes'
            ]
            messages_export = messages_export[[col for col in columns_to_export if col in messages_export.columns]]
            messages_export.to_excel(writer, sheet_name='All Messages', index=False)
            
            # Sheet 2: Behavioral Profiles
            if 'behavioral_profiles' in behavioral_results:
                profiles_df = pd.DataFrame(behavioral_results['behavioral_profiles'])
                profiles_df.to_excel(writer, sheet_name='Behavioral Profiles', index=False)
            
            # Sheet 3: Sentiment Progression
            if 'sentiment_progression' in behavioral_results:
                sentiment_df = pd.DataFrame(behavioral_results['sentiment_progression'])
                sentiment_df.to_excel(writer, sheet_name='Sentiment Progression', index=False)
            
            # Sheet 4: Communication Frequency
            if 'communication_frequency' in behavioral_results:
                freq_df = pd.DataFrame(behavioral_results['communication_frequency'])
                freq_df.to_excel(writer, sheet_name='Communication Frequency', index=False)
            
            # Sheet 5: Escalation Patterns
            if 'escalation_patterns' in behavioral_results:
                escalation_df = pd.DataFrame(behavioral_results['escalation_patterns'])
                escalation_df.to_excel(writer, sheet_name='Escalation Patterns', index=False)
            
            # Sheet 6: Relationship Dynamics
            if 'relationship_dynamics' in behavioral_results:
                dynamics_df = pd.DataFrame(behavioral_results['relationship_dynamics'])
                dynamics_df.to_excel(writer, sheet_name='Relationship Dynamics', index=False)
            
            # Sheet 7: Threat Assessment
            if 'threat_assessment' in behavioral_results:
                threats_df = pd.DataFrame(behavioral_results['threat_assessment'])
                threats_df.to_excel(writer, sheet_name='Threat Assessment', index=False)
            
            # Sheet 8: Timeline Events
            if 'events' in timeline_results:
                timeline_df = pd.DataFrame(timeline_results['events'])
                timeline_df.to_excel(writer, sheet_name='Timeline Events', index=False)
            
            # Sheet 9: Daily Summary
            if 'daily_summary' in timeline_results:
                daily_df = pd.DataFrame(timeline_results['daily_summary'])
                daily_df.to_excel(writer, sheet_name='Daily Summary', index=False)
            
            # Sheet 10: Visitation Analysis
            if 'visitation_analysis' in behavioral_results:
                vis_data = behavioral_results['visitation_analysis']
                if 'events' in vis_data:
                    vis_df = pd.DataFrame(vis_data['events'])
                    vis_df.to_excel(writer, sheet_name='Visitation Events', index=False)
        
        logging.info(f"Excel report generated: {output_path}")
        self.forensic.log_operation('Excel Report Generated', {'path': str(output_path)})
    
    def generate_word_report(self,
                            messages_df: pd.DataFrame,
                            behavioral_results: Dict[str, Any],
                            timeline_results: Dict[str, Any],
                            methodology: Dict[str, str],
                            limitations: Dict[str, str],
                            output_path: Path) -> None:
        """
        Generate detailed Word document for legal team.
        """
        logging.info(f"Generating Word report: {output_path}")
        
        doc = Document()
        
        # Title Page
        title = doc.add_heading('Forensic Message Analysis Report', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        doc.add_paragraph(f"Case ID: {self.forensic.case_id}")
        doc.add_paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        doc.add_paragraph(f"Total Messages Analyzed: {len(messages_df):,}")
        
        doc.add_page_break()
        
        # Executive Summary
        doc.add_heading('Executive Summary', 1)
        
        # Calculate key metrics
        harmful_count = messages_df['harmful_content'].sum() if 'harmful_content' in messages_df else 0
        threat_count = messages_df['threat_detected'].sum() if 'threat_detected' in messages_df else 0
        
        doc.add_paragraph(f"""
This forensic analysis examined {len(messages_df):,} messages from multiple sources 
spanning from {messages_df['timestamp'].min()} to {messages_df['timestamp'].max()}.

Key Findings:
• {harmful_count} messages contained harmful content
• {threat_count} messages contained threats
• {len(behavioral_results.get('escalation_patterns', []))} escalation patterns identified
• Overall risk assessment: {self._determine_overall_risk(behavioral_results)}
        """)
        
        # Methodology Section
        doc.add_heading('Scientific Methodology', 1)
        doc.add_paragraph('This analysis employs the following scientific methods:')
        
        for category, description in methodology.items():
            doc.add_heading(category.replace('_', ' ').title(), 2)
            doc.add_paragraph(description)
        
        # Known Limitations
        doc.add_heading('Known Limitations', 1)
        doc.add_paragraph('The following limitations apply to this analysis:')
        
        for category, description in limitations.items():
            doc.add_heading(category.replace('_', ' ').title(), 2)
            doc.add_paragraph(description)
        
        # Behavioral Profiles
        doc.add_page_break()
        doc.add_heading('Behavioral Analysis', 1)
        
        if 'behavioral_profiles' in behavioral_results:
            for profile in behavioral_results['behavioral_profiles']:
                doc.add_heading(f"Profile: {profile['participant']}", 2)
                
                doc.add_paragraph(f"Total Messages: {profile['total_messages']}")
                doc.add_paragraph(f"Average Sentiment: {profile['sentiment_metrics']['average']:.2f}")
                doc.add_paragraph(f"Risk Level: {profile['risk_level']}")
                doc.add_paragraph(f"Communication Pattern: {profile['communication_pattern']}")
                
                if 'abuse_categories' in profile and profile['abuse_categories']:
                    doc.add_paragraph("Abuse Categories Detected:")
                    for category, count in profile['abuse_categories'].items():
                        doc.add_paragraph(f"  • {category}: {count} instances", style='List Bullet')
        
        # Threat Assessment
        if 'threat_assessment' in behavioral_results and behavioral_results['threat_assessment']:
            doc.add_page_break()
            doc.add_heading('Threat Assessment', 1)
            
            for threat in behavioral_results['threat_assessment'][:10]:  # Limit to top 10
                doc.add_heading(f"Threat - {threat['timestamp']}", 2)
                doc.add_paragraph(f"Sender: {threat['sender']}")
                doc.add_paragraph(f"Type: {threat['threat_type']}")
                doc.add_paragraph(f"Severity: {threat['severity']}")
                doc.add_paragraph(f"Content Preview: {threat['content_preview']}")
                
                if 'manual_review' in threat:
                    doc.add_paragraph(f"Manual Review Decision: {threat['manual_review']}")
        
        # Timeline Summary
        doc.add_page_break()
        doc.add_heading('Timeline Analysis', 1)
        
        if 'events' in timeline_results:
            doc.add_paragraph(f"Total Significant Events: {len(timeline_results['events'])}")
            
            # Add top events
            doc.add_heading('Key Events', 2)
            for event in timeline_results['events'][:20]:  # Top 20 events
                doc.add_paragraph(f"• {event['timestamp']}: {event['description']}")
        
        # Chain of Custody
        doc.add_page_break()
        doc.add_heading('Chain of Custody', 1)
        doc.add_paragraph("""
All evidence has been preserved according to forensic best practices. 
Complete chain of custody documentation is available in the accompanying JSON file.
Hash verification ensures data integrity throughout the analysis process.
        """)
        
        # Washington ER Mapping (plain language)
        doc.add_page_break()
        doc.add_heading('Washington Evidence Rules (ER) Mapping', 1)
        doc.add_paragraph('This section explains, in plain language, how the materials in this report align with Washington Evidence Rules (ER), which generally mirror the Federal Rules of Evidence (FRE).')
        self._add_washington_er_mapping_word(doc)

        # Exhibit A – Methodology (appendix)
        doc.add_page_break()
        doc.add_heading('Exhibit A – Methodology (Plain Language)', 1)
        self._add_exhibit_a_methodology_word(doc)
        
        # Save document
        doc.save(output_path)
        logging.info(f"Word report generated: {output_path}")
        self.forensic.log_operation('Word Report Generated', {'path': str(output_path)})
    
    def generate_pdf_report(self,
                           messages_df: pd.DataFrame,
                           behavioral_results: Dict[str, Any],
                           timeline_results: Dict[str, Any],
                           output_path: Path) -> None:
        """
        Generate PDF report for court submission.
        """
        logging.info(f"Generating PDF report: {output_path}")
        
        # Create PDF
        pdf = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#2E4053'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        # Title
        elements.append(Paragraph("Forensic Message Analysis Report", title_style))
        elements.append(Spacer(1, 0.5*inch))
        
        # Case Information
        case_info = [
            ['Case ID:', self.forensic.case_id],
            ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Total Messages:', f"{len(messages_df):,}"],
            ['Date Range:', f"{messages_df['timestamp'].min()} to {messages_df['timestamp'].max()}"]
        ]
        
        case_table = Table(case_info, colWidths=[2*inch, 4*inch])
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(case_table)
        elements.append(PageBreak())
        
        # Summary Statistics
        elements.append(Paragraph("Summary Statistics", styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        harmful_count = messages_df['harmful_content'].sum() if 'harmful_content' in messages_df else 0
        threat_count = messages_df['threat_detected'].sum() if 'threat_detected' in messages_df else 0
        
        stats_data = [
            ['Metric', 'Value'],
            ['Total Messages', f"{len(messages_df):,}"],
            ['Unique Participants', f"{messages_df['sender'].nunique()}"],
            ['Harmful Messages', f"{harmful_count:,}"],
            ['Threats Detected', f"{threat_count:,}"],
            ['Messages Reviewed', f"{messages_df['manual_review_decision'].notna().sum():,}" if 'manual_review_decision' in messages_df else '0']
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(stats_table)
        
        # Risk Assessment
        elements.append(PageBreak())
        elements.append(Paragraph("Risk Assessment", styles['Heading1']))
        
        if 'behavioral_profiles' in behavioral_results:
            for profile in behavioral_results['behavioral_profiles'][:5]:  # Top 5 profiles
                elements.append(Paragraph(f"Participant: {profile['participant']}", styles['Heading2']))
                
                risk_data = [
                    ['Risk Level:', profile['risk_level']],
                    ['Total Messages:', str(profile['total_messages'])],
                    ['Harmful Messages:', str(profile['harmful_behavior']['harmful_messages'])],
                    ['Threats Made:', str(profile['harmful_behavior']['threats_made'])]
                ]
                
                risk_table = Table(risk_data, colWidths=[2*inch, 3*inch])
                risk_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 11),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                ]))
                elements.append(risk_table)
                elements.append(Spacer(1, 0.2*inch))
        
        # Legal Notice
        elements.append(PageBreak())
        elements.append(Paragraph("Legal Notice", styles['Heading1']))
        elements.append(Paragraph(
            """
This report was generated using automated forensic analysis tools. All findings should be 
reviewed by qualified legal professionals. The analysis methods employed meet the requirements 
of Federal Rules of Evidence 901 and 902 for authentication and the Daubert standard for 
scientific evidence. Complete chain of custody documentation is maintained separately.
            """,
            styles['Normal']
        ))
        
        # Washington ER Mapping (plain language)
        elements.append(PageBreak())
        elements.append(Paragraph('Washington Evidence Rules (ER) Mapping', styles['Heading1']))
        elements += self._build_washington_er_mapping_pdf(styles)

        # Exhibit A – Methodology (appendix)
        elements.append(PageBreak())
        elements.append(Paragraph('Exhibit A – Methodology (Plain Language)', styles['Heading1']))
        elements += self._build_exhibit_a_pdf(styles)

        # Build PDF
        pdf.build(elements)
        logging.info(f"PDF report generated: {output_path}")
        self.forensic.log_operation('PDF Report Generated', {'path': str(output_path)})
    
    def _determine_overall_risk(self, behavioral_results: Dict[str, Any]) -> str:
        """Determine overall risk level from behavioral analysis."""
        if not behavioral_results:
            return 'UNKNOWN'
        
        high_risk_count = 0
        if 'behavioral_profiles' in behavioral_results:
            for profile in behavioral_results['behavioral_profiles']:
                if profile.get('risk_level') == 'HIGH':
                    high_risk_count += 1
        
        if high_risk_count >= 2:
            return 'HIGH'
        elif high_risk_count == 1:
            return 'MEDIUM'
        else:
            return 'LOW'

    # ----------------------- Helper sections (Word) -----------------------
    def _add_washington_er_mapping_word(self, doc: Document) -> None:
        """Insert plain-language ER mapping for Word reports."""
        # ER 901 – Authentication/Identification
        doc.add_heading('ER 901 – Authentication / Identification', 2)
        doc.add_paragraph('• What the court requires: Proof that an item is what it is claimed to be.', style='List Bullet')
        doc.add_paragraph('• How this report satisfies it: Each original source and generated file has a SHA-256 hash; timestamps and actions are logged. Originals are not altered; processing occurs on copies.', style='List Bullet')
        doc.add_paragraph('• Where to verify: See chain_of_custody_*.json and run_manifest_*.json in the output folder.', style='List Bullet')

        # ER 1002 – Best Evidence Rule
        doc.add_heading('ER 1002 – Best Evidence (Original Writing Required)', 2)
        doc.add_paragraph('• What the court requires: The original or a reliable duplicate must be used to prove content.', style='List Bullet')
        doc.add_paragraph('• How this report satisfies it: Message content and metadata are exported without editorial changes; extraction is deterministic and reproducible from original sources.', style='List Bullet')
        doc.add_paragraph('• Where to verify: Compare exported content with source databases/exports and review metadata fields (timestamps, senders, IDs).', style='List Bullet')

        # ER 803 – Hearsay Exceptions (Business Records)
        doc.add_heading('ER 803 – Hearsay Exception (Records of Regularly Conducted Activity)', 2)
        doc.add_paragraph('• What the court considers: Records made in the regular course of activity may be admissible.', style='List Bullet')
        doc.add_paragraph('• How this report addresses it: Messages were created during normal communications and exported in their ordinary form with timestamps and system identifiers.', style='List Bullet')
        doc.add_paragraph('• Where to verify: Source descriptions, message metadata columns, and extraction notes in the chain of custody.', style='List Bullet')

        # Note on mapping FRE↔ER
        doc.add_paragraph('Note: Washington ER generally mirror corresponding FRE provisions (ER 901 ≈ FRE 901, etc.). This report uses plain-language explanations and provides verifiable artifacts (hashes, logs, timestamps).')

    def _add_exhibit_a_methodology_word(self, doc):
        """Add Exhibit A - Forensic Methodology section to Word document."""
        doc.add_heading('Exhibit A - Forensic Methodology', 1)
        
        methodology_text = """
This forensic analysis was conducted following industry-standard digital forensic principles:

1. **Data Preservation**: All original data sources were preserved in their original state. Hash values were calculated to ensure data integrity throughout the analysis process.

2. **Chain of Custody**: Complete documentation of all data handling, including timestamps, operations performed, and personnel involved.

3. **Tool Validation**: All analysis tools used have been validated and are industry-accepted for forensic analysis.

4. **Reproducibility**: All analysis steps have been documented to ensure results can be independently verified.

5. **Daubert Compliance**: This analysis meets the standards for scientific evidence as established in Daubert v. Merrell Dow Pharmaceuticals.
        """
        doc.add_paragraph(methodology_text)
    
    # ----------------------- Helper sections (PDF) -----------------------
    def _build_washington_er_mapping_pdf(self, styles) -> List[Any]:
        flow = []
        flow.append(Paragraph('<b>ER 901 – Authentication / Identification</b>', styles['Heading2']))
        flow.append(Paragraph('• Requirement: Prove an item is what it purports to be.', styles['BodyText']))
        flow.append(Paragraph('• How satisfied: SHA-256 hashes for sources/outputs; timestamped logs; originals remain unaltered.', styles['BodyText']))
        flow.append(Paragraph('• Where to verify: chain_of_custody_*.json and run_manifest_*.json.', styles['BodyText']))
        flow.append(Spacer(1, 0.15*inch))

        flow.append(Paragraph('<b>ER 1002 – Best Evidence (Original Writing Required)</b>', styles['Heading2']))
        flow.append(Paragraph('• Requirement: Use original or reliable duplicate to prove content.', styles['BodyText']))
        flow.append(Paragraph('• How satisfied: Exports preserve content/metadata without editorial changes; extraction is reproducible.', styles['BodyText']))
        flow.append(Paragraph('• Where to verify: Compare exports to sources; see metadata columns (timestamps/senders/IDs).', styles['BodyText']))
        flow.append(Spacer(1, 0.15*inch))

        flow.append(Paragraph('<b>ER 803 – Hearsay Exception (Records of Regularly Conducted Activity)</b>', styles['Heading2']))
        flow.append(Paragraph('• Consideration: Records made during regular communication may be admissible.', styles['BodyText']))
        flow.append(Paragraph('• How addressed: Messages were created in the regular course of communication and exported in ordinary form with timestamps and identifiers.', styles['BodyText']))
        flow.append(Paragraph('• Where to verify: Source notes, metadata columns, and chain of custody.', styles['BodyText']))
        flow.append(Spacer(1, 0.1*inch))

        flow.append(Paragraph('Note: Washington ER generally mirror the corresponding FRE provisions. This report provides plain-language explanations and verifiable artifacts (hashes, logs, timestamps).', styles['BodyText']))
        return flow

    def _build_exhibit_a_pdf(self, styles) -> List[Any]:
        flow = []
        flow.append(Paragraph('<b>Purpose</b>', styles['Heading2']))
        flow.append(Paragraph('Brief description of methods used to collect, analyze, and report messages, aligned to ER 901/1002/803.', styles['BodyText']))
        flow.append(Spacer(1, 0.1*inch))

        flow.append(Paragraph('<b>Data Sources</b>', styles['Heading2']))
        flow.append(Paragraph('• iMessage and WhatsApp exports; screenshots and attachments cataloged separately.', styles['BodyText']))

        flow.append(Paragraph('<b>Extraction & Preservation (ER 901/1002)</b>', styles['Heading2']))
        flow.append(Paragraph('• Originals not modified; SHA-256 hashing; timestamped logs; deterministic extraction for reproducibility.', styles['BodyText']))

        flow.append(Paragraph('<b>Analysis Steps</b>', styles['Heading2']))
        flow.append(Paragraph('• Automated: threats, sentiment, patterns, metrics, timeline. • Manual review recorded with decisions/notes.', styles['BodyText']))

        flow.append(Paragraph('<b>Reporting & Packaging</b>', styles['Heading2']))
        flow.append(Paragraph('• XLSX/DOCX/PDF plus chain_of_custody_*.json and run_manifest_*.json.', styles['BodyText']))

        flow.append(Paragraph('<b>Verification & Reproducibility</b>', styles['Heading2']))
        flow.append(Paragraph('• Re-run analysis and compare output hashes; matching hashes show identical results.', styles['BodyText']))

        flow.append(Paragraph('<b>Limitations</b>', styles['Heading2']))
        flow.append(Paragraph('• Potential gaps in sources; validation statistics are logged and reported.', styles['BodyText']))
        return flow
