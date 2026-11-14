import os
import uuid
import json
import html
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from flask import current_app

from app.extensions import db
from app.models.report import Report
from app.models.scan import Scan
from app.models.network_scan import NetworkScan

class NumberedCanvas(canvas.Canvas):
    """Custom canvas implementation to draw headers, footers, and page counters on document compile."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def _startPage(self):
        super()._startPage()
        self.saveState()
        # Draw dark background
        self.setFillColor(colors.HexColor('#080c14'))
        self.rect(0, 0, letter[0], letter[1], fill=True, stroke=False)
        self.restoreState()

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        self.saveState()
        
        # Company Style Header
        self.setFont('Helvetica-Bold', 9)
        self.setFillColor(colors.HexColor('#00f2fe')) # Cyber Cyan/Teal shade
        self.drawString(54, 750, "CYBERGUARD AI")
        
        self.setFont('Helvetica', 9)
        self.setFillColor(colors.HexColor('#ffffff'))
        self.drawRightString(letter[0]-54, 750, "DEFENSIVE STATUS COMPLIANCE REPORT")
        
        # Header accent separator line
        self.setStrokeColor(colors.HexColor('#1b263b'))
        self.setLineWidth(1)
        self.line(54, 742, letter[0]-54, 742)
        
        # Footer
        self.setFont('Helvetica', 8)
        self.setFillColor(colors.HexColor('#a5a5a5'))
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        self.drawString(54, 40, f"Generated: {date_str} | Confidential - Security Assessment Report")
        self.drawRightString(letter[0]-54, 40, f"Page {self._pageNumber} of {total_pages}")
        
        # Footer separator line
        self.line(54, 52, letter[0]-54, 52)
        
        self.restoreState()


class PDFGeneratorService:
    """Service layer generating styled, executive security compliance PDFs using ReportLab."""

    @staticmethod
    def safe_html(text: str) -> str:
        """Escape HTML characters to prevent ReportLab parsing crashes."""
        if not text:
            return ""
        return html.escape(str(text))

    @staticmethod
    def generate_scan_report(user_id: int, scan_obj, ai_data: dict = None) -> Report:
        """Compile a professional scan PDF, save to disk static reports, and store in DB."""
        if getattr(scan_obj, 'status', None) == 'inconclusive':
            raise ValueError("PDF report cannot be generated for an inconclusive scan.")

        if isinstance(ai_data, str):
            try:
                ai_data = json.loads(ai_data)
            except Exception:
                ai_data = None
        if not isinstance(ai_data, dict):
            ai_data = None

        is_network = isinstance(scan_obj, NetworkScan)
        report_uuid = str(uuid.uuid4())
        
        # 1. Prepare directory and paths
        reports_dir = os.path.join(current_app.root_path, 'static', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        filename = f"{report_uuid}.pdf"
        filepath = os.path.join(reports_dir, filename)

        # 2. Setup document formatting parameters
        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=72,
            bottomMargin=72,
            pageCompression=0
        )

        styles = getSampleStyleSheet()
        
        # Custom stylesheet definitions (professional typography)
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=colors.HexColor('#00f2fe'), # Cyan
            spaceAfter=15
        )
        h1_style = ParagraphStyle(
            'SectionH1',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=13,
            textColor=colors.HexColor('#ffffff'),
            spaceBefore=14,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyTextCustom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            textColor=colors.HexColor('#d0d0d0'),
            leading=13.5,
            spaceAfter=6
        )
        meta_label_style = ParagraphStyle(
            'MetaLabel',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.HexColor('#00f2fe')
        )
        meta_val_style = ParagraphStyle(
            'MetaValue',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#ffffff')
        )
        disclaimer_style = ParagraphStyle(
            'DisclaimerStyle',
            parent=styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=8,
            textColor=colors.HexColor('#a5a5a5'),
            leading=11,
            spaceBefore=12
        )

        story = []

        # Cover/Title
        story.append(Paragraph("CYBERGUARD AI SECURITY ASSESSMENT REPORT", title_style))
        story.append(Spacer(1, 10))

        # Target Target Name and type
        target_name = scan_obj.ip_address if is_network else scan_obj.target_destination
        scan_type_str = "Network Scan" if is_network else "Website Scan"
        scan_date_str = scan_obj.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan_obj.completed_at else 'Unknown'
        generated_date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        # Metadata Table
        meta_data = [
            [Paragraph("Report ID:", meta_label_style), Paragraph(PDFGeneratorService.safe_html(report_uuid), meta_val_style)],
            [Paragraph("Target Endpoint:", meta_label_style), Paragraph(PDFGeneratorService.safe_html(target_name), meta_val_style)],
            [Paragraph("Scan Type:", meta_label_style), Paragraph(scan_type_str, meta_val_style)],
            [Paragraph("Assessment Scope:", meta_label_style), Paragraph(scan_obj.scan_profile if is_network else "Security Headers & SSL", meta_val_style)],
            [Paragraph("Scan Date:", meta_label_style), Paragraph(scan_date_str, meta_val_style)],
            [Paragraph("Report Date:", meta_label_style), Paragraph(generated_date_str, meta_val_style)]
        ]
        meta_table = Table(meta_data, colWidths=[120, 384])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#0a0e17')), # Dark navy
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1b263b'))
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 15))

        # Executive Security Summary
        story.append(Paragraph("EXECUTIVE SECURITY SUMMARY", h1_style))
        
        # Determine score/risk info
        if is_network:
            score_text = f"Risk Level: {scan_obj.risk_level.upper()} (Authoritative Scanner Score)"
        else:
            risk_label = scan_obj.risk_level.upper() if getattr(scan_obj, 'risk_level', None) else None
            if risk_label:
                score_text = f"Security Score: {scan_obj.security_score}/100 | Risk Level: {risk_label} (Authoritative Scanner Score)"
            else:
                score_text = f"Security Score: {scan_obj.security_score}/100 (Authoritative Scanner Score)"

        story.append(Paragraph(score_text, ParagraphStyle('ScoreStyle', parent=h1_style, textColor=colors.HexColor('#f59e0b'))))
        
        if ai_data:
            summary_content = PDFGeneratorService.safe_html(ai_data.get('executive_summary', 'No summary generated.'))
        else:
            summary_content = "AI analysis is not available for this scan."
        story.append(Paragraph(summary_content, body_style))
        story.append(Spacer(1, 15))

        # Original Scan Results
        story.append(Paragraph("ORIGINAL SCAN RESULTS", h1_style))
        
        table_style_list = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1b263b')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#415a77'))
        ]

        if is_network:
            # Network scanner metadata
            scanner_mode_str = "REAL NMAP" if getattr(scan_obj, 'scanner_mode', 'MOCK') == 'REAL_NMAP' else "MOCK"
            story.append(Paragraph(f"Target Host IP: {PDFGeneratorService.safe_html(scan_obj.ip_address)} | Profile: {scan_obj.scan_profile} | Mode: {scanner_mode_str}", body_style))
            
            headers = [Paragraph("Port/Proto", meta_label_style), Paragraph("Service (Version)", meta_label_style), Paragraph("Severity", meta_label_style), Paragraph("Remediation", meta_label_style)]
            table_rows = [headers]
            for r in scan_obj.results:
                table_rows.append([
                    Paragraph(f"{r.port}/{r.protocol}", body_style),
                    Paragraph(PDFGeneratorService.safe_html(f"{r.service_name} ({r.service_version if r.service_version else 'Unknown'})"), body_style),
                    Paragraph(r.severity.upper(), body_style),
                    Paragraph(PDFGeneratorService.safe_html(r.remediation), body_style)
                ])
            findings_table = Table(table_rows, colWidths=[70, 130, 84, 220])
            findings_table.setStyle(TableStyle(table_style_list))
            story.append(findings_table)
        else:
            # Website scan metadata
            is_https = scan_obj.target_destination.lower().startswith('https://')
            https_text = "Enabled" if is_https else "Disabled"
            
            # Determine SSL certificate status driven by finding's error category:
            # - expired / self_signed / hostname_mismatch / unverified_cert_chain -> "SSL Issues Discovered"
            # - unverified_scanner_host -> "TLS not assessed (scanner host could not verify)"
            # - no TLS finding -> "Valid Certificate"
            if not is_https:
                ssl_text = "Not Applicable"
            else:
                tls_category = None
                for result in scan_obj.results:
                    raw = result.raw_payload or {}
                    err_type = raw.get('error_type')
                    vuln_name_lower = (result.vulnerability_name or '').lower()

                    if err_type in ('expired', 'self_signed', 'hostname_mismatch', 'unverified_cert_chain'):
                        tls_category = err_type
                        break
                    elif err_type == 'unverified_scanner_host':
                        tls_category = 'unverified_scanner_host'
                        break
                    elif 'trust store problem' in vuln_name_lower or ('inconclusive' in vuln_name_lower and 'scanner host' in vuln_name_lower):
                        tls_category = 'unverified_scanner_host'
                        break
                    elif any(k in vuln_name_lower for k in ('expired', 'self-signed', 'hostname mismatch', 'chain could not be verified', 'handshake failure', 'invalid or untrusted')):
                        tls_category = 'ssl_issues'
                        break

                if tls_category in ('expired', 'self_signed', 'hostname_mismatch', 'unverified_cert_chain', 'ssl_issues'):
                    ssl_text = "SSL Issues Discovered"
                elif tls_category == 'unverified_scanner_host':
                    ssl_text = "TLS not assessed (scanner host could not verify)"
                else:
                    ssl_text = "Valid Certificate"

            # Check status of 6 security headers
            findings_names = [r.vulnerability_name for r in scan_obj.results]
            headers_checked = [
                ('HSTS', 'Strict-Transport-Security (HSTS) Header'),
                ('CSP', 'Content-Security-Policy (CSP) Header'),
                ('X-Frame-Options', 'X-Frame-Options Header')
            ]
            header_status_list = []
            for label, check_name in headers_checked:
                missing = any(check_name in name for name in findings_names)
                status = "Missing" if missing else "Present"
                header_status_list.append(f"{label}: {status}")

            headers_summary = f"HTTPS Status: {https_text} | SSL Status: {ssl_text} | " + " | ".join(header_status_list)
            story.append(Paragraph(headers_summary, body_style))

            # Check if TLS verification was disabled
            has_tls_unverified = any(
                getattr(r, 'raw_payload', None) and r.raw_payload.get('tls_verified') is False
                for r in scan_obj.results
            )
            if has_tls_unverified:
                tls_warn_style = ParagraphStyle(
                    'TLSDisabledNotice',
                    parent=body_style,
                    textColor=colors.HexColor('#f59e0b'),
                    fontName='Helvetica-Bold'
                )
                story.append(Paragraph("Headers retrieved with TLS verification disabled", tls_warn_style))

            story.append(Spacer(1, 5))

            headers = [Paragraph("Vulnerability Findings", meta_label_style), Paragraph("Severity", meta_label_style), Paragraph("Remediation", meta_label_style)]
            table_rows = [headers]
            
            if scan_obj.results:
                for r in scan_obj.results:
                    table_rows.append([
                        Paragraph(PDFGeneratorService.safe_html(r.vulnerability_name), body_style),
                        Paragraph(r.severity.upper(), body_style),
                        Paragraph(PDFGeneratorService.safe_html(r.remediation), body_style)
                    ])
            else:
                table_rows.append([
                    Paragraph("No vulnerabilities discovered during scan.", body_style),
                    Paragraph("INFO", body_style),
                    Paragraph("No actions required.", body_style)
                ])

            findings_table = Table(table_rows, colWidths=[150, 74, 280])
            findings_table.setStyle(TableStyle(table_style_list))
            story.append(findings_table)

        story.append(Spacer(1, 15))

        # AI-Generated Analysis Section
        story.append(Paragraph("AI-GENERATED ANALYSIS", h1_style))
        if ai_data:
            # Overall Risk
            story.append(Paragraph(f"AI Overall Risk Assessment: {PDFGeneratorService.safe_html(ai_data.get('overall_risk', 'Unknown'))}", ParagraphStyle('AIRiskStyle', parent=h1_style, textColor=colors.HexColor('#00f2fe'))))
            
            # Critical Findings
            story.append(Paragraph("Critical Findings Implications:", meta_label_style))
            if ai_data.get('critical_findings'):
                for finding in ai_data.get('critical_findings', []):
                    story.append(Paragraph(f"&bull; {PDFGeneratorService.safe_html(finding)}", body_style))
            else:
                story.append(Paragraph("No critical findings reported.", body_style))

            story.append(Spacer(1, 10))

            # Recommendations in numbered format
            story.append(Paragraph("Actionable Recommendations:", meta_label_style))
            if ai_data.get('recommendations'):
                for idx, rec in enumerate(ai_data.get('recommendations', []), start=1):
                    story.append(Paragraph(f"{idx}. {PDFGeneratorService.safe_html(rec)}", body_style))
            else:
                story.append(Paragraph("No recommendations compiled.", body_style))

            story.append(Spacer(1, 10))

            # Remediation Priority Table
            story.append(Paragraph("Remediation Priority Mappings:", meta_label_style))
            prio_headers = [Paragraph("Finding Target", meta_label_style), Paragraph("Priority", meta_label_style), Paragraph("Remediation Action Steps", meta_label_style)]
            prio_table_rows = [prio_headers]
            for item in ai_data.get('remediation_priority', []):
                if isinstance(item, dict):
                    f_name = item.get('finding', 'Unknown')
                    f_prio = item.get('priority', 'Unknown')
                    f_rem = item.get('remediation', 'No details.')
                else:
                    f_name = str(item)
                    f_prio = 'Medium'
                    f_rem = 'Apply appropriate remediation guidance.'
                prio_table_rows.append([
                    Paragraph(PDFGeneratorService.safe_html(f_name), body_style),
                    Paragraph(PDFGeneratorService.safe_html(str(f_prio).upper()), body_style),
                    Paragraph(PDFGeneratorService.safe_html(f_rem), body_style)
                ])
            prio_table = Table(prio_table_rows, colWidths=[150, 74, 280])
            prio_table.setStyle(TableStyle(table_style_list))
            story.append(prio_table)
        else:
            story.append(Paragraph("AI analysis is not available for this scan.", body_style))

        # Disclaimer
        story.append(Paragraph("Disclaimer: AI-generated analysis is based only on the security scan data supplied to the system. It should be treated as security guidance and manually validated before production changes.", disclaimer_style))

        # 3. Build document using custom canvas (header/footer flowables)
        doc.build(story, canvasmaker=NumberedCanvas)

        # 4. Save metadata record to DB Report vaults
        report_title = f"Compliance Security Audit Report for {target_name}"
        report_summary = ai_data.get('executive_summary', 'Diagnostics scan report.') if ai_data else 'Diagnostics scan report.'
        
        report = Report(
            uuid=report_uuid,
            title=report_title,
            summary=report_summary,
            status='finalized',
            user_id=user_id
        )
        if is_network:
            report.network_scan_id = scan_obj.id
        else:
            report.scan_id = scan_obj.id

        db.session.add(report)
        db.session.commit()

        return report
