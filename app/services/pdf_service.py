import os
import re
import uuid
import json
import html
import xml.etree.ElementTree as ET
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

def draw_page_background(canvas_obj, doc_obj):
    """Draw full-page dark background before any flowables are placed on every page."""
    canvas_obj.saveState()
    canvas_obj.setFillColor(colors.HexColor('#080c14'))
    canvas_obj.rect(0, 0, letter[0], letter[1], fill=True, stroke=False)
    canvas_obj.restoreState()


class NumberedCanvas(canvas.Canvas):
    """Custom canvas implementation to draw headers, footers, and page counters on document compile."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

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
        is_network = isinstance(scan_obj, NetworkScan)
        risk_lvl_str = (getattr(scan_obj, 'risk_level', None) or '')
        is_inconclusive = (
            getattr(scan_obj, 'status', None) == 'inconclusive'
            or risk_lvl_str.lower() == 'inconclusive'
        )
        is_mock = getattr(scan_obj, 'scanner_mode', 'REAL_NMAP') == 'MOCK'

        if isinstance(ai_data, str):
            try:
                ai_data = json.loads(ai_data)
            except Exception:
                ai_data = None
        if not isinstance(ai_data, dict):
            ai_data = None

        if is_inconclusive:
            ai_data = None
        elif is_network and ai_data:
            # Force authoritative network scanner metrics
            score_map = {'Low': 90, 'Medium': 70, 'High': 40, 'Critical': 20}
            net_score = 100 if not getattr(scan_obj, 'results', None) else score_map.get(scan_obj.risk_level, 70)
            ai_data["overall_risk"] = scan_obj.risk_level
            ai_data["security_score"] = net_score

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
            leading=24,
            textColor=colors.HexColor('#00f2fe'), # Cyan
            spaceAfter=15
        )
        h1_style = ParagraphStyle(
            'SectionH1',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#ffffff'),
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
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
        banner_text_style = ParagraphStyle(
            'BannerText',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9.5,
            textColor=colors.HexColor('#ffffff'),
            leading=13
        )
        code_body_style = ParagraphStyle(
            'CodeBodyText',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            textColor=colors.HexColor('#00f2fe'),
            leading=9.5
        )
        code_dim_style = ParagraphStyle(
            'CodeDimText',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            textColor=colors.HexColor('#d0d0d0'),
            leading=10.5
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
        story.append(Spacer(1, 10))

        # Banners (MOCK and INCONCLUSIVE)
        if is_mock:
            mock_banner = Table([[Paragraph("<font color='#fef08a'><b>SIMULATED DATA - NOT A REAL ASSESSMENT</b>: This report contains simulated demonstration telemetry. No live network packets or port scans were sent to the target host.</font>", banner_text_style)]], colWidths=[504])
            mock_banner.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#451a03')),
                ('BOX', (0,0), (-1,-1), 1.5, colors.HexColor('#f59e0b')),
                ('PADDING', (0,0), (-1,-1), 8),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
            ]))
            story.append(mock_banner)
            story.append(Spacer(1, 10))

        if is_inconclusive:
            inconclusive_banner = Table([[Paragraph("<font color='#fee2e2'><b>INCONCLUSIVE:</b> Scan did not complete; no conclusion about exposure can be drawn. Re-run the scan.</font>", banner_text_style)]], colWidths=[504])
            inconclusive_banner.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#450a0a')),
                ('BOX', (0,0), (-1,-1), 1.5, colors.HexColor('#ef4444')),
                ('PADDING', (0,0), (-1,-1), 8),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
            ]))
            story.append(inconclusive_banner)
            story.append(Spacer(1, 10))

        # Executive Security Summary
        story.append(Paragraph("EXECUTIVE SECURITY SUMMARY", h1_style))
        
        if is_inconclusive:
            score_text = "Risk Level: INCONCLUSIVE (Scan Incomplete)"
            score_color = colors.HexColor('#94a3b8')  # Neutral slate (no risk color)
            summary_content = "Scan did not complete; no conclusion about exposure can be drawn. Re-run the scan."
        elif is_network:
            score_text = f"Risk Level: {scan_obj.risk_level.upper()} (rule-based, from observed open ports)"
            risk_l = scan_obj.risk_level.lower()
            if risk_l == 'low':
                score_color = colors.HexColor('#10b981')
            elif risk_l == 'medium':
                score_color = colors.HexColor('#f59e0b')
            else:
                score_color = colors.HexColor('#ef4444')
            if ai_data:
                from app.services.ai_service import filter_network_executive_summary
                raw_summary = ai_data.get('executive_summary', 'No summary generated.')
                n_ports = len(scan_obj.results) if getattr(scan_obj, 'results', None) else 0
                filtered_summary = filter_network_executive_summary(
                    raw_summary,
                    n_ports,
                    getattr(scan_obj, 'risk_level', 'Low')
                )
                summary_content = PDFGeneratorService.safe_html(filtered_summary)
            else:
                summary_content = "AI analysis is not available for this scan."
        else:
            risk_label = scan_obj.risk_level.upper() if getattr(scan_obj, 'risk_level', None) else None
            if risk_label:
                score_text = f"Security Score: {scan_obj.security_score}/100 | Risk Level: {risk_label} (Authoritative Scanner Score)"
            else:
                score_text = f"Security Score: {scan_obj.security_score}/100 (Authoritative Scanner Score)"
            score_color = colors.HexColor('#f59e0b')
            if ai_data:
                summary_content = PDFGeneratorService.safe_html(ai_data.get('executive_summary', 'No summary generated.'))
            else:
                summary_content = "AI analysis is not available for this scan."

        story.append(Paragraph(score_text, ParagraphStyle('ScoreStyle', parent=h1_style, textColor=score_color)))
        story.append(Paragraph(summary_content, body_style))
        story.append(Spacer(1, 15))

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
            story.append(Paragraph("OBSERVED EXPOSURE (OPEN PORTS)", h1_style))
            scanner_mode_str = "REAL NMAP" if getattr(scan_obj, 'scanner_mode', 'MOCK') == 'REAL_NMAP' else "MOCK"
            story.append(Paragraph(f"Target Host IP: {PDFGeneratorService.safe_html(scan_obj.ip_address)} | Profile: {scan_obj.scan_profile} | Mode: {scanner_mode_str}", body_style))
            
            headers = [
                Paragraph("Port/Proto", meta_label_style),
                Paragraph("Service (Version)", meta_label_style),
                Paragraph("Exposure Level", meta_label_style),
                Paragraph("Remediation Guidance", meta_label_style)
            ]
            table_rows = [headers]

            # Determine scanned ports list (for zero open ports row or evidence)
            discovery_cmd = ""
            if getattr(scan_obj, 'evidence', None):
                for ev in scan_obj.evidence:
                    if ev.phase == 'discovery':
                        discovery_cmd = ev.command or ""
                        break
                if not discovery_cmd and scan_obj.evidence:
                    discovery_cmd = scan_obj.evidence[0].command or ""

            m_ports = re.search(r'-p\s+([^\s]+)', discovery_cmd)
            if m_ports:
                ports_scanned_raw = m_ports.group(1)
                ports_scanned_display = ports_scanned_raw.replace(',', ', ')
            else:
                ports_scanned_display = "80, 443" if scan_obj.scan_profile == 'Quick Scan' else "22, 80, 443, 3389, 8080"

            table_custom_styles = list(table_style_list)

            if is_inconclusive:
                table_rows.append([
                    Paragraph("Scan did not complete; no conclusion about exposure can be drawn. Re-run the scan.", body_style),
                    Paragraph("", body_style),
                    Paragraph("", body_style),
                    Paragraph("", body_style)
                ])
                table_custom_styles.append(('SPAN', (0, 1), (3, 1)))
            elif not scan_obj.results:
                zero_ports_text = f"No open ports observed among scanned ports: {ports_scanned_display}. This does not rule out other exposure."
                table_rows.append([
                    Paragraph(zero_ports_text, body_style),
                    Paragraph("", body_style),
                    Paragraph("", body_style),
                    Paragraph("", body_style)
                ])
                table_custom_styles.append(('SPAN', (0, 1), (3, 1)))
            else:
                for r in scan_obj.results:
                    ver_text = r.service_version if r.service_version and r.service_version != 'Unknown' else 'Unknown'
                    rem_text = r.remediation or "Restrict access to trusted hosts using local firewall configurations."
                    if scan_obj.scan_profile == 'Quick Scan':
                        service_display = f"{r.service_name} (assumed from port number; version not probed)"
                    else:
                        if '(' in ver_text:
                            service_display = f"{r.service_name} - {ver_text}"
                        else:
                            service_display = f"{r.service_name} ({ver_text})"
                    table_rows.append([
                        Paragraph(f"{r.port}/{r.protocol}", body_style),
                        Paragraph(PDFGeneratorService.safe_html(service_display), body_style),
                        Paragraph(r.severity.upper(), body_style),
                        Paragraph(PDFGeneratorService.safe_html(rem_text), body_style)
                    ])

            findings_table = Table(table_rows, colWidths=[70, 130, 94, 210], repeatRows=1)
            findings_table.setStyle(TableStyle(table_custom_styles))
            story.append(findings_table)

            # Network Scan Evidence Block
            story.append(Spacer(1, 15))
            story.append(Paragraph("SCAN EVIDENCE", h1_style))

            if not getattr(scan_obj, 'evidence', None) or len(scan_obj.evidence) == 0:
                story.append(Paragraph("No evidence recorded (scan predates evidence storage)", body_style))
            else:
                discovery_ev = None
                for ev in scan_obj.evidence:
                    if ev.phase == 'discovery':
                        discovery_ev = ev
                        break
                if discovery_ev is None and scan_obj.evidence:
                    discovery_ev = scan_obj.evidence[0]

                ports_scanned = "Unknown"
                if discovery_ev and discovery_ev.command:
                    m = re.search(r'-p\s+([^\s]+)', discovery_ev.command)
                    if m:
                        ports_scanned = m.group(1)
                if ports_scanned == "Unknown":
                    ports_scanned = "80,443" if scan_obj.scan_profile == 'Quick Scan' else "22,80,443,3389,8080"

                host_state = "unknown"
                hosts_up = "0"
                if discovery_ev and discovery_ev.raw_xml:
                    try:
                        root = ET.fromstring(discovery_ev.raw_xml)
                        runstats_hosts = root.find('.//runstats/hosts')
                        if runstats_hosts is not None and 'up' in runstats_hosts.attrib:
                            hosts_up = runstats_hosts.get('up')
                        host_el = root.find('.//host')
                        if host_el is not None:
                            st_el = host_el.find('status')
                            if st_el is not None and 'state' in st_el.attrib:
                                host_state = st_el.get('state')
                            else:
                                host_state = 'up'
                            if hosts_up == '0' and host_state == 'up':
                                hosts_up = '1'
                    except Exception:
                        pass

                if host_state == "unknown":
                    if is_inconclusive:
                        host_state = "unknown (inconclusive)"
                        hosts_up = "0"
                    else:
                        host_state = "up"
                        hosts_up = "1"

                evidence_summary = f"<b>Scanned Ports:</b> {ports_scanned} | <b>Host State:</b> {host_state} | <b>Hosts Up:</b> {hosts_up}"
                story.append(Paragraph(evidence_summary, body_style))
                story.append(Spacer(1, 6))

                ev_headers = [
                    Paragraph("Phase", meta_label_style),
                    Paragraph("Command", meta_label_style),
                    Paragraph("Exit Code", meta_label_style),
                    Paragraph("Duration", meta_label_style),
                    Paragraph("Nmap Version", meta_label_style)
                ]
                ev_table_rows = [ev_headers]

                for ev in scan_obj.evidence:
                    clean_exit = str(ev.exit_code) if ev.exit_code is not None else 'None'
                    clean_dur = f"{ev.duration_seconds:.2f}s" if ev.duration_seconds is not None else 'N/A'
                    clean_ver = ev.nmap_version or 'unknown'
                    clean_cmd = ev.command or ''

                    ev_table_rows.append([
                        Paragraph(PDFGeneratorService.safe_html(ev.phase), code_dim_style),
                        Paragraph(PDFGeneratorService.safe_html(clean_cmd), code_body_style),
                        Paragraph(clean_exit, code_dim_style),
                        Paragraph(clean_dur, code_dim_style),
                        Paragraph(PDFGeneratorService.safe_html(clean_ver), code_dim_style)
                    ])

                ev_table = Table(ev_table_rows, colWidths=[70, 220, 54, 54, 106], repeatRows=1) # Total 504
                ev_table.setStyle(TableStyle(table_style_list))
                story.append(ev_table)
        else:
            # Website scan metadata
            story.append(Paragraph("ORIGINAL SCAN RESULTS", h1_style))
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

            # Parse evidence_json if available
            ev_data = {}
            if getattr(scan_obj, 'evidence_json', None):
                try:
                    ev_data = json.loads(scan_obj.evidence_json)
                except Exception:
                    ev_data = {}

            final_url = ev_data.get("final_url") or scan_obj.target_destination
            status_code = ev_data.get("status_code", "N/A")
            redirect_count = len(ev_data.get("redirect_chain") or [])
            audit_ssl_data = ev_data.get("audit_ssl") or {}
            tls_verified = audit_ssl_data.get("tls_verified", "N/A" if not is_https else True)
            if tls_verified is True:
                tls_verified_str = "True"
            elif tls_verified is False:
                tls_verified_str = "False"
            else:
                tls_verified_str = str(tls_verified)

            story.append(Paragraph(f"<b>Final URL:</b> {PDFGeneratorService.safe_html(final_url)}", body_style))
            evidence_line = f"<b>Evidence Telemetry:</b> Status Code: {status_code} | Redirect Count: {redirect_count} | TLS Verified: {tls_verified_str}"
            story.append(Paragraph(evidence_line, body_style))

            # Check status of 6 security headers
            findings_names = [r.vulnerability_name for r in scan_obj.results]
            headers_checked = [
                ('HSTS', 'Strict-Transport-Security (HSTS) Header'),
                ('CSP', 'Content-Security-Policy (CSP) Header'),
                ('X-Frame-Options', 'X-Frame-Options Header'),
                ('X-Content-Type-Options', 'X-Content-Type-Options Header'),
                ('Referrer-Policy', 'Referrer-Policy Header'),
                ('Permissions-Policy', 'Permissions-Policy Header')
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

            findings_table = Table(table_rows, colWidths=[150, 74, 280], repeatRows=1)
            findings_table.setStyle(TableStyle(table_style_list))
            story.append(findings_table)

        # AI-Generated Analysis Section (omitted for inconclusive scans)
        if not is_inconclusive and (ai_data or not is_network):
            story.append(Spacer(1, 15))
            story.append(Paragraph("AI-GENERATED ANALYSIS", h1_style))
            if ai_data:
                # Overall Risk
                if is_network:
                    ai_risk_display = scan_obj.risk_level.upper()
                else:
                    ai_risk_display = PDFGeneratorService.safe_html(ai_data.get('overall_risk', 'Unknown'))
                story.append(Paragraph(f"AI Overall Risk Assessment: {ai_risk_display}", ParagraphStyle('AIRiskStyle', parent=h1_style, textColor=colors.HexColor('#00f2fe'))))
                
                # Critical Findings
                story.append(Paragraph("Critical Findings Implications:", meta_label_style))
                if ai_data.get('critical_findings'):
                    for finding in ai_data.get('critical_findings', []):
                        story.append(Paragraph(f"&bull; {PDFGeneratorService.safe_html(finding)}", body_style))
                else:
                    if is_network:
                        story.append(Paragraph("None noted from observed ports.", body_style))
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
                prio_table = Table(prio_table_rows, colWidths=[150, 74, 280], repeatRows=1)
                prio_table.setStyle(TableStyle(table_style_list))
                story.append(prio_table)
            else:
                story.append(Paragraph("AI analysis is not available for this scan.", body_style))

            # Disclaimer
            story.append(Paragraph("Disclaimer: AI-generated analysis is based only on the security scan data supplied to the system. It should be treated as security guidance and manually validated before production changes.", disclaimer_style))

        # 3. Build document using custom canvas (header/footer flowables)
        doc.build(
            story,
            canvasmaker=NumberedCanvas,
            onFirstPage=draw_page_background,
            onLaterPages=draw_page_background
        )

        # 4. Save metadata record to DB Report vaults
        report_title = f"Compliance Security Audit Report for {target_name}"
        if is_network and ai_data:
            from app.services.ai_service import filter_network_executive_summary
            n_ports = len(scan_obj.results) if getattr(scan_obj, 'results', None) else 0
            report_summary = filter_network_executive_summary(
                ai_data.get('executive_summary', ''),
                n_ports,
                getattr(scan_obj, 'risk_level', 'Low')
            )
        elif ai_data:
            report_summary = ai_data.get('executive_summary', 'Diagnostics scan report.')
        elif is_inconclusive:
            report_summary = 'Inconclusive scan diagnostic report.'
        else:
            report_summary = 'Diagnostics scan report.'
        
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
