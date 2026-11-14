import os
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import pdfplumber

from app.models.network_scan import NetworkScan, NetworkScanResult, NetworkScanEvidence
from app.models.scan import Scan, ScanResult
from app.services.pdf_service import PDFGeneratorService
from app.services.ai_service import AIAnalysisService, generate_heuristic_fallback
import app.services.network_scan_service as nss


def test_pdf_visual_dark_background_and_title_no_overlap(app, db, test_users):
    """Item 8: Verify that with pdfplumber:
    1. EVERY page has the full-page rect with fill (0.031, 0.047, 0.078).
    2. Title top-to-top line distance >= font size (no overlap).
    3. No text is near-white on a page lacking the rect.
    """
    with app.app_context():
        user = test_users['user']
        # Create a network scan that produces at least 2 pages
        net_scan = NetworkScan(
            ip_address="192.168.1.50",
            status="completed",
            risk_level="Medium",
            scan_profile="Service Detection",
            scanner_mode="REAL_NMAP",
            user_id=user.id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(net_scan)
        db.session.flush()

        # Add findings
        for port, s_name in [(22, "ssh"), (80, "http"), (443, "https"), (8080, "http-proxy")]:
            db.session.add(NetworkScanResult(
                network_scan_id=net_scan.id,
                port=port,
                protocol="tcp",
                service_name=s_name,
                service_version="Apache httpd 2.4.41",
                state="open",
                severity="Medium",
                remediation="Restrict access"
            ))

        # Add evidence
        db.session.add(NetworkScanEvidence(
            network_scan_id=net_scan.id,
            phase="discovery",
            command="nmap -Pn -sT -p 22,80,443,8080 192.168.1.50",
            exit_code=0,
            duration_seconds=1.2,
            nmap_version="7.991",
            raw_xml='<nmaprun><host><status state="up"/></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        ))
        db.session.commit()

        ai_payload = {
            "overall_risk": "Medium",
            "security_score": 70,
            "executive_summary": "4 open ports were observed; this scan did not test for vulnerabilities.",
            "critical_findings": ["Port 22 SSH", "Port 80 HTTP", "Port 443 HTTPS", "Port 8080 Proxy"],
            "recommendations": ["Recommendation 1", "Recommendation 2", "Recommendation 3"],
            "remediation_priority": [
                {"finding": "Port 22 SSH", "priority": "Medium", "remediation": "Restrict to VPN"},
                {"finding": "Port 80 HTTP", "priority": "Medium", "remediation": "Redirect to HTTPS"},
                {"finding": "Port 443 HTTPS", "priority": "Medium", "remediation": "Update TLS ciphers"},
                {"finding": "Port 8080 Proxy", "priority": "Medium", "remediation": "Internal access only"}
            ]
        }

        report = PDFGeneratorService.generate_scan_report(user.id, net_scan, ai_payload)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        with pdfplumber.open(pdf_path) as pdf:
            assert len(pdf.pages) >= 2, f"Expected multi-page PDF, got {len(pdf.pages)} page(s)"

            for page_idx, page in enumerate(pdf.pages):
                # 1. Assert that EVERY page has the full-page rect with fill (0.031, 0.047, 0.078)
                dark_bg_rects = []
                for r in page.rects:
                    if r.get('width') == page.width and r.get('height') == page.height:
                        color = r.get('non_stroking_color')
                        if isinstance(color, (tuple, list)) and len(color) >= 3:
                            if (abs(color[0] - 0.031) < 0.01 and
                                abs(color[1] - 0.047) < 0.01 and
                                abs(color[2] - 0.078) < 0.01):
                                dark_bg_rects.append(r)

                assert len(dark_bg_rects) >= 1, f"Page {page_idx + 1} lacks full-page dark background rect (#080c14)"

                # 3. Assert that no text is near-white on a page lacking the rect
                near_white_chars = []
                for c in page.chars:
                    nsc = c.get('non_stroking_color')
                    if isinstance(nsc, (tuple, list)) and len(nsc) >= 3:
                        if all(val >= 0.8 for val in nsc[:3]):
                            near_white_chars.append(c)
                    elif isinstance(nsc, (int, float)) and nsc >= 0.8:
                        near_white_chars.append(c)

                if near_white_chars:
                    assert len(dark_bg_rects) >= 1, (
                        f"Page {page_idx + 1} contains near-white text but lacks the dark background rect!"
                    )

            # 2. Assert title top-to-top line distance >= font size (no overlap) on page 1
            page1 = pdf.pages[0]
            words = page1.extract_words()
            # Title words in the main report heading (exclude page header at top < 50)
            title_heading_words = [
                w for w in words
                if w['text'] in ('CYBERGUARD', 'AI', 'SECURITY', 'ASSESSMENT', 'REPORT') and w['top'] > 60 and w['top'] < 160
            ]
            title_lines = {}
            for w in title_heading_words:
                top_round = round(w['top'], 1)
                title_lines.setdefault(top_round, []).append(w['text'])

            assert len(title_lines) >= 2, f"Expected title to wrap into >= 2 lines, got {title_lines}"
            line_tops = sorted(title_lines.keys())
            distance = line_tops[1] - line_tops[0]
            # Font size is 20pt; distance between baseline/tops should be >= 20pt (leading is 24pt)
            assert distance >= 20.0, f"Expected title line top-to-top distance >= 20.0, got {distance:.2f}"


def test_network_wording_and_ai_claims(app, db, test_users):
    """Item 4:
    - PDF network executive summary uses 'Risk Level: LOW (rule-based, from observed open ports)'
      and removes '(Authoritative Scanner Score)'.
    - AI prompt and heuristic fallback forbid statements about vulnerabilities being found/not found;
      allowed claim: 'N open ports were observed; this scan did not test for vulnerabilities.'
    """
    with app.app_context():
        user = test_users['user']
        scan = NetworkScan(
            ip_address="192.168.1.10",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=user.id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.commit()

        # 1. PDF wording check
        report = PDFGeneratorService.generate_scan_report(user.id, scan, None)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        with pdfplumber.open(pdf_path) as pdf:
            full_text = "\n".join(p.extract_text() or "" for p in pdf.pages)

        assert "Risk Level: LOW (rule-based, from observed open ports)" in full_text
        assert "(Authoritative Scanner Score)" not in full_text

        # 2. Heuristic fallback for network scans: 0 open ports
        fb_zero = generate_heuristic_fallback({
            "target": "192.168.1.10",
            "scan_type": "network",
            "overall_risk": "Low",
            "findings": []
        }, reason="Quota exceeded")
        assert "0 open ports were observed; this scan did not test for vulnerabilities." in fb_zero["executive_summary"]
        assert "no vulnerabilities" not in fb_zero["executive_summary"].lower()

        # 3. Heuristic fallback for network scans: N open ports
        fb_two = generate_heuristic_fallback({
            "target": "192.168.1.10",
            "scan_type": "network",
            "overall_risk": "Medium",
            "findings": [
                {"name": "Port 80 (http) Open", "severity": "Medium", "remediation": "Harden"},
                {"name": "Port 443 (https) Open", "severity": "Low", "remediation": "Harden"}
            ]
        }, reason="Quota exceeded")
        assert "2 open ports were observed; this scan did not test for vulnerabilities." in fb_two["executive_summary"]
        assert "no vulnerabilities" not in fb_two["executive_summary"].lower()

        # 4. AI prompt inspection for network scans
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"}), \
             patch("requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "candidates": [{
                    "content": {
                        "parts": [{
                            "text": json.dumps({
                                "security_score": 70,
                                "overall_risk": "Medium",
                                "executive_summary": "2 open ports were observed; this scan did not test for vulnerabilities.",
                                "critical_findings": [],
                                "recommendations": [],
                                "remediation_priority": []
                            })
                        }]
                    }
                }]
            }
            mock_post.return_value = mock_resp

            AIAnalysisService.analyze_scan({
                "target": "192.168.1.10",
                "scan_type": "network",
                "findings": [
                    {"name": "Port 80 (http) Open", "severity": "Medium"},
                    {"name": "Port 443 (https) Open", "severity": "Low"}
                ]
            })

            # Verify prompt content in the post call
            call_kwargs = mock_post.call_args[1]
            sent_prompt = call_kwargs["json"]["contents"][0]["parts"][0]["text"]
            assert "2 open ports were observed; this scan did not test for vulnerabilities." in sent_prompt
            assert "FORBIDDEN from making statements about vulnerabilities being found or not found" in sent_prompt


def extract_all_table_cells(pdf) -> list:
    """Extract normalized text for every cell in every table in the PDF."""
    cells = []
    for page in pdf.pages:
        for table in page.extract_tables():
            for row in table:
                for cell in row:
                    if cell:
                        cells.append(" ".join(cell.split()))
    return cells


def test_quick_scan_and_service_detection_service_text(app, db, test_users):
    """Item 5:
    - Quick Scan: '<name> (assumed from port number; version not probed)'
    - Service Detection: keeps existing texts without nested parentheses
      (e.g. 'http - Not identified (service name assumed from port number)').
    """
    with app.app_context():
        user = test_users['user']

        # 1. Quick Scan
        quick_scan = NetworkScan(
            ip_address="192.168.1.20",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=user.id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(quick_scan)
        db.session.flush()
        db.session.add(NetworkScanResult(
            network_scan_id=quick_scan.id,
            port=80,
            protocol="tcp",
            service_name="http",
            service_version="Unknown",
            state="open",
            severity="Low"
        ))
        db.session.commit()

        rep_quick = PDFGeneratorService.generate_scan_report(user.id, quick_scan, None)
        pdf_path_q = os.path.join(app.root_path, 'static', 'reports', f"{rep_quick.uuid}.pdf")
        with pdfplumber.open(pdf_path_q) as pdf:
            cells_q = extract_all_table_cells(pdf)
        assert any("http (assumed from port number; version not probed)" in c for c in cells_q)

        # 2. Service Detection with method="table" (no product) -> "Not identified (service name assumed from port number)"
        sd_scan = NetworkScan(
            ip_address="192.168.1.21",
            status="completed",
            risk_level="Low",
            scan_profile="Service Detection",
            scanner_mode="REAL_NMAP",
            user_id=user.id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(sd_scan)
        db.session.flush()
        db.session.add(NetworkScanResult(
            network_scan_id=sd_scan.id,
            port=80,
            protocol="tcp",
            service_name="http",
            service_version="Not identified (service name assumed from port number)",
            state="open",
            severity="Low"
        ))
        db.session.add(NetworkScanResult(
            network_scan_id=sd_scan.id,
            port=443,
            protocol="tcp",
            service_name="https",
            service_version="Apache httpd 2.4.41",
            state="open",
            severity="Low"
        ))
        db.session.add(NetworkScanResult(
            network_scan_id=sd_scan.id,
            port=8080,
            protocol="tcp",
            service_name="http-proxy",
            service_version="Version detection incomplete (timed out)",
            state="open",
            severity="Low"
        ))
        db.session.commit()

        rep_sd = PDFGeneratorService.generate_scan_report(user.id, sd_scan, None)
        pdf_path_sd = os.path.join(app.root_path, 'static', 'reports', f"{rep_sd.uuid}.pdf")
        with pdfplumber.open(pdf_path_sd) as pdf:
            cells_sd = extract_all_table_cells(pdf)

        # Confirm exact formatting without nested parentheses
        assert any("http - Not identified (service name assumed from port number)" in c for c in cells_sd)
        assert not any("http (Not identified" in c for c in cells_sd)
        assert any("https (Apache httpd 2.4.41)" in c for c in cells_sd)
        assert any("http-proxy - Version detection incomplete (timed out)" in c for c in cells_sd)
        assert not any("http-proxy (Version detection incomplete" in c for c in cells_sd)


def test_nmap_version_storage_and_historical_display(app, db, test_users):
    """Item 6:
    - Nmap version storage: store nmap_version as just the number (e.g. '7.991' or '7.95'),
      parsed from the first line of nmap --version.
    - Display historical database rows as they are.
    """
    with app.app_context():
        user = test_users['user']

        # 1. Detection parses just the version number
        with patch("subprocess.run") as mock_run:
            mock_resp = MagicMock()
            mock_resp.returncode = 0
            mock_resp.stdout = "Nmap version 7.991 ( https://nmap.org )\nPlatform: x86_64\n"
            mock_run.return_value = mock_resp

            ver = nss._detect_nmap_version()
            assert ver == "7.991"

        with patch("subprocess.run") as mock_run:
            mock_resp = MagicMock()
            mock_resp.returncode = 0
            mock_resp.stdout = "Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64\n"
            mock_run.return_value = mock_resp

            ver = nss._detect_nmap_version()
            assert ver == "7.95"

        # 2. Historical row in database (e.g. 'Nmap 7.95') is rendered as-is
        hist_scan = NetworkScan(
            ip_address="192.168.1.30",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=user.id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(hist_scan)
        db.session.flush()

        db.session.add(NetworkScanEvidence(
            network_scan_id=hist_scan.id,
            phase="discovery",
            command="nmap -Pn -p 80 192.168.1.30",
            exit_code=0,
            duration_seconds=0.42,
            nmap_version="Nmap 7.95",
            raw_xml='<nmaprun></nmaprun>'
        ))
        db.session.commit()

        rep = PDFGeneratorService.generate_scan_report(user.id, hist_scan, None)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{rep.uuid}.pdf")
        with pdfplumber.open(pdf_path) as pdf:
            text = "\n".join(p.extract_text() or "" for p in pdf.pages)
        assert "Nmap 7.95" in text


def test_website_pdf_telemetry_and_six_headers(app, db, test_users):
    """Item 7:
    - Website PDF telemetry summary line lists all 6 security headers
      (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
      as Present or Missing.
    - Adds 'Final URL' and a short evidence line (status code, redirect count, tls_verified)
      from evidence_json.
    """
    with app.app_context():
        user = test_users['user']

        web_scan = Scan(
            target_type="url",
            target_destination="https://target.example.com",
            user_id=user.id,
            status="completed",
            security_score=85,
            risk_level="Low",
            evidence_json=json.dumps({
                "final_url": "https://target.example.com/login",
                "status_code": 200,
                "redirect_chain": ["http://target.example.com/"],
                "audit_ssl": {"tls_verified": True}
            })
        )
        db.session.add(web_scan)
        db.session.flush()

        # Add only HSTS missing finding
        db.session.add(ScanResult(
            scan_id=web_scan.id,
            vulnerability_name="Missing Strict-Transport-Security (HSTS) Header",
            severity="medium",
            description="HSTS missing",
            remediation="Enable HSTS"
        ))
        db.session.commit()

        report = PDFGeneratorService.generate_scan_report(user.id, web_scan, {
            "overall_risk": "Low",
            "security_score": 85,
            "executive_summary": "Website scan summary.",
            "critical_findings": [],
            "recommendations": ["Enable HSTS"],
            "remediation_priority": []
        })
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        with pdfplumber.open(pdf_path) as pdf:
            text = "\n".join(p.extract_text() or "" for p in pdf.pages)

        # Check Final URL
        assert "Final URL: https://target.example.com/login" in text

        # Check Evidence Telemetry short line
        assert "Status Code: 200" in text
        assert "Redirect Count: 1" in text
        assert "TLS Verified: True" in text

        # Check all 6 security headers as Present or Missing
        assert "HSTS: Missing" in text
        assert "CSP: Present" in text
        assert "X-Frame-Options: Present" in text
        assert "X-Content-Type-Options: Present" in text
        assert "Referrer-Policy: Present" in text
        assert "Permissions-Policy: Present" in text
