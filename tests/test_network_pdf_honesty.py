import os
import json
import pytest
from datetime import datetime, timezone
import pymupdf

from app.models.network_scan import NetworkScan, NetworkScanResult, NetworkScanEvidence
from app.models.ai import AIResponse
from app.services.pdf_service import PDFGeneratorService
from app.services.ai_service import generate_heuristic_fallback


def extract_pdf_text(filepath: str) -> str:
    """Extract plain text across all pages from a generated PDF file using PyMuPDF."""
    doc = pymupdf.open(filepath)
    text_chunks = [page.get_text() for page in doc]
    raw = "\n".join(text_chunks)
    # Also return with spaces normalized
    return raw


def test_pdf_scenario_1_completed_with_ports(app, db, test_users):
    """Scenario 1: Completed scan with open ports and telemetry evidence.
    Asserts presence of 'OBSERVED EXPOSURE (OPEN PORTS)', 'Exposure Level',
    'SCAN EVIDENCE', commands, exit codes, durations, Nmap version,
    and absence of 'clean audit' and 'no vulnerabilities'.
    """
    with app.app_context():
        scan = NetworkScan(
            ip_address="192.168.1.50",
            status="completed",
            risk_level="Medium",
            scan_profile="Service Detection",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.flush()

        res1 = NetworkScanResult(
            network_scan_id=scan.id,
            port=80,
            protocol="tcp",
            service_name="http",
            service_version="Apache httpd 2.4.41",
            state="open",
            severity="Medium",
            remediation="Apply latest vendor security patch."
        )
        db.session.add(res1)

        ev1 = NetworkScanEvidence(
            network_scan_id=scan.id,
            phase="discovery",
            command="nmap -Pn -sT -p 22,80,443,3389,8080 --max-retries 1 --host-timeout 20s -oX - 192.168.1.50",
            exit_code=0,
            duration_seconds=0.742,
            nmap_version="Nmap 7.95",
            raw_xml='<nmaprun><host><status state="up"/></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        )
        ev2 = NetworkScanEvidence(
            network_scan_id=scan.id,
            phase="version:80",
            command="nmap -Pn -sV -p 80 --version-intensity 7 -oX - 192.168.1.50",
            exit_code=0,
            duration_seconds=1.854,
            nmap_version="Nmap 7.95",
            raw_xml='<nmaprun></nmaprun>'
        )
        db.session.add_all([ev1, ev2])
        db.session.commit()

        ai_payload = {
            "overall_risk": "Medium",
            "security_score": 70,
            "executive_summary": "Observed open HTTP port 80 running Apache.",
            "critical_findings": ["Port 80/tcp exposed to perimeter"],
            "recommendations": ["Audit Apache modules and configure virtual host restrictions"],
            "remediation_priority": [{"finding": "Port 80 HTTP", "priority": "Medium", "remediation": "Restrict access"}]
        }

        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, ai_payload)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        text = extract_pdf_text(pdf_path)

        # Required phrases
        norm_text = " ".join(text.split())
        assert "CYBERGUARD AI SECURITY ASSESSMENT" in norm_text
        assert "OBSERVED EXPOSURE (OPEN PORTS)" in text
        assert "Exposure Level" in text
        assert "80/tcp" in text
        assert "Apache httpd 2.4.41" in text
        assert "SCAN EVIDENCE" in text
        assert "Scanned Ports:" in text
        assert "22,80,443,3389,8080" in text
        assert "Host State:" in text
        assert "Hosts Up: 1" in text
        assert "discovery" in text
        assert "version:80" in text
        assert "Nmap 7.95" in text

        # Negatives / Honesty checks
        assert "clean audit" not in text.lower()
        assert "clean audit signatures" not in text.lower()
        assert "no vulnerabilities" not in text.lower()
        assert "no detected vulnerabilities" not in text.lower()


def test_pdf_scenario_2_completed_zero_ports(app, db, test_users):
    """Scenario 2: Completed scan with zero open ports.
    Asserts row 'No open ports observed among scanned ports: <list>. This does not rule out other exposure.'
    and absence of 'clean', 'clean audit', and 'no vulnerabilities'.
    """
    with app.app_context():
        scan = NetworkScan(
            ip_address="192.168.1.51",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.flush()

        ev = NetworkScanEvidence(
            network_scan_id=scan.id,
            phase="discovery",
            command="nmap -Pn -sT -p 80,443 --max-retries 1 --host-timeout 20s -oX - 192.168.1.51",
            exit_code=0,
            duration_seconds=0.321,
            nmap_version="Nmap 7.95",
            raw_xml='<nmaprun><host><status state="up"/></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        )
        db.session.add(ev)
        db.session.commit()

        # Generate rule-based fallback data
        payload = {
            "target": scan.ip_address,
            "scan_type": "network",
            "overall_risk": "Low",
            "security_score": 100,
            "findings": []
        }
        fallback_data = generate_heuristic_fallback(payload)

        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, fallback_data)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        text = extract_pdf_text(pdf_path)

        # Required phrase
        assert "No open ports observed among scanned ports: 80, 443. This does not rule out other exposure." in text

        # Negatives / Honesty checks: NEVER use the word 'clean'
        assert "clean" not in text.lower()
        assert "no detected vulnerabilities" not in text.lower()
        assert "no vulnerabilities" not in text.lower()


def test_pdf_scenario_3_inconclusive_scan(app, db, test_users):
    """Scenario 3: Inconclusive scan.
    Asserts red INCONCLUSIVE banner ('Scan did not complete; no conclusion about exposure can be drawn. Re-run the scan.'),
    the evidence block, no risk colour, and NO AI sections.
    """
    with app.app_context():
        scan = NetworkScan(
            ip_address="192.168.1.52",
            status="inconclusive",
            risk_level="Inconclusive",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.flush()

        ev = NetworkScanEvidence(
            network_scan_id=scan.id,
            phase="discovery",
            command="nmap -Pn -sT -p 80,443 --max-retries 1 --host-timeout 20s -oX - 192.168.1.52",
            exit_code=None,
            duration_seconds=35.0,
            nmap_version="Nmap 7.95",
            stderr="subprocess.TimeoutExpired: Command timed out after 35 seconds"
        )
        db.session.add(ev)
        db.session.commit()

        # Attempt report generation (must NOT raise ValueError)
        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, None)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        text = extract_pdf_text(pdf_path)

        # Required banner and status
        assert "INCONCLUSIVE: Scan did not complete; no conclusion about exposure can be drawn. Re-run the scan." in text
        assert "Risk Level: INCONCLUSIVE (Scan Incomplete)" in text
        assert "SCAN EVIDENCE" in text
        assert "80,443" in text

        # NO AI sections
        assert "AI-GENERATED ANALYSIS" not in text
        assert "Critical Findings Implications:" not in text
        assert "Remediation Priority Mappings:" not in text

        # Negatives
        assert "clean" not in text.lower()


def test_pdf_scenario_4_mock_scanner_mode(app, db, test_users):
    """Scenario 4: MOCK scanner mode.
    Asserts stamp 'SIMULATED DATA - NOT A REAL ASSESSMENT' on the PDF.
    """
    with app.app_context():
        scan = NetworkScan(
            ip_address="192.168.1.53",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="MOCK",
            user_id=test_users['user'].id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.commit()

        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, None)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        text = extract_pdf_text(pdf_path)
        assert "SIMULATED DATA - NOT A REAL ASSESSMENT" in text


def test_pdf_scenario_5_pre_evidence_old_scan(app, db, test_users):
    """Scenario 5: Pre-evidence historical scan without evidence rows.
    Asserts 'No evidence recorded (scan predates evidence storage)'.
    """
    with app.app_context():
        scan = NetworkScan(
            ip_address="192.168.1.54",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.commit()

        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, None)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        text = extract_pdf_text(pdf_path)
        assert "SCAN EVIDENCE" in text
        assert "No evidence recorded (scan predates evidence storage)" in text


def test_regression_risk_low_next_to_ai_overall_none(app, db, test_users):
    """Regression test for Item 5:
    A scan with authoritative risk_level='Low' and an old ai_response row that says
    overall_risk='None' must render 'Risk Level: LOW' in both UI and PDF,
    not 'Risk LOW next to AI Overall None'.
    """
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    with app.app_context():
        scan = NetworkScan(
            ip_address="192.168.1.55",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.flush()

        # Legacy cached AI response with stale overall_risk='None'
        stale_ai_data = {
            "overall_risk": "None",
            "security_score": 100,
            "executive_summary": "Legacy report summary with None risk.",
            "recommendations": ["Routine perimeter audit"],
            "remediation_priority": []
        }
        ai_resp = AIResponse(
            prompt="Network Scan AI Prompt",
            response_text=json.dumps(stale_ai_data),
            model_used="gemini-2.5-flash",
            network_scan_id=scan.id
        )
        db.session.add(ai_resp)
        db.session.commit()

        # 1. Verify UI Results Page Rendering
        res_ui = client.get(f'/scanner/network/results/{scan.uuid}')
        assert res_ui.status_code == 200
        html = res_ui.get_data(as_text=True)

        assert "OVERALL RISK:" in html
        assert "LOW" in html
        assert "OVERALL AI RISK LEVEL:" in html
        # Must NOT show 'None' as the overall AI risk level
        assert "AI Overall None" not in html
        # Both UI badges reflect authoritative 'Low'
        assert 'LOW</span>' in html

        # 2. Verify PDF Generation Rendering
        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, stale_ai_data)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        text = extract_pdf_text(pdf_path)

        assert "Risk Level: LOW (rule-based, from observed open ports)" in text
        assert "AI Overall Risk Assessment: LOW" in text
        assert "AI Overall Risk Assessment: None" not in text
        assert "AI Overall None" not in text


def test_download_inconclusive_pdf_route(app, db, test_users):
    """Verify that download_pdf route allows inconclusive network scan PDFs."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    with app.app_context():
        scan = NetworkScan(
            ip_address="192.168.1.56",
            status="inconclusive",
            risk_level="Inconclusive",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.commit()

        res = client.get(f'/scanner/network/results/{scan.uuid}/pdf')
        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/pdf'
        assert "INCONCLUSIVE" in res.data.decode('latin1', errors='ignore')
