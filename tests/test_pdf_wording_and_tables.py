import os
import json
import pytest
from datetime import datetime, timezone
import pdfplumber

from app.models.network_scan import NetworkScan, NetworkScanResult, NetworkScanEvidence
from app.services.pdf_service import PDFGeneratorService
from app.services.ai_service import BANNED_NETWORK_PHRASES, filter_network_executive_summary


@pytest.mark.parametrize("banned_phrase", [
    "no critical",
    "no high",
    "no vulnerabilities",
    "no issues",
    "clean",
    "risk posture",
    "secure",
    "safe",
])
def test_banned_phrases_post_filter_replaces_with_deterministic_sentence(app, db, test_users, banned_phrase):
    """Part A, Items 1 & 3:
    Feed an AI response containing each banned phrase and assert:
    - PDF text has NONE of the banned phrases.
    - PDF text HAS the exact deterministic sentence:
      'N open ports were observed. The LOW exposure level is a rule-based rating of the observed ports; this scan did not test for vulnerabilities.'
    """
    with app.app_context():
        user = test_users['user']
        scan = NetworkScan(
            ip_address="192.168.1.105",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=user.id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.flush()

        db.session.add(NetworkScanResult(
            network_scan_id=scan.id,
            port=80,
            protocol="tcp",
            service_name="http",
            service_version="Apache",
            state="open",
            severity="Low"
        ))
        db.session.commit()

        # AI payload with the banned phrase embedded
        ai_data = {
            "overall_risk": "Low",
            "security_score": 90,
            "executive_summary": f"Perimeter check indicates {banned_phrase} detected across target ports.",
            "critical_findings": [],
            "recommendations": ["Routine audit"],
            "remediation_priority": []
        }

        report = PDFGeneratorService.generate_scan_report(user.id, scan, ai_data)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        with pdfplumber.open(pdf_path) as pdf:
            pdf_text = "\n".join(p.extract_text() or "" for p in pdf.pages)
        norm_pdf_text = " ".join(pdf_text.split())

        # 1. Assert PDF text does NOT contain the banned phrase
        assert banned_phrase.lower() not in norm_pdf_text.lower(), (
            f"Banned phrase '{banned_phrase}' was found in the PDF text!"
        )

        # 2. Assert PDF text contains the deterministic sentence
        expected_deterministic = (
            "1 open ports were observed. The LOW exposure level is a "
            "rule-based rating of the observed ports; this scan did not test for vulnerabilities."
        )
        assert expected_deterministic in norm_pdf_text


def test_table_header_repeats_on_page_split(app, db, test_users):
    """Part A, Items 2 & 3:
    Tables that can split across pages use repeatRows=1.
    Assert the header text appears on page 1 and appears again on page 2
    for a report with enough rows to split.
    """
    with app.app_context():
        user = test_users['user']
        scan = NetworkScan(
            ip_address="192.168.1.106",
            status="completed",
            risk_level="Medium",
            scan_profile="Service Detection",
            scanner_mode="REAL_NMAP",
            user_id=user.id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.flush()

        # Add 30 port rows to guarantee the port table splits across pages
        for port in range(1001, 1031):
            db.session.add(NetworkScanResult(
                network_scan_id=scan.id,
                port=port,
                protocol="tcp",
                service_name=f"svc-{port}",
                service_version=f"v{port}",
                state="open",
                severity="Medium",
                remediation=f"Harden port {port} against unauthorized access."
            ))

        db.session.commit()

        ai_data = {
            "overall_risk": "Medium",
            "security_score": 60,
            "executive_summary": "30 open ports were observed; this scan did not test for vulnerabilities.",
            "critical_findings": [],
            "recommendations": ["Harden ports"],
            "remediation_priority": []
        }

        report = PDFGeneratorService.generate_scan_report(user.id, scan, ai_data)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        with pdfplumber.open(pdf_path) as pdf:
            assert len(pdf.pages) >= 2, f"Expected table to split across >= 2 pages, got {len(pdf.pages)}"

            # Extract tables from page 1 and page 2
            tables_p1 = pdf.pages[0].extract_tables()
            tables_p2 = pdf.pages[1].extract_tables()

            # Find the port table on page 1
            expected_header = ['Port/Proto', 'Service (Version)', 'Exposure Level', 'Remediation Guidance']
            
            p1_has_header = False
            for t in tables_p1:
                if t and t[0] == expected_header:
                    p1_has_header = True
                    break

            assert p1_has_header, f"Page 1 table does not contain expected header: {expected_header}"

            # Find the repeated port table header on page 2
            p2_has_repeated_header = False
            for t in tables_p2:
                if t and t[0] == expected_header:
                    p2_has_repeated_header = True
                    break

            assert p2_has_repeated_header, (
                f"Page 2 table does not contain repeated header: {expected_header}. "
                f"Tables on page 2: {tables_p2}"
            )
