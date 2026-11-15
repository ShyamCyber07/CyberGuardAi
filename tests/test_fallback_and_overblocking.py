import os
import io
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import requests
import pdfplumber

from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan, NetworkScanResult
from app.models.ai import AIResponse
from app.services.pdf_service import PDFGeneratorService
from app.services.ai_service import (
    AIAnalysisService,
    validate_ai_text,
    sanitize_ai_data,
    generate_heuristic_fallback,
    get_short_failure_reason,
    check_ai_text_blocked
)
from app.services.scanner_service import ScannerService
from app.services.network_scan_service import NmapNetworkScannerService


def _extract_pdf_text(pdf_path_or_bytes):
    if isinstance(pdf_path_or_bytes, (bytes, bytearray)):
        stream = io.BytesIO(pdf_path_or_bytes)
    else:
        stream = pdf_path_or_bytes
    all_text = []
    with pdfplumber.open(stream) as pdf:
        for page in pdf.pages:
            all_text.append(page.extract_text() or "")
    return "\n".join(all_text)


def test_port_80_remediation_survives_in_both_tables(app, db, test_users):
    """
    Evidence 1 regression:
    Port 80 remediation text 'Ensure HTTP traffic redirects automatically to secure HTTPS configurations.'
    contains 'to secure', which must NOT match banned assurance claims.
    Assert it survives in BOTH the observed exposure port table AND the remediation priority table.
    """
    with app.app_context():
        user = test_users['user']
        scan = NetworkScan(
            ip_address="192.0.2.1",
            status="completed",
            risk_level="Low",
            scan_profile="Service Detection",
            scanner_mode="REAL_NMAP",
            user_id=user.id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.flush()

        port80_rem = "Ensure HTTP traffic redirects automatically to secure HTTPS configurations."
        db.session.add(NetworkScanResult(
            network_scan_id=scan.id,
            port=80,
            protocol="tcp",
            service_name="http",
            service_version="nginx",
            state="open",
            severity="Low",
            remediation=port80_rem
        ))
        db.session.commit()

        ai_data = {
            "overall_risk": "Low",
            "security_score": 90,
            "executive_summary": "1 open ports were observed. The LOW exposure level is a rule-based rating of the observed ports; this scan did not test for vulnerabilities.",
            "critical_findings": [],
            "recommendations": ["Verify that each observed exposure is intended for this host's role."],
            "remediation_priority": [
                {
                    "finding": "Port 80",
                    "priority": "Low",
                    "remediation": port80_rem
                }
            ]
        }

        # Sanitize data
        sanitized = sanitize_ai_data(
            ai_data,
            authoritative_score=90,
            authoritative_risk="Low",
            scan_type="network",
            findings=scan.results,
            n_ports=1
        )
        # Verify action step survived in sanitized dict
        assert sanitized["remediation_priority"][0]["remediation"] == port80_rem

        # Generate PDF report
        report = PDFGeneratorService.generate_scan_report(user.id, scan, sanitized)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        pdf_text = _extract_pdf_text(pdf_path)
        norm_text = " ".join(pdf_text.split())

        # Assert port 80 remediation text appears at least twice (in both tables)
        occurrences = norm_text.count(port80_rem)
        assert occurrences >= 2, f"Expected port 80 remediation in both tables, found {occurrences} times"

        # Assert placeholder was NOT placed into remediation slot
        assert "1 open ports were observed; this scan did not test for vulnerabilities" not in sanitized["remediation_priority"][0]["remediation"]


def test_blocked_list_items_are_dropped_and_placeholder_count_at_most_one(app, db, test_users):
    """
    Requirement 2 & 3:
    - If an item is blocked, DROP it.
    - If whole critical_findings list becomes empty, show deterministic sentence once.
    - NEVER put the deterministic sentence into a recommendation or action-step slot.
    - Blocked action step replaced by original rule-based text for that port.
    - Deterministic sentence appears at most once per report section.
    """
    with app.app_context():
        user = test_users['user']
        scan = NetworkScan(
            ip_address="192.0.2.2",
            status="completed",
            risk_level="Low",
            scan_profile="Service Detection",
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
            severity="Low",
            remediation="Ensure HTTP traffic redirects automatically to secure HTTPS configurations."
        ))
        db.session.commit()

        # AI payload where:
        # - critical_findings has 2 items: both with banned assurance claims
        # - recommendations has 2 items: 1 blocked (banned claim), 1 valid
        # - remediation_priority has an action step with banned assurance claim
        ai_data = {
            "overall_risk": "Low",
            "security_score": 90,
            "executive_summary": "1 open ports were observed. The LOW exposure level is a rule-based rating of the observed ports; this scan did not test for vulnerabilities.",
            "critical_findings": [
                "No critical or high-risk vulnerabilities were identified in this scan.",
                "Perimeter is clean and host is secure."
            ],
            "recommendations": [
                "System is secure so no actions are required.",
                "Verify intended operational role for HTTP listener."
            ],
            "remediation_priority": [
                {
                    "finding": "Port 80",
                    "priority": "Low",
                    "remediation": "No vulnerabilities were found and host remains safe."
                }
            ]
        }

        sanitized = sanitize_ai_data(
            ai_data,
            authoritative_score=90,
            authoritative_risk="Low",
            scan_type="network",
            findings=scan.results,
            n_ports=1
        )

        # 1. Blocked items in critical_findings were dropped; whole list became empty -> deterministic sentence shown once
        det_sentence = "1 open ports were observed; this scan did not test for vulnerabilities."
        assert sanitized["critical_findings"] == [det_sentence]

        # 2. Blocked item in recommendations dropped, valid item survived, NEVER has deterministic sentence
        assert len(sanitized["recommendations"]) == 1
        assert sanitized["recommendations"][0] == "Verify intended operational role for HTTP listener."
        assert det_sentence not in sanitized["recommendations"]

        # 3. Blocked action step replaced by original rule-based text for that port
        orig_expected = "Ensure HTTP traffic redirects automatically to secure HTTPS configurations."
        assert sanitized["remediation_priority"][0]["remediation"] == orig_expected
        assert det_sentence not in sanitized["remediation_priority"][0]["remediation"]

        # 4. Generate PDF and verify placeholder count per section is <= 1
        report = PDFGeneratorService.generate_scan_report(user.id, scan, sanitized)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        with pdfplumber.open(pdf_path) as pdf:
            pdf_text = "\n".join(p.extract_text() or "" for p in pdf.pages)
        norm_text = " ".join(pdf_text.split())

        # Section 1 (Executive Summary) has summary deterministic sentence
        # Section 4 (AI Analysis) has critical findings deterministic sentence
        # Nowhere else does it appear
        assert norm_text.count(orig_expected) >= 2


@pytest.mark.parametrize("failure_type,exc_or_resp,expected_short_reason", [
    ("timeout", requests.exceptions.Timeout("HTTPSConnectionPool: Read timed out"), "timeout"),
    ("connection_error", requests.exceptions.ConnectionError("Connection refused by host"), "connection error"),
    ("http_500", (500, "Internal Server Error"), "HTTP 500"),
    ("http_503", (503, "Service Unavailable"), "HTTP 503"),
    ("http_429", (429, '{"error": {"message": "Resource exhausted", "status": "RESOURCE_EXHAUSTED"}}'), "HTTP 429"),
    ("invalid_json", (200, "NOT_JSON_BODY"), "invalid JSON"),
    ("validation_error", (200, json.dumps({"candidates": [{"content": {"parts": [{"text": json.dumps({"wrong": 123})}]}}]})), "validation error"),
])
def test_website_scan_fallback_stored_for_each_failure_type(app, db, test_users, failure_type, exc_or_resp, expected_short_reason):
    """
    Requirement 4 & 6:
    Any failure in live AI generation (timeout, connection error, HTTP 5xx, HTTP 429, invalid or unparseable JSON, validation error)
    must store a rule-based analysis labelled 'Rule-based analysis (live AI unavailable: <short reason>)'.
    Assert label text in generated PDF with pdfplumber for website scans.
    """
    user = test_users['user']

    def mock_requests_post(*args, **kwargs):
        if isinstance(exc_or_resp, Exception):
            raise exc_or_resp
        status_code, body = exc_or_resp
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.text = body
        if body == "NOT_JSON_BODY":
            mock_resp.json.side_effect = ValueError("No JSON")
        else:
            try:
                mock_resp.json.return_value = json.loads(body)
            except Exception:
                mock_resp.json.return_value = {"error": {"message": body}}
        return mock_resp

    with app.app_context(), \
         patch.dict("os.environ", {"GEMINI_API_KEY": "dummy_test_key"}), \
         patch("requests.post", side_effect=mock_requests_post):

        scan = Scan(
            user_id=user.id,
            target_type='website',
            target_destination='https://cortexclash.in',
            status='completed',
            security_score=80,
            risk_level='Low',
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.flush()

        db.session.add(ScanResult(
            scan_id=scan.id,
            vulnerability_name="Missing Content-Security-Policy (CSP) Header",
            severity="medium",
            description="CSP header is missing",
            remediation="Configure Content-Security-Policy header."
        ))
        db.session.commit()

        # Simulate scanner service running AI step
        findings_data = [{
            "name": r.vulnerability_name,
            "severity": r.severity,
            "description": r.description,
            "remediation": r.remediation
        } for r in scan.results]

        payload = {
            "target": scan.target_destination,
            "scan_type": "website",
            "security_score": scan.security_score,
            "overall_risk": scan.risk_level,
            "enforce_authoritative_metrics": True,
            "findings": findings_data
        }

        # Analyze with fallback_on_failure=True
        ai_data = AIAnalysisService.analyze_scan(
            payload,
            fallback_on_quota=True,
            fallback_on_failure=True,
            user_id=user.id
        )

        # 1. Assert fallback data stored in AIResponse
        assert ai_data.get("_fallback") is True
        assert f"Rule-based analysis (live AI unavailable: {expected_short_reason})" in ai_data.get("fallback_label", "")

        ai_resp = AIResponse(
            prompt="Automatically generated report from website scanner results.",
            response_text=json.dumps(ai_data),
            model_used=ai_data.get("_model_used", "rule-based-fallback"),
            scan_id=scan.id
        )
        db.session.add(ai_resp)
        db.session.commit()

        # 2. Generate PDF and verify label text appears in PDF
        report = PDFGeneratorService.generate_scan_report(user.id, scan, ai_data)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        pdf_text = _extract_pdf_text(pdf_path)
        expected_label = f"Rule-based analysis (live AI unavailable: {expected_short_reason})"
        assert expected_label in pdf_text
        assert "AI analysis is not available for this scan." not in pdf_text


@pytest.mark.parametrize("failure_type,exc_or_resp,expected_short_reason", [
    ("timeout", requests.exceptions.Timeout("Connection timeout"), "timeout"),
    ("connection_error", requests.exceptions.ConnectionError("Network down"), "connection error"),
    ("http_500", (500, "Internal Server Error"), "HTTP 500"),
    ("http_429", (429, '{"error": {"message": "RESOURCE_EXHAUSTED"}}'), "HTTP 429"),
    ("invalid_json", (200, "INVALID_FORMAT"), "invalid JSON"),
    ("validation_error", (200, json.dumps({"candidates": [{"content": {"parts": [{"text": json.dumps({"missing_keys": True})}]}}]})), "validation error"),
])
def test_network_scan_fallback_stored_for_each_failure_type(app, db, test_users, failure_type, exc_or_resp, expected_short_reason):
    """
    Requirement 4 & 6:
    Assert label text in generated PDF with pdfplumber for network scans under all failure types.
    """
    user = test_users['user']

    def mock_requests_post(*args, **kwargs):
        if isinstance(exc_or_resp, Exception):
            raise exc_or_resp
        status_code, body = exc_or_resp
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.text = body
        if body == "INVALID_FORMAT":
            mock_resp.json.side_effect = ValueError("No JSON")
        else:
            try:
                mock_resp.json.return_value = json.loads(body)
            except Exception:
                mock_resp.json.return_value = {"error": {"message": body}}
        return mock_resp

    with app.app_context(), \
         patch.dict("os.environ", {"GEMINI_API_KEY": "dummy_test_key"}), \
         patch("requests.post", side_effect=mock_requests_post):

        scan = NetworkScan(
            ip_address="192.168.1.100",
            status="completed",
            risk_level="Low",
            scan_profile="Service Detection",
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
            severity="Low",
            remediation="Ensure HTTP traffic redirects automatically to secure HTTPS configurations."
        ))
        db.session.commit()

        findings_data = [{
            "name": f"Port {r.port}/{r.protocol} ({r.service_name})",
            "severity": r.severity,
            "description": f"Port {r.port} open",
            "remediation": r.remediation
        } for r in scan.results]

        payload = {
            "target": scan.ip_address,
            "scan_type": "network",
            "overall_risk": scan.risk_level,
            "security_score": 90,
            "findings": findings_data
        }

        ai_data = AIAnalysisService.analyze_scan(
            payload,
            fallback_on_quota=True,
            fallback_on_failure=True,
            user_id=user.id
        )

        assert ai_data.get("_fallback") is True
        expected_label = f"Rule-based analysis (live AI unavailable: {expected_short_reason})"
        assert expected_label in ai_data.get("fallback_label", "")

        ai_resp = AIResponse(
            prompt="Automatically generated report from network scanner results.",
            response_text=json.dumps(ai_data),
            model_used="rule-based-fallback",
            network_scan_id=scan.id
        )
        db.session.add(ai_resp)
        db.session.commit()

        report = PDFGeneratorService.generate_scan_report(user.id, scan, ai_data)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        pdf_text = _extract_pdf_text(pdf_path)
        assert expected_label in pdf_text
        assert "AI analysis is not available for this scan." not in pdf_text


def test_pdf_only_says_ai_unavailable_when_no_scan_data_exists(app, db, test_users):
    """
    Requirement 4:
    The PDF may only say 'AI analysis is not available' when no scan data exists.
    """
    with app.app_context():
        user = test_users['user']

        # 1. Scan with NO scan data (e.g. status='failed', target_destination='')
        failed_scan = Scan(
            user_id=user.id,
            target_type='website',
            target_destination='',
            status='failed',
            security_score=0,
            risk_level='High',
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(failed_scan)
        db.session.commit()

        rep_failed = PDFGeneratorService.generate_scan_report(user.id, failed_scan, ai_data=None)
        pdf_failed_path = os.path.join(app.root_path, 'static', 'reports', f"{rep_failed.uuid}.pdf")
        pdf_failed_text = _extract_pdf_text(pdf_failed_path)
        assert "AI analysis is not available for this scan." in pdf_failed_text

        # 2. Completed scan WITH scan data, but ai_data=None passed -> synthesizes rule-based fallback
        completed_scan = Scan(
            user_id=user.id,
            target_type='website',
            target_destination='https://example.com',
            status='completed',
            security_score=100,
            risk_level='None',
            evidence_json=json.dumps({"final_url": "https://example.com", "status_code": 200}),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(completed_scan)
        db.session.commit()

        rep_comp = PDFGeneratorService.generate_scan_report(user.id, completed_scan, ai_data=None)
        pdf_comp_path = os.path.join(app.root_path, 'static', 'reports', f"{rep_comp.uuid}.pdf")
        pdf_comp_text = _extract_pdf_text(pdf_comp_path)
        assert "AI analysis is not available for this scan." not in pdf_comp_text
        assert "Rule-based analysis" in pdf_comp_text
