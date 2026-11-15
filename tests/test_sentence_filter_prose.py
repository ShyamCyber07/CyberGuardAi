import os
import io
import json
import re
import logging
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import pytest
import pdfplumber

from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan, NetworkScanResult, NetworkScanEvidence
from app.models.ai import AIResponse
from app.services.pdf_service import PDFGeneratorService
from app.services.ai_service import (
    is_ai_sentence_blocked,
    filter_ai_text_sentences,
    sanitize_ai_data,
    validate_ai_text,
    AIAnalysisService
)


def _extract_pdf_text(pdf_path_or_bytes):
    """Extract complete text from PDF using pdfplumber."""
    if isinstance(pdf_path_or_bytes, (bytes, bytearray)):
        stream = io.BytesIO(pdf_path_or_bytes)
    else:
        stream = pdf_path_or_bytes

    all_text = []
    with pdfplumber.open(stream) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            all_text.append(text)
    return "\n".join(all_text)


# Fixtures from real PDFs and prompt specifications
REAL_PDF_FIXTURES = [
    "assessed as Medium risk, with a security score of 45/100",
    "elevate the overall risk posture of the website to Medium, with a security score of 55",
    "While no active exploits were detected",
]

PARAPHRASE_FIXTURES = [
    "rated Medium",
    "score of fifty-five",
    "risk level: 70",
    "falls into the High band",
    "an overall rating of Low",
    "security score of 60 out of 100",
    "overall risk posture is assessed as Critical",
    "risk score of 85 was calculated",
    "categorized with a risk level of High",
    "rating of None was determined for this endpoint",
    "evaluated as Critical risk based on open services",
    "overall severity is classified as Medium",
    "posture is considered Low risk",
    "gives this host a rating of High",
    "calculated score: 45",
    "no active exploits were found during the scan",
    "exploits were detected against the web application",
    "there was no evidence of compromise or attacks",
    "target was not exploited during assessment",
    "no signs of malicious exploitation were observed",
]

SURVIVING_ORDINARY_FIXTURES = [
    "Missing Content-Security-Policy is a critical finding that should be resolved promptly.",
    "This is a high-severity header misconfiguration.",
    "Implementing HSTS prevents man-in-the-middle attacks on subsequent visits.",
    "A medium-severity finding was reported for the missing X-Frame-Options directive.",
    "Port 80/tcp is open running an Apache HTTP server.",
    "Ensure that cookies are marked with Secure and HttpOnly flags.",
]


@pytest.mark.parametrize("text", REAL_PDF_FIXTURES + PARAPHRASE_FIXTURES)
def test_all_fixtures_and_paraphrases_are_blocked(text):
    """Assert every prohibited score/rating/exploit claim sentence is blocked."""
    blocked, reason = is_ai_sentence_blocked(text)
    assert blocked is True, f"Expected '{text}' to be blocked, but it was allowed. Reason: {reason}"


@pytest.mark.parametrize("text", SURVIVING_ORDINARY_FIXTURES)
def test_ordinary_uses_survive(text):
    """Assert ordinary uses ('a critical finding', 'high-severity header', etc.) survive without false positive."""
    blocked, reason = is_ai_sentence_blocked(text)
    assert blocked is False, f"Expected ordinary use '{text}' to survive, but it was blocked for: {reason}"


def test_ai_prompt_prohibits_prose_scores_and_includes_authoritative_context():
    """Requirement 1: AI prompt tells model authoritative values for context, but forbids prose scores."""
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"}), \
         patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": json.dumps({
                            "security_score": 60,
                            "overall_risk": "High",
                            "executive_summary": "Missing Content-Security-Policy is a critical finding that should be resolved promptly.",
                            "critical_findings": ["Missing Content-Security-Policy is a critical finding."],
                            "recommendations": ["Implement strict Content-Security-Policy directives."],
                            "remediation_priority": [{
                                "finding": "Missing CSP",
                                "priority": "High",
                                "remediation": "Configure Content-Security-Policy header."
                            }]
                        })
                    }]
                }
            }]
        }
        mock_post.return_value = mock_resp

        # Website scan prompt check
        AIAnalysisService.analyze_scan({
            "target": "https://example.com",
            "scan_type": "website",
            "security_score": 60,
            "overall_risk": "High",
            "findings": [{"name": "Missing CSP", "severity": "High"}]
        })
        call_args = mock_post.call_args[1]
        sent_prompt_web = call_args["json"]["contents"][0]["parts"][0]["text"]
        assert "Authoritative Security Score: 60/100" in sent_prompt_web
        assert "Authoritative Risk Level: High" in sent_prompt_web
        assert "PROSE RESTRICTION" in sent_prompt_web
        assert "must NOT state, quote, assert, or mention any score, rating, risk level" in sent_prompt_web

        # Network scan prompt check
        AIAnalysisService.analyze_scan({
            "target": "192.168.1.1",
            "scan_type": "network",
            "security_score": 90,
            "overall_risk": "Low",
            "findings": [{"name": "Port 80 (http) Open", "severity": "Low"}]
        })
        call_args_net = mock_post.call_args[1]
        sent_prompt_net = call_args_net["json"]["contents"][0]["parts"][0]["text"]
        assert "Authoritative Security Score: 90/100" in sent_prompt_net
        assert "Authoritative Risk Level: Low" in sent_prompt_net
        assert "PROSE RESTRICTION" in sent_prompt_net
        assert "must NOT state, quote, assert, or mention any score, rating, risk level" in sent_prompt_net


def test_website_scan_pdf_results_page_and_cached_row_contain_no_dropped_sentences(app, db, test_users):
    """Requirement 4: For website scans, assert generated PDF, results page, and cached row have none of the dropped sentences."""
    client = app.test_client()
    user = test_users['user']
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    scan = Scan(
        user_id=user.id,
        target_type='website',
        target_destination='https://example.com',
        status='completed',
        security_score=60,
        risk_level='High',
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    db.session.add(ScanResult(
        scan_id=scan.id,
        vulnerability_name='Missing Content-Security-Policy (CSP) Header',
        severity='High',
        description='CSP header missing',
        remediation='Configure Content-Security-Policy'
    ))
    db.session.commit()

    # Raw AI payload with real fixtures and paraphrases embedded alongside surviving ordinary text
    raw_ai_payload = {
        "security_score": 45, # contradictory raw score
        "overall_risk": "Medium", # contradictory raw risk
        "executive_summary": (
            "The target was assessed as Medium risk, with a security score of 45/100. "
            "Missing Content-Security-Policy is a critical finding that should be resolved promptly. "
            "While no active exploits were detected, several issues elevate the overall risk posture of the website to Medium, with a security score of 55."
        ),
        "critical_findings": [
            "Missing Content-Security-Policy is a critical finding that should be resolved promptly.",
            "The scan was rated Medium with score of fifty-five.",
            "This is a high-severity header misconfiguration."
        ],
        "recommendations": [
            "This is a high-severity header misconfiguration.",
            "Implementing HSTS prevents man-in-the-middle attacks on subsequent visits.",
            "Assigns an overall rating of Low once fixed.",
            "Ensure that cookies are marked with Secure and HttpOnly flags."
        ],
        "remediation_priority": [
            {
                "finding": "Missing Content-Security-Policy",
                "priority": "High",
                "remediation": "This falls into the High band. Configure CSP directive to protect against XSS."
            }
        ]
    }

    # Sanitize and store in DB
    sanitized_payload = sanitize_ai_data(
        raw_ai_payload,
        authoritative_score=60,
        authoritative_risk="High",
        scan_type="website",
        findings=scan.results,
        is_cached_read=False
    )

    ai_resp = AIResponse(
        prompt="Test Website Prompt",
        response_text=json.dumps(sanitized_payload),
        model_used="gemini-2.5-flash",
        scan_id=scan.id
    )
    db.session.add(ai_resp)
    db.session.commit()

    cached_text = scan.ai_response.response_text

    # 1. Assert cached row contains NONE of the dropped sentences
    assert "assessed as Medium risk, with a security score of 45/100" not in cached_text
    assert "security score of 55" not in cached_text
    assert "While no active exploits were detected" not in cached_text
    assert "rated Medium" not in cached_text
    assert "score of fifty-five" not in cached_text
    assert "an overall rating of Low" not in cached_text
    assert "falls into the High band" not in cached_text

    # Assert cached row DOES contain surviving ordinary sentences
    assert "Missing Content-Security-Policy is a critical finding that should be resolved promptly." in cached_text
    assert "This is a high-severity header misconfiguration." in cached_text
    assert "Implementing HSTS prevents man-in-the-middle attacks on subsequent visits." in cached_text
    assert "Ensure that cookies are marked with Secure and HttpOnly flags." in cached_text

    # 2. Assert results page contains NONE of the dropped sentences and HAS surviving ordinary sentences
    res_page = client.get(f'/scanner/results/{scan.uuid}')
    assert res_page.status_code == 200
    page_html = res_page.data.decode('utf-8')

    assert "assessed as Medium risk, with a security score of 45/100" not in page_html
    assert "security score of 55" not in page_html
    assert "While no active exploits were detected" not in page_html
    assert "rated Medium" not in page_html
    assert "score of fifty-five" not in page_html
    assert "an overall rating of Low" not in page_html
    assert "falls into the High band" not in page_html

    assert "Missing Content-Security-Policy is a critical finding that should be resolved promptly." in page_html
    assert "This is a high-severity header misconfiguration." in page_html

    # 3. Assert generated PDF text (pdfplumber) contains NONE of the dropped sentences and HAS surviving sentences
    report = PDFGeneratorService.generate_scan_report(user.id, scan, sanitized_payload)
    pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
    pdf_text = _extract_pdf_text(pdf_path)

    assert "assessed as Medium risk, with a security score of 45/100" not in pdf_text
    assert "security score of 55" not in pdf_text
    assert "While no active exploits were detected" not in pdf_text
    assert "rated Medium" not in pdf_text
    assert "score of fifty-five" not in pdf_text
    assert "an overall rating of Low" not in pdf_text
    assert "falls into the High band" not in pdf_text

    assert "Missing Content-Security-Policy is a critical finding that should be resolved promptly." in pdf_text
    assert "This is a high-severity header misconfiguration." in pdf_text


def test_network_scan_pdf_results_page_and_cached_row_contain_no_dropped_sentences(app, db, test_users):
    """Requirement 4: For network scans, assert generated PDF, results page, and cached row have none of the dropped sentences."""
    client = app.test_client()
    user = test_users['user']
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    scan = NetworkScan(
        ip_address="192.168.1.55",
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
        service_version="Apache 2.4.41",
        state="open",
        severity="Low",
        remediation="Ensure HTTP traffic redirects automatically to secure HTTPS configurations."
    ))
    db.session.add(NetworkScanEvidence(
        network_scan_id=scan.id,
        phase="discovery",
        command="nmap -Pn -sT -p 80,443 192.168.1.55",
        exit_code=0,
        duration_seconds=1.1,
        nmap_version="7.94",
        raw_xml='<nmaprun><host><status state="up"/></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    ))
    db.session.commit()

    raw_ai_payload = {
        "security_score": 70,
        "overall_risk": "Medium",
        "executive_summary": (
            "The host was categorized with a risk level of High and risk score of 85 was calculated. "
            "Port 80/tcp is open running an Apache HTTP server. "
            "While no active exploits were detected, exploits were detected against similar services in the wild."
        ),
        "critical_findings": [
            "Evaluated as Critical risk based on open services.",
            "There was no evidence of compromise or attacks."
        ],
        "recommendations": [
            "Calculated score: 45 gives this host a rating of High.",
            "Verify that each observed exposure is intended for this host's role."
        ],
        "remediation_priority": [
            {
                "finding": "Port 80 HTTP",
                "priority": "Medium",
                "remediation": "Posture is considered Low risk. Ensure HTTP redirects to HTTPS."
            }
        ]
    }

    sanitized_payload = sanitize_ai_data(
        raw_ai_payload,
        authoritative_score=90,
        authoritative_risk="Low",
        scan_type="network",
        findings=scan.results,
        n_ports=1,
        is_cached_read=False
    )

    ai_resp = AIResponse(
        prompt="Test Network Prompt",
        response_text=json.dumps(sanitized_payload),
        model_used="gemini-2.5-flash",
        network_scan_id=scan.id
    )
    db.session.add(ai_resp)
    db.session.commit()

    cached_text = scan.ai_response.response_text

    # 1. Assert cached row contains NONE of the dropped sentences
    assert "risk score of 85 was calculated" not in cached_text
    assert "categorized with a risk level of High" not in cached_text
    assert "While no active exploits were detected" not in cached_text
    assert "exploits were detected" not in cached_text
    assert "Evaluated as Critical risk" not in cached_text
    assert "there was no evidence of compromise or attacks" not in cached_text
    assert "gives this host a rating of High" not in cached_text
    assert "Posture is considered Low risk" not in cached_text

    # Assert surviving ordinary sentences and deterministic guidance
    assert "Port 80/tcp is open running an Apache HTTP server." in cached_text

    # 2. Results page check
    res_page = client.get(f'/scanner/network/results/{scan.uuid}')
    assert res_page.status_code == 200
    page_html = res_page.data.decode('utf-8')

    assert "risk score of 85 was calculated" not in page_html
    assert "categorized with a risk level of High" not in page_html
    assert "While no active exploits were detected" not in page_html
    assert "gives this host a rating of High" not in page_html
    assert "Port 80/tcp is open running an Apache HTTP server." in page_html

    # 3. PDF check
    report = PDFGeneratorService.generate_scan_report(user.id, scan, sanitized_payload)
    pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
    pdf_text = _extract_pdf_text(pdf_path)

    assert "risk score of 85 was calculated" not in pdf_text
    assert "categorized with a risk level of High" not in pdf_text
    assert "While no active exploits were detected" not in pdf_text
    assert "gives this host a rating of High" not in pdf_text
    assert "Port 80/tcp is open running an Apache HTTP server." in pdf_text


def test_dropping_sentences_empties_block_uses_deterministic_sentence_once():
    """Requirement 3: If dropping sentences empties a block, use the deterministic sentence once."""
    bad_summary = "assessed as Medium risk, with a security score of 45/100. While no active exploits were detected."
    filtered = filter_ai_text_sentences(
        bad_summary,
        authoritative_score=60,
        authoritative_risk="High",
        scan_type="website",
        findings=[{"name": "Missing CSP", "severity": "High"}],
        is_summary=True
    )
    # The deterministic sentence must be returned once
    assert "Security Score: 60/100, Risk Level: HIGH" in filtered
    assert "Missing headers: CSP" in filtered
    assert "assessed as Medium risk" not in filtered


def test_evidence_block_keeptogether_layout(app, db, test_users):
    """Requirement 5: Heading, Scanned Ports line, and evidence table are kept together via KeepTogether."""
    with app.app_context():
        user = test_users['user']
        scan = NetworkScan(
            ip_address="192.168.1.99",
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

        for port, service in [(22, "ssh"), (80, "http"), (443, "https"), (8080, "http-proxy")]:
            db.session.add(NetworkScanResult(
                network_scan_id=scan.id,
                port=port,
                protocol="tcp",
                service_name=service,
                service_version="Apache",
                state="open",
                severity="Low"
            ))

        db.session.add(NetworkScanEvidence(
            network_scan_id=scan.id,
            phase="discovery",
            command="nmap -Pn -sT -p 22,80,443,8080 192.168.1.99",
            exit_code=0,
            duration_seconds=1.5,
            nmap_version="7.94",
            raw_xml='<nmaprun><host><status state="up"/></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        ))
        db.session.commit()

        report = PDFGeneratorService.generate_scan_report(user.id, scan, None)
        pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
        assert os.path.isfile(pdf_path)

        with pdfplumber.open(pdf_path) as pdf:
            evidence_heading_page = None
            scanned_ports_page = None
            evidence_phase_page = None

            for page_idx, page in enumerate(pdf.pages):
                text = page.extract_text() or ""
                if "SCAN EVIDENCE" in text:
                    evidence_heading_page = page_idx
                if "Scanned Ports: 22,80,443,8080" in text:
                    scanned_ports_page = page_idx
                if "discovery" in text and "nmap -Pn -sT" in text:
                    evidence_phase_page = page_idx

            assert evidence_heading_page is not None, "SCAN EVIDENCE heading not found in PDF"
            assert scanned_ports_page is not None, "Scanned Ports line not found in PDF"
            assert evidence_phase_page is not None, "Evidence phase table rows not found in PDF"

            # All three must reside on the exact same page due to KeepTogether
            assert evidence_heading_page == scanned_ports_page == evidence_phase_page, (
                f"Evidence block was split across pages: heading on page {evidence_heading_page + 1}, "
                f"scanned ports on page {scanned_ports_page + 1}, table on page {evidence_phase_page + 1}"
            )


def test_sanitising_cached_rows_on_read_logs_at_debug(app, db, test_users, caplog):
    """Requirement 6: Sanitising cached rows on read should log at DEBUG, not WARNING."""
    ai_logger = logging.getLogger("app.services.ai_service")
    ai_logger.disabled = False
    ai_logger.setLevel(logging.DEBUG)

    client = app.test_client()
    user = test_users['user']
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    scan = Scan(
        user_id=user.id,
        target_type='website',
        target_destination='https://example.com',
        status='completed',
        security_score=60,
        risk_level='High',
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # Cached AI response with a droppable sentence
    ai_resp = AIResponse(
        prompt="Test Prompt",
        response_text=json.dumps({
            "security_score": 60,
            "overall_risk": "High",
            "executive_summary": "assessed as Medium risk, with a security score of 45/100. This is a high-severity header misconfiguration.",
            "critical_findings": ["This is a high-severity header misconfiguration."],
            "recommendations": ["Harden headers."],
            "remediation_priority": []
        }),
        model_used="gemini-2.5-flash",
        scan_id=scan.id
    )
    db.session.add(ai_resp)
    db.session.commit()

    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        res = client.get(f'/scanner/results/{scan.uuid}')
        assert res.status_code == 200

    # Inspect log records
    ai_service_records = [
        r for r in caplog.records
        if "ai_service" in r.name or "Dropped AI sentence" in r.message or "AI text" in r.message
    ]

    # Must have logged at DEBUG
    debug_records = [r for r in ai_service_records if r.levelno == logging.DEBUG]
    assert len(debug_records) > 0, "Expected sanitization on read to log at DEBUG"

    # Must NOT have logged at WARNING for the cached read
    warning_records = [r for r in ai_service_records if r.levelno == logging.WARNING]
    assert len(warning_records) == 0, f"Expected 0 WARNING logs during cached read, got: {warning_records}"
