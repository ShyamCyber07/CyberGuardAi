import os
import io
import json
import re
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import pytest
import pdfplumber

from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan, NetworkScanResult
from app.models.ai import AIResponse
from app.services.pdf_service import PDFGeneratorService
from app.services.ai_service import validate_ai_text, sanitize_ai_data, is_restricting_web_ports


def _extract_pdf_text(pdf_bytes_or_path):
    """Extract complete text from PDF using pdfplumber."""
    if isinstance(pdf_bytes_or_path, (bytes, bytearray)):
        stream = io.BytesIO(pdf_bytes_or_path)
    else:
        stream = pdf_bytes_or_path

    all_text = []
    with pdfplumber.open(stream) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            all_text.append(text)
    return "\n".join(all_text)


def audit_pdf_text_for_contradictions(pdf_bytes, authoritative_score, authoritative_risk):
    """
    Generic audit test helper:
    Extract every 'N/100' and every risk word near 'Risk' from the PDF and
    assert they equal the authoritative values.
    """
    text = _extract_pdf_text(pdf_bytes)
    normalized_text = " ".join(text.split())

    # 1. Assert all N/100 matches equal the authoritative score
    if authoritative_score is not None:
        score_matches = re.findall(r'\b(\d{1,3})\s*/\s*100\b', normalized_text)
        assert len(score_matches) > 0, "Expected at least one score in PDF"
        for s in score_matches:
            assert int(s) == authoritative_score, (
                f"Contradictory score in PDF: found {s}/100 but authoritative is {authoritative_score}/100"
            )

    # 2. Assert risk ratings near 'Risk' match authoritative risk
    if authoritative_risk is not None:
        expected_risk = authoritative_risk.upper()
        # Find explicit risk statements
        risk_patterns = [
            r'Risk\s*(?:Level|Assessment)?\s*:?\s*(Critical|High|Medium|Low|None|Inconclusive)',
            r'Overall\s*Risk(?:\s*Assessment)?\s*:?\s*(Critical|High|Medium|Low|None|Inconclusive)',
            r'Risk\s*Level\s*:\s*(Critical|High|Medium|Low|None|Inconclusive)',
            r'\b(Critical|High|Medium|Low|None)\s+risk\b'
        ]
        found_ratings = []
        for pat in risk_patterns:
            for m in re.finditer(pat, normalized_text, re.IGNORECASE):
                for g in m.groups():
                    if g:
                        found_ratings.append(g.upper())

        assert len(found_ratings) > 0, "Expected at least one risk rating in PDF"
        for rating in found_ratings:
            assert rating == expected_risk, (
                f"Contradictory risk in PDF: found '{rating}' near 'Risk' but authoritative is '{expected_risk}'"
            )


def test_website_scan_bad_ai_output_sanitized(app, db, test_users):
    """
    Test bad AI output ("45/100 Medium" for a 60/HIGH website scan):
    Assert the generated PDF text (pdfplumber), the results page, and a cached row contain none of them.
    """
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

    r1 = ScanResult(
        scan_id=scan.id,
        vulnerability_name='Missing Content-Security-Policy (CSP) Header',
        severity='high',
        description='CSP missing',
        remediation='Configure CSP header.'
    )
    r2 = ScanResult(
        scan_id=scan.id,
        vulnerability_name='Missing X-Frame-Options Header',
        severity='medium',
        description='X-Frame-Options missing',
        remediation='Configure X-Frame-Options header.'
    )
    db.session.add_all([r1, r2])
    db.session.commit()

    bad_ai_dict = {
        "security_score": 45,
        "overall_risk": "Medium",
        "executive_summary": "The target was assessed as Medium risk, with a security score of 45/100.",
        "critical_findings": ["Assessed as Medium risk with 45/100 score."],
        "recommendations": ["Keep 45/100 score maintained.", "Medium risk remediation needed."],
        "remediation_priority": [
            {
                "finding": "Missing CSP",
                "priority": "Medium",
                "remediation": "Apply Medium risk fixes to achieve 45/100."
            }
        ]
    }

    mock_gemini_resp = MagicMock()
    mock_gemini_resp.status_code = 200
    mock_gemini_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": json.dumps(bad_ai_dict)}]
                }
            }
        ]
    }

    with patch.dict("os.environ", {"GEMINI_API_KEY": "dummy_test_key"}), \
         patch("requests.post", return_value=mock_gemini_resp):
        res_trigger = client.post(f"/scanner/results/{scan.uuid}/ai", follow_redirects=True)
        assert res_trigger.status_code == 200

    # 1. Assert Cached Row in Database contains none of the bad claims
    cached_row = AIResponse.query.filter_by(scan_id=scan.id).first()
    assert cached_row is not None
    cached_text = cached_row.response_text
    assert "45/100" not in cached_text
    assert "Medium risk" not in cached_text
    assert "assessed as Medium" not in cached_text
    assert "60/100" in cached_text
    assert "HIGH" in cached_text

    # 2. Assert Results Page HTML contains none of the bad claims
    res_page = client.get(f"/scanner/results/{scan.uuid}")
    assert res_page.status_code == 200
    page_html = res_page.get_data(as_text=True)
    assert "45/100" not in page_html
    assert "Medium risk" not in page_html
    assert "assessed as Medium" not in page_html
    assert "60/100" in page_html
    assert "HIGH" in page_html

    # 3. Assert Generated PDF contains none of the bad claims
    res_pdf = client.get(f"/scanner/results/{scan.uuid}/pdf")
    assert res_pdf.status_code == 200
    pdf_text = _extract_pdf_text(res_pdf.data)
    assert "45/100" not in pdf_text
    assert "Medium risk" not in pdf_text
    assert "assessed as Medium" not in pdf_text
    assert "60/100" in pdf_text
    assert "HIGH" in pdf_text

    # 4. Generic audit on the generated PDF
    audit_pdf_text_for_contradictions(res_pdf.data, authoritative_score=60, authoritative_risk='High')


def test_network_scan_bad_ai_output_sanitized(app, db, test_users):
    """
    Test bad AI output for network scan:
    - 'No critical or high-risk vulnerabilities were identified' in implications and recommendations
    - 'restrict access to ports 80 and 443'
    Assert the generated PDF text (pdfplumber), the results page, and a cached row contain none of them.
    """
    client = app.test_client()
    user = test_users['user']
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    net_scan = NetworkScan(
        user_id=user.id,
        ip_address='198.51.100.12',
        status='completed',
        scan_profile='Quick Scan',
        risk_level='Low',
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(net_scan)
    db.session.commit()

    nr1 = NetworkScanResult(
        network_scan_id=net_scan.id,
        port=80,
        protocol='tcp',
        state='open',
        service_name='http',
        service_version='Apache/2.4',
        severity='low',
        remediation='Verify intended web exposure.'
    )
    nr2 = NetworkScanResult(
        network_scan_id=net_scan.id,
        port=443,
        protocol='tcp',
        state='open',
        service_name='https',
        service_version='Apache/2.4',
        severity='low',
        remediation='Verify intended TLS exposure.'
    )
    db.session.add_all([nr1, nr2])
    db.session.commit()

    bad_ai_dict = {
        "security_score": 90,
        "overall_risk": "Low",
        "executive_summary": "No critical or high-risk vulnerabilities were identified in this network port scan.",
        "critical_findings": ["No critical or high-risk vulnerabilities were identified in this network port scan."],
        "recommendations": [
            "restrict access to ports 80 and 443",
            "Ensure safe perimeter controls."
        ],
        "remediation_priority": [
            {
                "finding": "Port 80",
                "priority": "Low",
                "remediation": "restrict access to ports 80 and 443"
            }
        ]
    }

    mock_gemini_resp = MagicMock()
    mock_gemini_resp.status_code = 200
    mock_gemini_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": json.dumps(bad_ai_dict)}]
                }
            }
        ]
    }

    with patch.dict("os.environ", {"GEMINI_API_KEY": "dummy_test_key"}), \
         patch("requests.post", return_value=mock_gemini_resp):
        res_trigger = client.post(f"/scanner/network/results/{net_scan.uuid}/ai", follow_redirects=True)
        assert res_trigger.status_code == 200

    # 1. Assert Cached Row in Database
    cached_row = AIResponse.query.filter_by(network_scan_id=net_scan.id).first()
    assert cached_row is not None
    cached_text = cached_row.response_text
    assert "no critical" not in cached_text.lower()
    assert "were identified" not in cached_text.lower()
    assert "restrict access to ports 80 and 443" not in cached_text.lower()
    assert "2 open ports were observed; this scan did not test for vulnerabilities." in cached_text

    # 2. Assert Results Page HTML
    res_page = client.get(f"/scanner/network/results/{net_scan.uuid}")
    assert res_page.status_code == 200
    page_html = res_page.get_data(as_text=True)
    assert "no critical" not in page_html.lower()
    assert "were identified" not in page_html.lower()
    assert "restrict access to ports 80 and 443" not in page_html.lower()
    assert "2 open ports were observed" in page_html
    assert "this scan did not test for vulnerabilities" in page_html

    # 3. Assert Generated PDF
    res_pdf = client.get(f"/scanner/network/results/{net_scan.uuid}/pdf")
    assert res_pdf.status_code == 200
    pdf_text = _extract_pdf_text(res_pdf.data)
    assert "no critical" not in pdf_text.lower()
    assert "were identified" not in pdf_text.lower()
    assert "restrict access to ports 80 and 443" not in pdf_text.lower()
    assert "2 open ports were observed; this scan did not test for vulnerabilities." in " ".join(pdf_text.split())

    # 4. Generic audit on the generated PDF
    audit_pdf_text_for_contradictions(res_pdf.data, authoritative_score=None, authoritative_risk='Low')


def test_generic_audit_across_multiple_pdf_scenarios(app, db, test_users):
    """
    Generic audit test across various website and network PDF reports:
    Extract every 'N/100' and every risk word near 'Risk' and assert they equal the authoritative values.
    """
    user = test_users['user']

    # Scenario A: Website Scan with 100/LOW (or NONE)
    web_scan_clean = Scan(
        user_id=user.id,
        target_type='website',
        target_destination='https://clean-site.example.com',
        status='completed',
        security_score=100,
        risk_level='None',
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(web_scan_clean)
    db.session.commit()

    ai_data_clean = {
        "security_score": 100,
        "overall_risk": "None",
        "executive_summary": "All security controls are properly configured.",
        "critical_findings": [],
        "recommendations": ["Maintain current security baseline."],
        "remediation_priority": []
    }
    rep_clean = PDFGeneratorService.generate_scan_report(user.id, web_scan_clean, ai_data_clean)
    with open(os.path.join(app.root_path, 'static', 'reports', f"{rep_clean.uuid}.pdf"), 'rb') as f:
        pdf_bytes_clean = f.read()

    audit_pdf_text_for_contradictions(pdf_bytes_clean, authoritative_score=100, authoritative_risk='None')

    # Scenario B: Network Scan with Medium Risk
    net_scan_med = NetworkScan(
        user_id=user.id,
        ip_address='198.51.100.99',
        status='completed',
        scan_profile='Service Detection',
        risk_level='Medium',
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(net_scan_med)
    db.session.commit()

    nr_med = NetworkScanResult(
        network_scan_id=net_scan_med.id,
        port=8080,
        protocol='tcp',
        state='open',
        service_name='http-proxy',
        service_version='Squid',
        severity='medium',
        remediation='Verify intended proxy exposure.'
    )
    db.session.add(nr_med)
    db.session.commit()

    ai_data_med = {
        "security_score": 70,
        "overall_risk": "Medium",
        "executive_summary": "1 open ports were observed; this scan did not test for vulnerabilities.",
        "critical_findings": ["1 open ports were observed; this scan did not test for vulnerabilities."],
        "recommendations": ["Verify that each observed exposure is intended for this host's role."],
        "remediation_priority": [
            {
                "finding": "Port 8080",
                "priority": "Medium",
                "remediation": "Verify that observed port exposure is intended for this host's operational role."
            }
        ]
    }
    rep_med = PDFGeneratorService.generate_scan_report(user.id, net_scan_med, ai_data_med)
    with open(os.path.join(app.root_path, 'static', 'reports', f"{rep_med.uuid}.pdf"), 'rb') as f:
        pdf_bytes_med = f.read()

    audit_pdf_text_for_contradictions(pdf_bytes_med, authoritative_score=None, authoritative_risk='Medium')


def test_ai_assistant_contradiction_replacement(app, db, test_users):
    """Test that AIAssistant answers are also validated against authoritative scanner metrics."""
    from app.services.ai_assistant_service import AIAssistantService

    user = test_users['user']
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

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Based on my analysis, the target has a score of 45/100 and is Medium risk."}]
                }
            }
        ]
    }

    with patch.dict("os.environ", {"GEMINI_API_KEY": "dummy_test_key"}), \
         patch("requests.post", return_value=mock_resp):
        answer = AIAssistantService.ask_question(
            user_id=user.id,
            scan_type='website',
            scan_uuid=scan.uuid,
            user_question="What is the score and risk?"
        )

    assert "45/100" not in answer
    assert "Medium risk" not in answer
    assert "60/100" in answer
    assert "HIGH" in answer
