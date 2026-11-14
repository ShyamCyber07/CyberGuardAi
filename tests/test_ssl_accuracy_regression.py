import os
import json
import ssl
import requests
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
import certifi

from app.models.scan import Scan
from app.services.scanner_service import ScannerService


def _mock_headers_response(headers=None, status_code=200):
    """Helper to return a mock HTTP response with all standard security headers present."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.url = "https://test.example.com/"
    mock_resp.history = []
    if headers is None:
        mock_resp.headers = {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'camera=(), microphone=()'
        }
    else:
        mock_resp.headers = headers
    return mock_resp


# ---------------------------------------------------------------------------
# Unit tests for audit_ssl with certifi CA bundle and error classification
# ---------------------------------------------------------------------------

def test_audit_ssl_uses_certifi_ca_bundle():
    """Verify that audit_ssl constructs default SSL context using certifi.where() CA bundle."""
    with patch("ssl.create_default_context") as mock_ctx_factory:
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock

            mock_ssl_sock = MagicMock()
            mock_ssl_sock.getpeercert.return_value = {
                'issuer': [[('commonName', 'DigiCert Global Root CA')]],
                'notAfter': 'Dec 31 23:59:59 2030 GMT'
            }
            mock_ssl_sock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
            mock_ctx_factory.return_value.wrap_socket.return_value = mock_ssl_sock

            res = ScannerService.audit_ssl("test.example.com", port=443)
            assert res['valid'] is True

            # Assert certifi.where() was passed as cafile
            mock_ctx_factory.assert_called_once_with(cafile=certifi.where())


def test_audit_ssl_classifies_expired_certificate():
    """Verify audit_ssl classifies expired certificate errors as 'expired'."""
    raw_error_msg = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1000)"
    with patch("socket.create_connection"):
        with patch("ssl.create_default_context") as mock_ctx_factory:
            mock_ctx_factory.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error_msg)

            res = ScannerService.audit_ssl("expired.example.com", port=443)
            assert res['valid'] is False
            assert res['error_type'] == 'expired'
            assert 'expired' in res['error'].lower()


def test_audit_ssl_classifies_hostname_mismatch():
    """Verify audit_ssl classifies hostname mismatch errors as 'hostname_mismatch'."""
    raw_error_msg = "Certificate hostname mismatch for 'mismatch.example.com'"
    with patch("socket.create_connection"):
        with patch("ssl.create_default_context") as mock_ctx_factory:
            mock_ctx_factory.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error_msg)

            res = ScannerService.audit_ssl("mismatch.example.com", port=443)
            assert res['valid'] is False
            assert res['error_type'] == 'hostname_mismatch'
            assert 'mismatch' in res['error'].lower()


def test_audit_ssl_classifies_self_signed():
    """Verify audit_ssl classifies self-signed certificates as 'self_signed'."""
    raw_error_msg = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain (_ssl.c:1000)"
    with patch("socket.create_connection"):
        with patch("ssl.create_default_context") as mock_ctx_factory:
            mock_ctx_factory.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error_msg)

            res = ScannerService.audit_ssl("selfsigned.example.com", port=443)
            assert res['valid'] is False
            assert res['error_type'] == 'self_signed'
            assert 'self-signed' in res['error'].lower()


def test_audit_ssl_classifies_unverified_scanner_host_local_issuer():
    """
    Verify audit_ssl classifies 'unable to get local issuer certificate'
    as 'unverified_scanner_host' and retains the exact raw error text.
    """
    raw_error_msg = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)"
    with patch("socket.create_connection"):
        with patch("ssl.create_default_context") as mock_ctx_factory:
            mock_ctx_factory.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error_msg)

            res = ScannerService.audit_ssl("incomplete-chain.example.com", port=443)
            assert res['valid'] is False
            assert res['error_type'] == 'unverified_scanner_host'
            assert res['error'] == raw_error_msg


def test_audit_ssl_classifies_unverified_scanner_host_phrase():
    """Verify audit_ssl classifies explicit 'could not verify from the scanner host' text."""
    raw_error_msg = "could not verify from the scanner host: root CA untrusted locally"
    with patch("socket.create_connection"):
        with patch("ssl.create_default_context") as mock_ctx_factory:
            mock_ctx_factory.return_value.wrap_socket.side_effect = ssl.SSLError(raw_error_msg)

            res = ScannerService.audit_ssl("unverified.example.com", port=443)
            assert res['valid'] is False
            assert res['error_type'] == 'unverified_scanner_host'
            assert res['error'] == raw_error_msg


# ---------------------------------------------------------------------------
# End-to-end scan_target / run_active_scan regression tests asserting findings & score
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_scan_expired_cert_penalty_and_critical_finding(mock_get, app, db, test_users):
    """
    Category 1: Expired certificate.
    Asserts: Finding is Critical ('Expired SSL Certificate Detected') and subtracts 30 points (score: 70).
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1000)"

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://expired.example.com")
            assert scan.status == 'completed'
            assert scan.security_score == 70  # 100 - 30

            expired_findings = [r for r in scan.results if r.vulnerability_name == 'Expired SSL Certificate Detected']
            assert len(expired_findings) == 1
            assert expired_findings[0].severity == 'critical'


@patch("requests.get")
def test_scan_hostname_mismatch_penalty_and_high_finding(mock_get, app, db, test_users):
    """
    Category 2: Hostname mismatch.
    Asserts: Finding is High ('SSL Certificate Hostname Mismatch') and subtracts 20 points (score: 80).
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "Certificate hostname mismatch for 'mismatch.example.com'"

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://mismatch.example.com")
            assert scan.status == 'completed'
            assert scan.security_score == 80  # 100 - 20

            mismatch_findings = [r for r in scan.results if r.vulnerability_name == 'SSL Certificate Hostname Mismatch']
            assert len(mismatch_findings) == 1
            assert mismatch_findings[0].severity == 'high'


@patch("requests.get")
def test_scan_self_signed_penalty_and_critical_finding(mock_get, app, db, test_users):
    """
    Category 3: Self-signed certificate.
    Asserts: Finding is Critical ('Self-Signed or Untrusted SSL Certificate') and subtracts 25 points (score: 75).
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1000)"

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://self-signed.example.com")
            assert scan.status == 'completed'
            assert scan.security_score == 75  # 100 - 25

            self_signed_findings = [r for r in scan.results if r.vulnerability_name == 'Self-Signed or Untrusted SSL Certificate']
            assert len(self_signed_findings) == 1
            assert self_signed_findings[0].severity == 'critical'


@patch("requests.get")
def test_scan_unverified_scanner_host_no_penalty_and_info_finding(mock_get, app, db, test_users):
    """
    Category 4: 'Could not verify from the scanner host' (unable to get local issuer certificate).
    CRITICAL REQUIREMENTS:
    - MUST NOT be a High finding (severity must be 'info').
    - MUST NOT subtract 20 points from the score (score remains 100 with all headers present).
    - Report as an informational/inconclusive observation with the raw error text.
    - Header scoring must not be changed.
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)"

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://unverified-host.example.com")
            assert scan.status == 'completed'

            # MUST NOT subtract 20 points: 100 score maintained
            assert scan.security_score == 100

            # Must NOT have any High or Critical SSL findings
            ssl_failures = [r for r in scan.results if r.severity in ('high', 'critical') and 'SSL' in r.vulnerability_name]
            assert len(ssl_failures) == 0

            # Must have informational/inconclusive observation
            info_findings = [r for r in scan.results if 'inconclusive' in r.vulnerability_name.lower() or 'trust store' in r.vulnerability_name.lower() or 'scanner host' in r.vulnerability_name.lower()]
            assert len(info_findings) == 1

            obs = info_findings[0]
            assert obs.severity == 'info'
            assert obs.vulnerability_name == 'TLS verification inconclusive: scanner host trust store problem'
            assert raw_error in obs.raw_payload['evidence']
            assert obs.raw_payload['error'] == raw_error


@patch("requests.get")
def test_scan_unverified_scanner_host_leaves_header_scoring_intact(mock_get, app, db, test_users):
    """
    Category 4 follow-up: Ensure header scoring still functions accurately when
    'unverified from scanner host' occurs.
    Missing: CSP (-15), Referrer-Policy (-5).
    Present: HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy.
    Expected Score: 100 - (15 + 5) = 80 (NO -20 deduction for unverified SSL).
    """
    partial_headers = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Permissions-Policy': 'camera=()'
    }
    mock_get.return_value = _mock_headers_response(headers=partial_headers)
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)"

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://missing-headers.example.com")
            assert scan.status == 'completed'

            # 100 - 15 (CSP) - 5 (Referrer-Policy) = 80; no SSL deduction
            assert scan.security_score == 80

            vuln_names = [r.vulnerability_name for r in scan.results]
            assert 'Missing Content-Security-Policy (CSP) Header' in vuln_names
            assert 'Missing Referrer-Policy Header' in vuln_names
            assert 'TLS verification inconclusive: scanner host trust store problem' in vuln_names


@patch("requests.get")
def test_scan_generic_handshake_failure_penalized(mock_get, app, db, test_users):
    """
    Generic handshake/connection failure (e.g. connection refused):
    Asserts: Finding is High ('SSL/TLS Handshake Failure') and subtracts 20 points (score: 80).
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "Connection refused on port 443"

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.side_effect = ConnectionRefusedError(raw_error)

        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://refused.example.com")
            assert scan.status == 'completed'
            assert scan.security_score == 80  # 100 - 20

            handshake_findings = [r for r in scan.results if r.vulnerability_name == 'SSL/TLS Handshake Failure']
            assert len(handshake_findings) == 1
            assert handshake_findings[0].severity == 'high'


# ---------------------------------------------------------------------------
# Follow-up regression tests: Control probes, verify=False, derive_risk & AI
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_control_probe_all_fail(mock_get, app, db, test_users):
    """
    Item 1: When target handshake fails with 'unable to get local issuer certificate'
    and ALL control probes also fail:
    - Finding is info severity with text "TLS verification inconclusive: scanner host trust store problem"
    - 0 score penalty (score remains 100)
    - Raw error text is preserved in evidence.
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)"

    with patch.object(ScannerService, "run_control_probes", return_value={
        'results': {'www.google.com': False, 'www.cloudflare.com': False, 'www.microsoft.com': False},
        'errors': {'www.google.com': 'Trust store error'},
        'any_succeeded': False,
        'all_failed': True
    }):
        with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

            with app.app_context():
                scan = ScannerService.run_active_scan(test_users['user'].id, "https://all-controls-fail.example.com")
                assert scan.status == 'completed'
                assert scan.security_score == 100  # 0 penalty

                info_finding = next(r for r in scan.results if r.severity == 'info')
                assert info_finding.vulnerability_name == 'TLS verification inconclusive: scanner host trust store problem'
                assert "TLS verification inconclusive: scanner host trust store problem" in info_finding.description
                assert raw_error in info_finding.raw_payload['evidence']
                assert info_finding.raw_payload['error'] == raw_error


@patch("requests.get")
def test_control_probe_one_succeeds(mock_get, app, db, test_users):
    """
    Item 1: When target handshake fails with 'unable to get local issuer certificate'
    and ANY control probe succeeds:
    - Medium finding "SSL Certificate Chain Could Not Be Verified"
    - -10 score penalty (score: 90)
    - Evidence includes raw error and control results.
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)"

    mock_control_results = {'www.google.com': True, 'www.cloudflare.com': False, 'www.microsoft.com': False}
    with patch.object(ScannerService, "run_control_probes", return_value={
        'results': mock_control_results,
        'errors': {'www.cloudflare.com': 'timeout'},
        'any_succeeded': True,
        'all_failed': False
    }):
        with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

            with app.app_context():
                scan = ScannerService.run_active_scan(test_users['user'].id, "https://one-control-succeeds.example.com")
                assert scan.status == 'completed'
                assert scan.security_score == 90  # 100 - 10 penalty

                med_finding = next(r for r in scan.results if r.vulnerability_name == 'SSL Certificate Chain Could Not Be Verified')
                assert med_finding.severity == 'medium'
                assert raw_error in med_finding.raw_payload['evidence']
                assert med_finding.raw_payload['control_results'] == mock_control_results


@patch("requests.get")
def test_verify_false_flag_and_display(mock_get, app, db, test_users):
    """
    Item 2: When requests falls back to verify=False:
    - store tls_verified=False in the finding's raw_payload
    - show "Headers retrieved with TLS verification disabled" on results page and PDF.
    """
    # Simulate requests.get throwing SSLError on verify=True then returning headers on verify=False
    mock_headers = _mock_headers_response()
    mock_get.side_effect = [
        requests.exceptions.SSLError("certificate verify failed: self-signed certificate"),
        mock_headers
    ]

    with patch.object(ScannerService, "audit_ssl", return_value={
        'valid': False,
        'error': 'self-signed certificate',
        'error_type': 'self_signed'
    }):
        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://verify-false-target.example.com")
            assert scan.status == 'completed'

            # Assert tls_verified=False stored in finding raw_payload
            ssl_finding = next(r for r in scan.results if 'self-signed' in r.vulnerability_name.lower())
            assert ssl_finding.raw_payload.get('tls_verified') is False

            # Assert results page contains notice
            client = app.test_client()
            with client.session_transaction() as sess:
                sess['_user_id'] = str(test_users['user'].id)
                sess['_fresh'] = True

            res = client.get(f'/scanner/results/{scan.uuid}')
            assert res.status_code == 200
            html = res.data.decode('utf-8')
            assert "Headers retrieved with TLS verification disabled" in html

            # Assert PDF compilation contains notice
            from app.services.pdf_service import PDFGeneratorService
            report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan)
            pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
            assert os.path.exists(pdf_path)
            try:
                with open(pdf_path, 'rb') as f:
                    pdf_bytes = f.read()
                # ReportLab PDF embeds literal text strings in content streams
                assert b"Headers retrieved with TLS verification disabled" in pdf_bytes
            finally:
                if os.path.exists(pdf_path):
                    try:
                        os.remove(pdf_path)
                    except Exception:
                        pass


@patch("requests.get")
def test_expired_cert_floor_rule_yields_high_risk(mock_get, app, db, test_users):
    """
    Item 3 & 5: Expired cert with score 70 has a critical finding.
    Floor rule elevates risk from Medium to 'High'.
    Asserts: scan.risk_level == 'High' and derive_risk rule is 'critical_finding_floor'.
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1000)"

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://expired-floor.example.com")
            assert scan.security_score == 70  # 100 - 30
            assert scan.risk_level == 'High'

            from app.models.scan import derive_risk
            risk, rule = derive_risk(scan.security_score, scan.results, return_rule=True)
            assert risk == 'High'
            assert rule == 'critical_finding_floor'


@patch("requests.get")
def test_self_signed_cert_floor_rule_yields_high_risk(mock_get, app, db, test_users):
    """
    Item 3 & 5: Self-signed cert with score 75 has a critical finding.
    Floor rule elevates risk from Medium to 'High'.
    Asserts: scan.risk_level == 'High' and derive_risk rule is 'critical_finding_floor'.
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1000)"

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

        with app.app_context():
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://self-signed-floor.example.com")
            assert scan.security_score == 75  # 100 - 25
            assert scan.risk_level == 'High'

            from app.models.scan import derive_risk
            risk, rule = derive_risk(scan.security_score, scan.results, return_rule=True)
            assert risk == 'High'
            assert rule == 'critical_finding_floor'


def test_old_scan_row_keeps_stored_risk_level(app, db, test_users):
    """
    Item 3: Old rows in database with an existing stored risk_level keep it.
    """
    with app.app_context():
        scan = Scan(
            target_type='website',
            target_destination='https://legacy-row.example.com',
            user_id=test_users['user'].id,
            risk_score=70,
            risk_level='Medium',  # Stored risk level on legacy row
            status='completed',
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.commit()

        assert scan.risk_level == 'Medium'
        assert scan.authoritative_risk == 'Medium'
        assert getattr(scan.authoritative_risk, 'rule', None) == 'stored_risk_level'


@patch("requests.post")
@patch("requests.get")
def test_risk_consistency_between_scan_and_ai_output(mock_get, mock_post, app, db, test_users):
    """
    Item 5: Risk consistency between scan and AI output.
    When a scan has an authoritative risk of 'High' (due to critical floor),
    the generated AI fallback or enforced AI payload also produces 'High',
    never downgrading to 'Medium' or 'Low'.
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1000)"

    # AI candidate attempting to downgrade risk to Medium
    mock_gemini_resp = MagicMock()
    mock_gemini_resp.status_code = 200
    mock_gemini_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "security_score": 75,
                                "overall_risk": "Medium",
                                "executive_summary": "Test summary",
                                "critical_findings": ["Self-Signed or Untrusted SSL Certificate"],
                                "recommendations": ["Deploy valid CA cert"],
                                "remediation_priority": []
                            })
                        }
                    ]
                }
            }
        ]
    }
    mock_post.return_value = mock_gemini_resp

    with patch.dict(os.environ, {"GEMINI_API_KEY": "ai_test_key"}):
        with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

            with app.app_context():
                scan = ScannerService.run_active_scan(test_users['user'].id, "https://ai-consistent.example.com")
                assert scan.risk_level == 'High'

                from app.services.ai_service import AIAnalysisService, generate_heuristic_fallback
                from app.models.ai import AIResponse

                # 1. Verify stored AIResponse has matching risk ('High', not downgraded to 'Medium')
                ai_resp = AIResponse.query.filter_by(scan_id=scan.id).first()
                assert ai_resp is not None
                parsed = json.loads(ai_resp.response_text)
                assert parsed.get("overall_risk") == "High"
                assert parsed.get("security_score") == scan.security_score

                # 2. Verify rule-based heuristic fallback also consistently produces 'High'
                findings_data = [{"name": r.vulnerability_name, "severity": r.severity} for r in scan.results]
                fallback = generate_heuristic_fallback({
                    "target": scan.target_destination,
                    "scan_type": "website",
                    "security_score": scan.security_score,
                    "overall_risk": scan.risk_level,
                    "findings": findings_data
                })
                assert fallback["overall_risk"] == "High"


# ---------------------------------------------------------------------------
# Specific regression tests for PDF SSL Status, derive_risk info, and chain evidence
# ---------------------------------------------------------------------------

def test_pdf_ssl_status_categories_text(app, db, test_users):
    """
    Item 1: pdf_service.py SSL Status line driven by error category:
    - expired / self_signed / hostname_mismatch / unverified_cert_chain -> "SSL Issues Discovered"
    - unverified_scanner_host -> "TLS not assessed (scanner host could not verify)"
    - no TLS finding -> "Valid Certificate"
    Asserts against the actual generated PDF binary content.
    """
    from app.services.pdf_service import PDFGeneratorService
    from app.models.scan import ScanResult

    with app.app_context():
        # Case A: unverified_scanner_host
        scan_unverified = Scan(
            target_type='website',
            target_destination='https://unverified.example.com',
            user_id=test_users['user'].id,
            risk_score=100,
            status='completed',
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan_unverified)
        db.session.flush()

        res_unverified = ScanResult(
            scan_id=scan_unverified.id,
            vulnerability_name='TLS verification inconclusive: scanner host trust store problem',
            severity='info',
            description='Scanner host local trust store issue',
            remediation='Check CA certs',
            raw_payload={'error_type': 'unverified_scanner_host'}
        )
        db.session.add(res_unverified)
        db.session.commit()

        report_a = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan_unverified)
        pdf_path_a = os.path.join(app.root_path, 'static', 'reports', f"{report_a.uuid}.pdf")
        try:
            with open(pdf_path_a, 'rb') as f:
                content_a = f.read()
            assert b"SSL Status: TLS not assessed" in content_a
            assert b"scanner host could not verify" in content_a
            assert (
                rb"SSL Status: TLS not assessed \(scanner host could not verify\)" in content_a
                or b"SSL Status: TLS not assessed (scanner host could not verify)" in content_a
            )
        finally:
            if os.path.exists(pdf_path_a):
                os.remove(pdf_path_a)

        # Case B: unverified_cert_chain (or expired, self_signed, hostname_mismatch)
        scan_issues = Scan(
            target_type='website',
            target_destination='https://issues.example.com',
            user_id=test_users['user'].id,
            risk_score=90,
            status='completed',
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan_issues)
        db.session.flush()

        res_issues = ScanResult(
            scan_id=scan_issues.id,
            vulnerability_name='SSL Certificate Chain Could Not Be Verified',
            severity='medium',
            description='Target cert chain could not be validated',
            remediation='Serve complete cert chain',
            raw_payload={'error_type': 'unverified_cert_chain'}
        )
        db.session.add(res_issues)
        db.session.commit()

        report_b = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan_issues)
        pdf_path_b = os.path.join(app.root_path, 'static', 'reports', f"{report_b.uuid}.pdf")
        try:
            with open(pdf_path_b, 'rb') as f:
                content_b = f.read()
            assert b"SSL Status: SSL Issues Discovered" in content_b
        finally:
            if os.path.exists(pdf_path_b):
                os.remove(pdf_path_b)

        # Case C: Valid certificate (no TLS finding)
        scan_valid = Scan(
            target_type='website',
            target_destination='https://valid.example.com',
            user_id=test_users['user'].id,
            risk_score=100,
            status='completed',
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan_valid)
        db.session.commit()

        report_c = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan_valid)
        pdf_path_c = os.path.join(app.root_path, 'static', 'reports', f"{report_c.uuid}.pdf")
        try:
            with open(pdf_path_c, 'rb') as f:
                content_c = f.read()
            assert b"SSL Status: Valid Certificate" in content_c
        finally:
            if os.path.exists(pdf_path_c):
                os.remove(pdf_path_c)


def test_derive_risk_info_findings_only_evaluates_to_none():
    """
    Item 2: derive_risk(): 'None' vs 'Low' must count only findings of severity low or higher.
    A scan with only 'info' findings and score >= 85 is 'None'.
    """
    from app.models.scan import derive_risk

    # 1. Score 100 with only 'info' findings -> 'None'
    info_only_findings = [
        {'name': 'HTTP to HTTPS Redirection Enforced', 'severity': 'info'},
        {'name': 'TLS verification inconclusive: scanner host trust store problem', 'severity': 'info'}
    ]
    risk_info, rule_info = derive_risk(100, info_only_findings, return_rule=True)
    assert risk_info == 'None'
    assert rule_info == 'score_band_none'

    # 2. Score 90 with only 'info' findings -> 'None'
    assert derive_risk(90, info_only_findings) == 'None'

    # 3. Score 90 with 'low' finding -> 'Low'
    low_findings = [
        {'name': 'HTTP to HTTPS Redirection Enforced', 'severity': 'info'},
        {'name': 'Minor Cookie Flag Missing', 'severity': 'low'}
    ]
    risk_low, rule_low = derive_risk(90, low_findings, return_rule=True)
    assert risk_low == 'Low'
    assert rule_low == 'score_band_low'

    # 4. Score 100 with zero findings -> 'None'
    risk_empty, rule_empty = derive_risk(100, [], return_rule=True)
    assert risk_empty == 'None'
    assert rule_empty == 'score_band_none'


@patch("requests.get")
def test_chain_failure_evidence_reworded(mock_get, app, db, test_users):
    """
    Item 3: Reword chain-failure evidence: "certificate chain could not be validated"
    (do not claim a specific cause such as a missing intermediate).
    """
    mock_get.return_value = _mock_headers_response()
    raw_error = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)"

    with patch.object(ScannerService, "run_control_probes", return_value={
        'results': {'www.google.com': True, 'www.cloudflare.com': False, 'www.microsoft.com': False},
        'errors': {},
        'any_succeeded': True,
        'all_failed': False
    }):
        with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(raw_error)

            with app.app_context():
                scan = ScannerService.run_active_scan(test_users['user'].id, "https://chain-fail.example.com")
                assert scan.status == 'completed'

                chain_finding = next(r for r in scan.results if r.vulnerability_name == 'SSL Certificate Chain Could Not Be Verified')
                evidence = chain_finding.raw_payload.get('evidence', '')
                description = chain_finding.description

                # Must contain the exact reworded phrase
                assert "certificate chain could not be validated" in evidence

                # Must NOT claim a specific cause like "missing intermediate"
                assert "missing intermediate" not in evidence.lower()
                assert "missing intermediate" not in description.lower()
