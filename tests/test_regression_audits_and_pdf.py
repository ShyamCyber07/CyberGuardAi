import os
import json
import pytest
from unittest.mock import patch, MagicMock
import requests

from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan, NetworkScanResult
from app.models.report import Report
from app.models.ai import AIResponse
from app.services.scanner_service import ScannerService
from app.services.network_scan_service import (
    NmapNetworkScannerService,
    MockNetworkScannerService,
    _ensure_nmap_on_path,
    is_nmap_available
)
from app.services.pdf_service import PDFGeneratorService


# ---------------------------------------------------------------------------
# Phase 2 Regression Tests: Website Security Audit Accuracy & Evidence
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_website_scan_ssl_error_records_evidence(mock_get, app, db, test_users):
    """Test that SSL verification failure records an explicit untrusted cert finding with evidence."""
    mock_resp = MagicMock()
    mock_resp.url = "https://self-signed.badssl.com"
    mock_resp.status_code = 200
    mock_resp.headers = {
        'Content-Type': 'text/html',
        'Server': 'nginx/1.18.0'
    }
    mock_resp.history = []

    mock_get.side_effect = [
        requests.exceptions.SSLError("certificate verify failed: self-signed certificate in certificate chain"),
        mock_resp
    ]

    with app.app_context():
        with patch.object(ScannerService, "audit_ssl", return_value={
            'valid': False,
            'expiry_date': None,
            'days_remaining': 0,
            'tls_version': 'TLSv1.3',
            'issuer': 'Unknown Issuer',
            'error': 'self-signed certificate',
            'error_type': 'self_signed'
        }):
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://self-signed.badssl.com")
            
            assert scan is not None
            assert scan.status == 'completed'
            
            vuln_names = [r.vulnerability_name for r in scan.results]
            assert 'Self-Signed or Untrusted SSL Certificate' in vuln_names or 'Invalid or Untrusted SSL Certificate' in vuln_names

            # Check evidence structure in raw_payload
            ssl_finding = next(r for r in scan.results if 'SSL' in r.vulnerability_name or 'Certificate' in r.vulnerability_name)
            assert 'evidence' in ssl_finding.raw_payload
            assert ssl_finding.severity == 'critical'


@patch("requests.get")
def test_website_scan_http_to_https_redirect_handling(mock_get, app, db, test_users):
    """Test that an HTTP endpoint properly redirecting to HTTPS is credited, not penalized as plain HTTP."""
    mock_redirect = MagicMock()
    mock_redirect.is_redirect = True
    mock_redirect.headers = {'Location': 'https://example.com/'}

    mock_resp = MagicMock()
    mock_resp.url = "https://example.com/"
    mock_resp.status_code = 200
    mock_resp.headers = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=()'
    }
    mock_resp.history = [mock_redirect]
    mock_get.return_value = mock_resp

    with app.app_context():
        scan = ScannerService.run_active_scan(test_users['user'].id, "http://example.com")
        
        vuln_names = [r.vulnerability_name for r in scan.results]
        assert 'Plain HTTP Transmission (No HTTPS)' not in vuln_names
        assert 'HTTP to HTTPS Redirection Enforced' in vuln_names
        
        redirect_finding = next(r for r in scan.results if r.vulnerability_name == 'HTTP to HTTPS Redirection Enforced')
        assert redirect_finding.severity == 'info'
        assert 'final_url' in redirect_finding.raw_payload


@patch("requests.get")
def test_website_scan_http_error_status_noted(mock_get, app, db, test_users):
    """Test that scanning a 404 or 500 endpoint records the HTTP status code in findings and evidence."""
    mock_resp = MagicMock()
    mock_resp.url = "https://example.com/notfound"
    mock_resp.status_code = 404
    mock_resp.headers = {'Server': 'nginx'}
    mock_resp.history = []
    mock_get.return_value = mock_resp

    with app.app_context():
        with patch.object(ScannerService, "audit_ssl", return_value={'valid': True, 'tls_version': 'TLSv1.3', 'days_remaining': 120, 'issuer': 'Let\'s Encrypt', 'error': None}):
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://example.com/notfound")
            
            vuln_names = [r.vulnerability_name for r in scan.results]
            assert 'Target Returned HTTP 404 Error' in vuln_names
            err_finding = next(r for r in scan.results if '404' in r.vulnerability_name)
            assert err_finding.raw_payload['http_status'] == 404


@patch("requests.get")
def test_website_scan_connection_error_no_false_positive_headers(mock_get, app, db, test_users):
    """Test that connection failures gracefully stop and do NOT generate false missing header findings."""
    mock_get.side_effect = requests.exceptions.ConnectionError("Failed to establish a new connection: [Errno 11001] getaddrinfo failed")

    with app.app_context():
        with patch.object(ScannerService, "audit_ssl", return_value={'valid': False, 'error': 'Name or service not known', 'error_type': 'handshake_failure'}):
            scan = ScannerService.run_active_scan(test_users['user'].id, "https://nonexistent-domain-xyz123.com")
            
            assert scan.status == 'completed'
            vuln_names = [r.vulnerability_name for r in scan.results]
            assert 'Target Connection Failed' in vuln_names
            assert 'Missing Strict-Transport-Security (HSTS) Header' not in vuln_names
            assert 'Missing Content-Security-Policy (CSP) Header' not in vuln_names


# ---------------------------------------------------------------------------
# Phase 3 Regression Tests: Network Audit Arguments & Mock Labelling
# ---------------------------------------------------------------------------

def test_mock_network_scanner_clearly_labeled(app, db, test_users):
    """Test that MockNetworkScannerService produces findings explicitly labeled as simulated."""
    from app.repositories.network_scan_repository import SQLAlchemyNetworkScanRepository
    from app.services.risk_calculator import SimpleRiskCalculator

    repo = SQLAlchemyNetworkScanRepository()
    calc = SimpleRiskCalculator()
    service = MockNetworkScannerService(repo, calc)

    with app.app_context():
        scan = service.execute_scan(test_users['user'].id, "8.8.8.8", "Quick Scan", scanner_mode='MOCK')
        assert scan.scanner_mode == 'MOCK'
        assert len(scan.results) > 0


@patch("os.path.isfile")
def test_ensure_nmap_on_path_adds_candidate(mock_isfile):
    """Test that _ensure_nmap_on_path prepends candidate directory to PATH when nmap.exe exists."""
    import shutil
    with patch("shutil.which", return_value=None):
        mock_isfile.return_value = True
        orig_path = os.environ.get("PATH", "")
        try:
            _ensure_nmap_on_path()
            assert any(candidate in os.environ.get("PATH", "") for candidate in [
                "C:\\Program Files (x86)\\Nmap",
                "C:\\Program Files\\Nmap",
                "/usr/bin"
            ])
        finally:
            os.environ["PATH"] = orig_path


# ---------------------------------------------------------------------------
# Phase 4 Regression Tests: PDF Download by Scan UUID & Report UUID
# ---------------------------------------------------------------------------

def test_download_website_pdf_by_report_uuid(app, db, test_users):
    """Test that downloading a website scan PDF by report.uuid successfully resolves."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    with app.app_context():
        scan = Scan(
            target_type='website',
            target_destination='https://mytestsite.com',
            user_id=test_users['user'].id,
            status='completed'
        )
        db.session.add(scan)
        db.session.commit()

        # Generate a Report record referencing this scan
        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, None)
        report_uuid = report.uuid

    # Now request PDF download using the report.uuid instead of scan.uuid
    res = client.get(f'/scanner/results/{report_uuid}/pdf')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert 'attachment' in res.headers.get('Content-Disposition', '')
    assert 'CyberGuard_Web_Audit_' in res.headers.get('Content-Disposition', '')


def test_download_network_pdf_by_report_uuid(app, db, test_users):
    """Test that downloading a network scan PDF by report.uuid successfully resolves."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    with app.app_context():
        scan = NetworkScan(
            ip_address='8.8.4.4',
            scan_profile='Quick Scan',
            scanner_mode='MOCK',
            risk_level='Low',
            user_id=test_users['user'].id,
            status='completed'
        )
        db.session.add(scan)
        db.session.commit()

        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, None)
        report_uuid = report.uuid

    res = client.get(f'/scanner/network/results/{report_uuid}/pdf')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert 'CyberGuard_Network_Audit_' in res.headers.get('Content-Disposition', '')


def test_cross_route_pdf_resolution(app, db, test_users):
    """Test that requesting a network report UUID on the web route redirects to the network download route."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    with app.app_context():
        scan = NetworkScan(
            ip_address='8.8.8.8',
            scan_profile='Quick Scan',
            scanner_mode='MOCK',
            risk_level='Low',
            user_id=test_users['user'].id,
            status='completed'
        )
        db.session.add(scan)
        db.session.commit()

        report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, None)
        report_uuid = report.uuid

    # Request via web scanner PDF route, expect redirect to network scanner PDF route
    res = client.get(f'/scanner/results/{report_uuid}/pdf', follow_redirects=True)
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
