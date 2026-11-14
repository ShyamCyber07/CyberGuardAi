import os
from datetime import datetime, timezone
from unittest.mock import patch
from app.models.scan import Scan
from app.models.network_scan import NetworkScan
from app.models.report import Report

def test_web_scan_form_validation(app, db, test_users):
    """Test URL inputs validation in the Website Security Scanner."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Test invalid URL
    res_invalid = client.post('/scanner/', data={'target_url': 'invalid-url'}, follow_redirects=True)
    assert b"Invalid URL format" in res_invalid.data

    # Test valid URL
    with patch("app.services.scanner_service.ScannerService.audit_ssl", return_value={
        'valid': True,
        'tls_version': 'TLSv1.3',
        'days_remaining': 120,
        'issuer': 'Google Trust Services',
        'expiry_date': datetime.now(timezone.utc),
        'error': None,
        'error_type': None
    }), patch("requests.get") as mock_get:
        from unittest.mock import MagicMock
        mock_resp = MagicMock()
        mock_resp.url = "https://google.com"
        mock_resp.status_code = 200
        mock_resp.headers = {'Strict-Transport-Security': 'max-age=31536000'}
        mock_resp.history = []
        mock_get.return_value = mock_resp

        res_valid = client.post('/scanner/', data={'target_url': 'https://google.com'}, follow_redirects=True)
        assert res_valid.status_code == 200
        assert b"Audit Results" in res_valid.data


def test_network_scan_form_validation(app, db, test_users):
    """Test target input validation in the Network Scanner."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Test invalid IP/Hostname target
    res_invalid = client.post('/scanner/network/', data={
        'ip_address': 'invalid_target!',
        'scan_profile': 'Quick Scan'
    }, follow_redirects=True)
    assert b"Invalid target format" in res_invalid.data

    # Test valid IP target
    res_valid = client.post('/scanner/network/', data={
        'ip_address': '127.0.0.1',
        'scan_profile': 'Quick Scan'
    }, follow_redirects=True)
    assert res_valid.status_code == 200
    assert b"Network Audit Results" in res_valid.data


def test_ai_compliance_trigger(app, db, test_users):
    """Test AI Copilot analysis request triggers."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Create dummy scan
    scan = Scan(
        target_type='website',
        target_destination='https://test.com',
        user_id=test_users['user'].id,
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # Trigger AI analysis
    res = client.post(f'/scanner/results/{scan.uuid}/ai', follow_redirects=True)
    assert res.status_code == 200
    assert b"AI Remediation Report compiled" in res.data or b"AI Analysis" in res.data


def test_pdf_report_download(app, db, test_users):
    """Test PDF compilation and exports download routes."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Create dummy scan
    scan = Scan(
        target_type='website',
        target_destination='https://test.com',
        user_id=test_users['user'].id,
        risk_score=75,
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # Build basic PDF report entry
    report = Report(
        uuid=scan.uuid,
        title='Website Security Audit Report',
        status='finalized',
        user_id=test_users['user'].id,
        scan_id=scan.id
    )
    db.session.add(report)
    db.session.commit()

    # Create dummy report file on disk (so download doesn't fail)
    reports_dir = os.path.join(app.root_path, 'static', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, f"{scan.uuid}.pdf")
    with open(pdf_path, 'w') as f:
        f.write('dummy pdf binary content')

    res = None
    try:
        # Request download
        res = client.get(f'/scanner/results/{scan.uuid}/pdf')
        assert res.status_code == 200
        assert res.mimetype == 'application/pdf'
    finally:
        if res is not None and hasattr(res, 'close'):
            res.close()
        # Clean up file
        if os.path.exists(pdf_path):
            try:
                os.remove(pdf_path)
            except PermissionError:
                pass
