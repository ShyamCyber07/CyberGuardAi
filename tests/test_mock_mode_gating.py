import json
from unittest.mock import patch
from datetime import datetime, timezone
from app.models.network_scan import NetworkScan, NetworkScanResult
from app.routes.network_scanner.forms import NetworkScanForm


def test_form_choices_gated_by_demo_mode(app, test_users):
    """Test that Simulated / Demonstration Mode is hidden from form unless DEMO_MODE is True."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # 1. When DEMO_MODE is False
    app.config['DEMO_MODE'] = False
    with app.test_request_context():
        form = NetworkScanForm()
        mode_choices = [c[0] for c in form.scanner_mode.choices]
        mode_labels = [c[1] for c in form.scanner_mode.choices]
        assert 'MOCK' not in mode_choices
        assert 'Simulated / Demonstration Mode' not in mode_labels
        assert form.scanner_mode.choices == [('REAL_NMAP', 'Real Nmap Scanner')]

    res = client.get('/scanner/network/')
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert 'Simulated / Demonstration Mode' not in html

    # 2. When DEMO_MODE is True
    app.config['DEMO_MODE'] = True
    with app.test_request_context():
        form = NetworkScanForm()
        mode_choices = [c[0] for c in form.scanner_mode.choices]
        mode_labels = [c[1] for c in form.scanner_mode.choices]
        assert 'MOCK' in mode_choices
        assert 'Simulated / Demonstration Mode' in mode_labels

    res = client.get('/scanner/network/')
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert 'Simulated / Demonstration Mode' in html


def test_api_scan_rejection_when_demo_mode_off_and_on(app, db, test_users):
    """Test that /scanner/network/api/scan rejects scanner_mode='MOCK' with HTTP 400 when DEMO_MODE is off."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    payload = {
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'MOCK'
    }

    # When DEMO_MODE is False -> Rejects with 400
    app.config['DEMO_MODE'] = False
    res = client.post(
        '/scanner/network/api/scan',
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert res.status_code == 400
    data = res.get_json()
    assert data['success'] is False
    assert 'Simulated demonstration mode is disabled' in data['error']

    # When DEMO_MODE is True -> Accepts and runs MOCK scan
    app.config['DEMO_MODE'] = True
    res = client.post(
        '/scanner/network/api/scan',
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['scan']['scanner_mode'] == 'MOCK'


def test_nmap_missing_message_and_no_simulation(app, db, test_users):
    """Test that when Nmap is not installed, error instructs to install from nmap.org and does not offer simulation."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # 1. UI view when Nmap is not available
    with patch("app.routes.network_scanner.routes.is_nmap_available", return_value=False):
        res = client.get('/scanner/network/')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Nmap not found, install it from nmap.org' in html
        assert 'You can still test with Simulated Mode' not in html

    # 2. Form execution when Nmap is not available
    with patch("app.routes.network_scanner.routes.is_nmap_available", return_value=False), \
         patch("app.services.network_scan_service.is_nmap_available", return_value=False):
        res = client.post('/scanner/network/', data={
            'ip_address': '8.8.8.8',
            'scan_profile': 'Quick Scan',
            'scanner_mode': 'REAL_NMAP'
        }, follow_redirects=True)
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Nmap not found, install it from nmap.org' in html

    # 3. API execution when Nmap is not available
    with patch("app.routes.network_scanner.routes.is_nmap_available", return_value=False), \
         patch("app.services.network_scan_service.is_nmap_available", return_value=False):
        res = client.post(
            '/scanner/network/api/scan',
            data=json.dumps({
                'ip_address': '8.8.8.8',
                'scan_profile': 'Quick Scan',
                'scanner_mode': 'REAL_NMAP'
            }),
            content_type='application/json'
        )
        assert res.status_code == 400
        data = res.get_json()
        assert data['success'] is False
        assert 'Nmap not found, install it from nmap.org' in data['error']


def test_simulated_badge_rendered_on_history_results_and_dashboard(app, db, test_users):
    """Test visible SIMULATED badge is rendered on history, results, and dashboard rows for MOCK scans."""
    client = app.test_client()
    user = test_users['user']
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    # Seed a MOCK network scan
    mock_scan = NetworkScan(
        ip_address='198.51.100.42',
        status='completed',
        scan_profile='Quick Scan',
        risk_level='Low',
        scanner_mode='MOCK',
        user_id=user.id,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(mock_scan)
    db.session.commit()

    result = NetworkScanResult(
        network_scan_id=mock_scan.id,
        port=80,
        protocol='tcp',
        state='open',
        service_name='http',
        service_version='Apache/2.4',
        severity='low'
    )
    db.session.add(result)
    db.session.commit()

    # 1. Check Results page
    res = client.get(f'/scanner/network/results/{mock_scan.uuid}')
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert '198.51.100.42' in html
    assert 'SIMULATED' in html

    # 2. Check Unified History page (/history)
    res = client.get('/history')
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert '198.51.100.42' in html
    assert 'SIMULATED' in html

    # 3. Check Dashboard page (/dashboard)
    res = client.get('/dashboard')
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert '198.51.100.42' in html
    assert 'SIMULATED' in html
