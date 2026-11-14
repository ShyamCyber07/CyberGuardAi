import pytest
from flask import current_app

def test_website_scanner_ssrf_blocking(app, db, test_users):
    """Verify that private IP / loopback URLs are blocked for security when TESTING config is False."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    app.config['TESTING'] = False
    try:
        res = client.post('/scanner/api/scan', json={
            "target_url": "http://127.0.0.1:8000"
        })
        assert res.status_code == 400
        data = res.get_json()
        assert "blocked" in data["error"]
        
        res_private = client.post('/scanner/api/scan', json={
            "target_url": "http://192.168.1.1/dashboard"
        })
        assert res_private.status_code == 400
        data_p = res_private.get_json()
        assert "blocked" in data_p["error"]
    finally:
        app.config['TESTING'] = True


def test_network_scanner_private_ip_blocking(app, db, test_users):
    """Verify that private and loopback IPs are blocked in the network scanner when TESTING is False."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    app.config['TESTING'] = False
    try:
        res = client.post('/scanner/network/api/scan', json={
            "ip_address": "127.0.0.1",
            "scan_profile": "Quick Scan"
        })
        assert res.status_code == 400
        data = res.get_json()
        assert "blocked" in data["error"]

        res_invalid = client.post('/scanner/network/api/scan', json={
            "ip_address": "invalid-ip-format",
            "scan_profile": "Quick Scan"
        })
        assert res_invalid.status_code == 400
        data_inv = res_invalid.get_json()
        assert "Invalid target format" in data_inv["error"]
    finally:
        app.config['TESTING'] = True


def test_ssrf_blocks_record_threat_log(app, db, test_users):
    """Verify that SSRF target blocking records a ThreatLog entry in the database."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    from app.models.threat import ThreatLog
    # Clear threat logs first
    with app.app_context():
        db.session.query(ThreatLog).delete()
        db.session.commit()

    app.config['TESTING'] = False
    try:
        res = client.post('/scanner/api/scan', json={
            "target_url": "http://127.0.0.1:8000"
        })
        assert res.status_code == 400
        
        # Verify ThreatLog entry exists
        with app.app_context():
            threats = ThreatLog.query.all()
            assert len(threats) > 0
            assert threats[0].threat_type == "SSRF Scan Attempt"
            assert "127.0.0.1" in threats[0].description
    finally:
        app.config['TESTING'] = True


def test_bola_blocks_record_threat_log(app, db, test_users):
    """Verify that unauthorized BOLA queries on AI Assistant record a ThreatLog entry."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id) # Login as user
        sess['_fresh'] = True

    from app.models.threat import ThreatLog
    # Clear threat logs first
    with app.app_context():
        db.session.query(ThreatLog).delete()
        db.session.commit()

    # Admin owns this scan
    from app.models.network_scan import NetworkScan
    with app.app_context():
        scan = NetworkScan(
            ip_address="8.8.8.8",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            user_id=test_users['admin'].id
        )
        db.session.add(scan)
        db.session.commit()
        scan_uuid = scan.uuid

    # Query scan we do not own
    res = client.post('/assistant/ask', json={
        "scan_uuid": scan_uuid,
        "scan_type": "network",
        "question": "What ports are open?"
    })
    assert res.status_code == 403

    # Verify ThreatLog entry exists
    with app.app_context():
        threats = ThreatLog.query.filter_by(threat_type="BOLA Attempt").all()
        assert len(threats) > 0
        assert "AI Assistant BOLA block" in threats[0].description


def test_user_deletion_cascades(app, db, test_users):
    """Verify user account deletions cascade purge network scans and password vault entries."""
    from app.models.user import User
    from app.models.network_scan import NetworkScan
    from app.models.saved_password import SavedPassword

    with app.app_context():
        # Create temp user
        temp_user = User(email="cascade@cyberguard.ai")
        temp_user.set_password("SecureTemp123!")
        db.session.add(temp_user)
        db.session.commit()
        user_id = temp_user.id

        # Create user child records
        scan = NetworkScan(
            ip_address="8.8.8.8",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            user_id=user_id
        )
        password = SavedPassword(
            label="cascade key",
            encrypted_password="some_encrypted_data",
            user_id=user_id
        )
        db.session.add_all([scan, password])
        db.session.commit()

        # Delete user
        db.session.delete(temp_user)
        db.session.commit()

        # Assert cascades deleted the child items
        assert NetworkScan.query.filter_by(user_id=user_id).first() is None
        assert SavedPassword.query.filter_by(user_id=user_id).first() is None
