import os
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from app.models.scan import Scan
from app.models.network_scan import NetworkScan
from app.models.ai import AIResponse

# Mock AI response data
MOCK_DASHBOARD_AI_JSON = {
    "security_score": 85,
    "overall_risk": "Medium",
    "executive_summary": "Dashboard AI summary content.",
    "critical_findings": ["Dashboard Critical Finding A", "Dashboard Critical Finding B"],
    "recommendations": ["Dashboard Recommendation X"],
    "remediation_priority": [
        {
            "finding": "Dashboard Critical Finding A",
            "priority": "High",
            "remediation": "Dashboard Remediation A"
        }
    ]
}

@patch.dict(os.environ, {"GEMINI_API_KEY": "test_dashboard_secret_key_789"})
@patch("requests.post")
def test_dashboard_displays_latest_ai_analysis(mock_post, app, db, test_users):
    """Test that the dashboard fetches and renders the user's latest scan and its AIResponse."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # 1. Create an older website scan
    old_scan = Scan(
        target_type='website',
        target_destination='https://old.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=95,
        started_at=datetime(2026, 8, 9, 10, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 8, 9, 10, 5, 0, tzinfo=timezone.utc)
    )
    db.session.add(old_scan)

    # 2. Create a newer network scan (this will be the latest)
    new_scan = NetworkScan(
        ip_address='10.0.0.1',
        status='completed',
        scan_profile='Quick Scan',
        risk_level='Medium',
        user_id=test_users['user'].id,
        started_at=datetime(2026, 8, 9, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 8, 9, 12, 5, 0, tzinfo=timezone.utc)
    )
    db.session.add(new_scan)
    db.session.commit()

    # 3. Associate AI response with the newer network scan
    ai_resp = AIResponse(
        prompt="Prompt text",
        response_text=json.dumps(MOCK_DASHBOARD_AI_JSON),
        model_used="gemini-2.5-flash",
        network_scan_id=new_scan.id
    )
    db.session.add(ai_resp)
    db.session.commit()

    # Request dashboard page
    res = client.get('/dashboard')
    assert res.status_code == 200

    # Assert latest scan target & info is rendered
    assert b"10.0.0.1" in res.data
    assert b"network" in res.data
    assert b"Medium" in res.data

    # Assert AI analysis contents are rendered
    assert b"Dashboard AI summary content." in res.data
    assert b"Dashboard Critical Finding A" in res.data
    assert b"Dashboard Recommendation X" in res.data
    assert b"Dashboard Remediation A" in res.data

    # Verify no API calls are made to Gemini when fetching dashboard
    assert mock_post.call_count == 0

    # Verify API key never leaks in HTML responses
    assert b"test_dashboard_secret_key_789" not in res.data
    assert b"GEMINI_API_KEY" not in res.data


def test_dashboard_user_isolation(app, db, test_users):
    """Test that a user cannot see another user's scans or AI responses on their dashboard."""
    # 1. Create completed scan + AIResponse for user A (admin)
    admin_scan = Scan(
        target_type='website',
        target_destination='https://admin-only.com',
        user_id=test_users['admin'].id,
        status='completed',
        risk_score=50,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(admin_scan)
    db.session.commit()

    admin_ai = AIResponse(
        prompt="Admin prompt",
        response_text=json.dumps({
            "security_score": 50,
            "overall_risk": "High",
            "executive_summary": "Admin sensitive summary details.",
            "critical_findings": ["Admin leak"],
            "recommendations": [],
            "remediation_priority": []
        }),
        model_used="gemini-2.5-flash",
        scan_id=admin_scan.id
    )
    db.session.add(admin_ai)
    db.session.commit()

    # 2. Log in as user B (standard user)
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Request dashboard page
    res = client.get('/dashboard')
    assert res.status_code == 200

    # Ensure admin user's scan data or AI summary is not visible
    assert b"admin-only.com" not in res.data
    assert b"Admin sensitive summary details." not in res.data
    assert b"Admin leak" not in res.data

    # User B has no scans, so it should display the fallback empty state
    assert b"No Completed Scans Found" in res.data


def test_dashboard_handles_missing_ai_response(app, db, test_users):
    """Test that the dashboard handles completed scans without an associated AI response gracefully."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Create completed scan but NO AI response
    scan = Scan(
        target_type='website',
        target_destination='https://no-ai.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=80,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    res = client.get('/dashboard')
    assert res.status_code == 200

    # Should display AI unavailable status and Analyze Scan button
    assert b"AI Analysis Unavailable" in res.data
    assert b"Analyze Scan" in res.data


def test_dashboard_handles_missing_scan(app, db, test_users):
    """Test that the dashboard displays the appropriate fallback when the user has no scans at all."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # No scans in the database for user
    res = client.get('/dashboard')
    assert res.status_code == 200

    # Displays No Completed Scans Found state
    assert b"No Completed Scans Found" in res.data
    assert b"Run Web Audit" in res.data
    assert b"Run Network Audit" in res.data
