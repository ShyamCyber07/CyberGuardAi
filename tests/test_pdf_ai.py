import os
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from app.models.scan import Scan
from app.models.network_scan import NetworkScan
from app.models.ai import AIResponse

# Mock AI response data
MOCK_PDF_AI_JSON = {
    "security_score": 88,
    "overall_risk": "Medium",
    "executive_summary": "PDF AI summary content that is very descriptive.",
    "critical_findings": ["PDF Finding Alpha", "PDF Finding Beta"],
    "recommendations": ["PDF recommendation primary"],
    "remediation_priority": [
        {
            "finding": "PDF Finding Alpha",
            "priority": "High",
            "remediation": "PDF Action Alpha"
        }
    ]
}

@pytest.fixture
def mock_gemini_post():
    """Mock requests.post to ensure it's not called during PDF generation."""
    with patch("requests.post") as mock_post:
        yield mock_post


@patch.dict(os.environ, {"GEMINI_API_KEY": "secret_gemini_key_pdf_999"})
def test_download_website_scan_pdf_with_ai(app, db, test_users, mock_gemini_post):
    """Test downloading a website scan PDF report with completed AI analysis."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # 1. Create scan
    scan = Scan(
        target_type='website',
        target_destination='https://pdf-test.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=92,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # 2. Create AI Response
    ai_resp = AIResponse(
        prompt="PDF Prompt",
        response_text=json.dumps(MOCK_PDF_AI_JSON),
        model_used="gemini-2.5-flash",
        scan_id=scan.id
    )
    db.session.add(ai_resp)
    db.session.commit()

    # 3. Request PDF
    res = client.get(f'/scanner/results/{scan.uuid}/pdf')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert len(res.data) > 0

    # Assert AI API was not called
    assert mock_gemini_post.call_count == 0

    # Assert content check (binary substring checks for ReportLab PDF format)
    assert b"pdf-test.com" in res.data
    # ReportLab encodes text chunks inside parenthesis
    assert b"PDF AI summary content" in res.data
    assert b"PDF Finding Alpha" in res.data
    assert b"PDF recommendation primary" in res.data

    # Assert key does not leak
    assert b"secret_gemini_key_pdf_999" not in res.data
    assert b"GEMINI_API_KEY" not in res.data


def test_download_network_scan_pdf_with_ai(app, db, test_users, mock_gemini_post):
    """Test downloading a network scan PDF report with completed AI analysis."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # 1. Create scan
    scan = NetworkScan(
        ip_address='192.168.1.55',
        status='completed',
        scan_profile='Full Scan',
        risk_level='High',
        user_id=test_users['user'].id,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # 2. Create AI Response
    ai_resp = AIResponse(
        prompt="PDF Network Prompt",
        response_text=json.dumps(MOCK_PDF_AI_JSON),
        model_used="gemini-2.5-flash",
        network_scan_id=scan.id
    )
    db.session.add(ai_resp)
    db.session.commit()

    # 3. Request PDF
    res = client.get(f'/scanner/network/results/{scan.uuid}/pdf')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    
    assert b"192.168.1.55" in res.data
    assert b"PDF AI summary" in res.data
    assert b"PDF Finding Alpha" in res.data

    assert mock_gemini_post.call_count == 0


def test_download_pdf_missing_ai_response(app, db, test_users, mock_gemini_post):
    """Test that downloading a scan PDF works gracefully and states AI unavailable when AIResponse is missing."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    scan = Scan(
        target_type='website',
        target_destination='https://no-ai-pdf.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=85,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    res = client.get(f'/scanner/results/{scan.uuid}/pdf')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    
    # Assert original scan target is there
    assert b"no-ai-pdf.com" in res.data
    # Assert fallback message is there
    assert b"AI analysis is not available for this scan" in res.data

    assert mock_gemini_post.call_count == 0


def test_download_pdf_long_text(app, db, test_users, mock_gemini_post):
    """Test that PDF generation succeeds and doesn't crash on very long AI response text."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    scan = Scan(
        target_type='website',
        target_destination='https://long-text-pdf.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=75,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    long_summary = "Long summary " * 500  # 6500 characters
    long_ai_json = dict(MOCK_PDF_AI_JSON)
    long_ai_json["executive_summary"] = long_summary

    ai_resp = AIResponse(
        prompt="PDF Long Prompt",
        response_text=json.dumps(long_ai_json),
        model_used="gemini-2.5-flash",
        scan_id=scan.id
    )
    db.session.add(ai_resp)
    db.session.commit()

    res = client.get(f'/scanner/results/{scan.uuid}/pdf')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert len(res.data) > 0


def test_download_pdf_user_isolation(app, db, test_users):
    """Test that a user cannot download/generate another user's PDF report."""
    # Create scan for admin user
    admin_scan = Scan(
        target_type='website',
        target_destination='https://admin-secret.com',
        user_id=test_users['admin'].id,
        status='completed',
        risk_score=99,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(admin_scan)
    db.session.commit()

    # Log in as standard user
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Request PDF for admin's scan
    res = client.get(f'/scanner/results/{admin_scan.uuid}/pdf')
    assert res.status_code == 403


def test_download_pdf_invalid_scan(app, db, test_users):
    """Test that requesting a PDF for a non-existent scan ID returns 404."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.get('/scanner/results/nonexistent-uuid-123/pdf')
    assert res.status_code == 404


def test_download_pdf_path_traversal(app, db, test_users):
    """Test path traversal block in PDF retrieval routes."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Route segment pattern matches uuid, so direct path traversal inside URL segment is blocked by Flask router.
    # We also test that passing encoded dots in uuid does not resolve to local files.
    res = client.get('/scanner/results/%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd/pdf')
    assert res.status_code == 404
