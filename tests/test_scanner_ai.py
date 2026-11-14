import os
import json
from datetime import datetime, timezone
import pytest
import requests
from unittest.mock import patch, MagicMock
from app.models.scan import Scan
from app.models.ai import AIResponse
from app.services.scanner_service import ScannerService

# Mock headers for requests.get (Website Scanner)
MOCK_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=()'
}

# Mock Gemini Response
MOCK_GEMINI_RESPONSE = {
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": json.dumps({
                            "security_score": 90,
                            "overall_risk": "Low",
                            "executive_summary": "The website is well-secured with necessary headers present.",
                            "critical_findings": [],
                            "recommendations": ["Keep security dependencies updated."],
                            "remediation_priority": [
                                {
                                    "finding": "Outdated dependencies",
                                    "priority": "Low",
                                    "remediation": "Update libraries regularly."
                                }
                            ]
                        })
                    }
                ]
            }
        }
    ]
}

@pytest.fixture
def mock_scanner_http():
    """Mock the requests.get call performed by the Website Scanner."""
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = MOCK_HEADERS
        mock_get.return_value = mock_resp
        yield mock_get

@pytest.fixture
def mock_gemini_success():
    """Mock the requests.post call to Gemini API returning a valid response."""
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_GEMINI_RESPONSE
        mock_post.return_value = mock_resp
        yield mock_post


@pytest.fixture
def mock_audit_ssl():
    """Mock ScannerService.audit_ssl with a fixed valid result so website scans never touch the network."""
    fixed_ssl = {
        'valid': True,
        'expiry_date': datetime(2027, 6, 1, tzinfo=timezone.utc),
        'days_remaining': 200,
        'tls_version': 'TLSv1.3',
        'issuer': 'DigiCert Global Root CA',
        'error': None,
        'error_type': None
    }
    with patch("app.services.scanner_service.ScannerService.audit_ssl", return_value=fixed_ssl) as mock_ssl:
        yield mock_ssl


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_secret_api_key_123"})
def test_successful_scan_and_ai_analysis(app, db, test_users, mock_scanner_http, mock_gemini_success, mock_audit_ssl):
    """Test successful website scan + successful AI analysis end-to-end integration."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Trigger scan via route index
    res = client.post('/scanner/', data={'target_url': 'https://example.com'}, follow_redirects=True)
    assert res.status_code == 200
    
    # Retrieve the scan from the database
    scan = Scan.query.filter_by(target_destination='https://example.com').first()
    assert scan is not None
    assert scan.status == 'completed'
    
    # Verify AI analysis enforces authoritative score and risk
    assert scan.ai_response is not None
    ai_data = json.loads(scan.ai_response.response_text)
    assert ai_data["security_score"] == 100
    assert ai_data["overall_risk"] == "None"

    # Verify original scanner data remains unchanged
    assert scan.risk_score == 100  # Because all mock headers are present
    assert scan.risk_level == "None"
    assert len(scan.results) == 0

    # Verify AI analysis is displayed correctly on results page
    res_page = client.get(f'/scanner/results/{scan.uuid}')
    assert b"AI Security Analysis" in res_page.data
    assert b"None" in res_page.data
    assert b"The website is well-secured" in res_page.data
    assert b"Keep security dependencies updated" in res_page.data

    # Verify no API key appears in HTML response
    assert b"test_secret_api_key_123" not in res_page.data
    assert b"GEMINI_API_KEY" not in res_page.data


@patch.dict(os.environ, {})
def test_scan_missing_gemini_key(app, db, test_users, mock_scanner_http):
    """Test that a website scan succeeds even if the Gemini API key is missing."""
    if "GEMINI_API_KEY" in os.environ:
        del os.environ["GEMINI_API_KEY"]

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Scan should still succeed
    res = client.post('/scanner/', data={'target_url': 'https://example.com'}, follow_redirects=True)
    assert res.status_code == 200

    scan = Scan.query.filter_by(target_destination='https://example.com').first()
    assert scan is not None
    assert scan.status == 'completed'
    # AI response should be missing (None) due to missing API key
    assert scan.ai_response is None

    # Results page should render unavailable message
    res_page = client.get(f'/scanner/results/{scan.uuid}')
    assert b"AI Analysis Unavailable" in res_page.data


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"})
@patch("requests.post")
def test_scan_gemini_timeout(mock_post, app, db, test_users, mock_scanner_http):
    """Test that a website scan succeeds even if the Gemini API call times out."""
    mock_post.side_effect = requests.exceptions.Timeout("API Timed Out")

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/', data={'target_url': 'https://example.com'}, follow_redirects=True)
    assert res.status_code == 200

    scan = Scan.query.filter_by(target_destination='https://example.com').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert scan.ai_response is None

    # Results page should render unavailable message
    res_page = client.get(f'/scanner/results/{scan.uuid}')
    assert b"AI Analysis Unavailable" in res_page.data


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"})
@patch("requests.post")
def test_scan_invalid_gemini_response(mock_post, app, db, test_users, mock_scanner_http):
    """Test that a website scan succeeds even if the Gemini API returns an invalid JSON response."""
    # Mock invalid JSON response format
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": "invalid_json{}"
                        }
                    ]
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/', data={'target_url': 'https://example.com'}, follow_redirects=True)
    assert res.status_code == 200

    scan = Scan.query.filter_by(target_destination='https://example.com').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert scan.ai_response is None

    # Results page should render unavailable message
    res_page = client.get(f'/scanner/results/{scan.uuid}')
    assert b"AI Analysis Unavailable" in res_page.data


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_quota_key_999"})
@patch("requests.post")
def test_scan_gemini_quota_exceeded_uses_fallback(mock_post, app, db, test_users, mock_scanner_http, mock_audit_ssl):
    """Test that HTTP 429 RESOURCE_EXHAUSTED seamlessly triggers rule-based fallback without breaking scan."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {"Retry-After": "25"}
    mock_resp.json.return_value = {
        "error": {
            "code": 429,
            "message": "Resource has been exhausted (e.g. check quota).",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "25s"
                }
            ]
        }
    }
    mock_post.return_value = mock_resp

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/', data={'target_url': 'https://example.com'}, follow_redirects=True)
    assert res.status_code == 200

    scan = Scan.query.filter_by(target_destination='https://example.com').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert scan.risk_score == 100

    # Fallback AI response must be created and labeled
    assert scan.ai_response is not None
    assert scan.ai_response.model_used == 'rule-based-fallback'

    ai_data = json.loads(scan.ai_response.response_text)
    assert ai_data["_fallback"] is True
    assert ai_data["_model_used"] == "rule-based-fallback"
    assert "[Rule-Based Fallback Analysis]" in ai_data["executive_summary"]
    assert "RESOURCE_EXHAUSTED" in ai_data["executive_summary"]

    # Verify rendering on results page
    res_page = client.get(f'/scanner/results/{scan.uuid}')
    assert b"AI Security Analysis" in res_page.data
    assert b"rule-based-fallback" in res_page.data
    assert b"Rule-Based Fallback Analysis" in res_page.data

    # Verify no raw payload or secret leak
    assert b"test_quota_key_999" not in res_page.data
    assert b"type.googleapis.com" not in res_page.data

