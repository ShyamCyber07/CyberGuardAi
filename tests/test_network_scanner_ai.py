import os
import json
import pytest
import requests
from unittest.mock import patch, MagicMock
from app.models.network_scan import NetworkScan
from app.models.ai import AIResponse

# Mock Gemini Response for Network Scan
MOCK_GEMINI_RESPONSE = {
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": json.dumps({
                            "security_score": 75,
                            "overall_risk": "Medium",
                            "executive_summary": "The host exposes SSH, HTTP, and RDP. Public RDP increases exposure.",
                            "critical_findings": ["Port 3389 RDP is open."],
                            "recommendations": ["Filter port 3389 using firewalls."],
                            "remediation_priority": [
                                {
                                    "finding": "RDP Open Port",
                                    "priority": "High",
                                    "remediation": "Restrict RDP to VPN access only."
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
def mock_gemini_success():
    """Mock the requests.post call to Gemini API returning a valid response."""
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_GEMINI_RESPONSE
        mock_post.return_value = mock_resp
        yield mock_post


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_secret_network_api_key_456"})
def test_network_scan_and_ai_success(app, db, test_users, mock_gemini_success):
    """Test successful network scan + successful AI analysis integration."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Trigger scan via route index (Service Detection profile triggers SSH, Apache, RDP mock findings)
    res = client.post('/scanner/network/', data={
        'ip_address': '192.168.1.1',
        'scan_profile': 'Service Detection'
    }, follow_redirects=True)
    assert res.status_code == 200
    
    # Retrieve the scan from the database
    scan = NetworkScan.query.filter_by(ip_address='192.168.1.1').first()
    assert scan is not None
    assert scan.status == 'completed'
    
    # Verify AIResponse is correctly associated with the scan
    assert scan.ai_response is not None
    assert scan.ai_response.network_scan_id == scan.id
    
    # Verify AI analysis is stored separately as JSON and cannot downgrade High risk to Medium
    ai_data = json.loads(scan.ai_response.response_text)
    assert ai_data["overall_risk"] == "High"
    assert ai_data["executive_summary"] == "The host exposes SSH, HTTP, and RDP. Public RDP increases exposure."

    # Verify original scanner results remain unchanged
    # Service Detection yields 3 findings (SSH, HTTP, RDP) and calculating risk gives High because of RDP
    assert scan.risk_level == "High"
    assert len(scan.results) == 3
    ports = [r.port for r in scan.results]
    assert 22 in ports
    assert 80 in ports
    assert 3389 in ports

    # Verify AI analysis is displayed correctly on results page
    res_page = client.get(f'/scanner/network/results/{scan.uuid}')
    assert b"AI Security Analysis" in res_page.data
    assert b"High" in res_page.data
    assert b"The host exposes SSH" in res_page.data
    assert b"Restrict RDP to VPN access only." in res_page.data

    # Verify no API key appears in HTML responses
    assert b"test_secret_network_api_key_456" not in res_page.data
    assert b"GEMINI_API_KEY" not in res_page.data


@patch.dict(os.environ, {})
def test_network_scan_missing_gemini_key(app, db, test_users):
    """Test that a network scan succeeds even if the Gemini API key is missing."""
    if "GEMINI_API_KEY" in os.environ:
        del os.environ["GEMINI_API_KEY"]

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Scan should still succeed
    res = client.post('/scanner/network/', data={
        'ip_address': '192.168.1.1',
        'scan_profile': 'Quick Scan'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='192.168.1.1').first()
    assert scan is not None
    assert scan.status == 'completed'
    
    # AI response should be missing (None) due to missing API key
    assert scan.ai_response is None

    # Results page should render unavailable message
    res_page = client.get(f'/scanner/network/results/{scan.uuid}')
    assert b"AI Analysis Unavailable" in res_page.data


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"})
@patch("requests.post")
def test_network_scan_gemini_timeout(mock_post, app, db, test_users):
    """Test that a network scan succeeds even if the Gemini API call times out."""
    mock_post.side_effect = requests.exceptions.Timeout("API Timed Out")

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '192.168.1.1',
        'scan_profile': 'Quick Scan'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='192.168.1.1').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert scan.ai_response is None

    # Results page should render unavailable message
    res_page = client.get(f'/scanner/network/results/{scan.uuid}')
    assert b"AI Analysis Unavailable" in res_page.data


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"})
@patch("requests.post")
def test_network_scan_invalid_gemini_response(mock_post, app, db, test_users):
    """Test that a network scan succeeds even if the Gemini API returns an invalid response."""
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

    res = client.post('/scanner/network/', data={
        'ip_address': '192.168.1.1',
        'scan_profile': 'Quick Scan'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='192.168.1.1').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert scan.ai_response is None

    # Results page should render unavailable message
    res_page = client.get(f'/scanner/network/results/{scan.uuid}')
    assert b"AI Analysis Unavailable" in res_page.data


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_quota_key_network_888"})
@patch("requests.post")
def test_network_scan_quota_exceeded_uses_fallback(mock_post, app, db, test_users):
    """Test that HTTP 429 quota exhaustion gracefully triggers heuristic fallback for network scans."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {"Retry-After": "45"}
    mock_resp.json.return_value = {
        "error": {
            "code": 429,
            "message": "Resource has been exhausted.",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "45s"
                }
            ]
        }
    }
    mock_post.return_value = mock_resp

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Run network scan
    res = client.post('/scanner/network/', data={
        'ip_address': '192.168.1.1',
        'scan_profile': 'Service Detection'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='192.168.1.1').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert scan.risk_level == "High"
    assert len(scan.results) == 3

    # Fallback AI response must be created and labeled
    assert scan.ai_response is not None
    assert scan.ai_response.model_used == 'rule-based-fallback'

    ai_data = json.loads(scan.ai_response.response_text)
    assert ai_data["_fallback"] is True
    assert ai_data["_model_used"] == "rule-based-fallback"
    assert "[Rule-Based Fallback Analysis]" in ai_data["executive_summary"]
    assert "RESOURCE_EXHAUSTED" in ai_data["executive_summary"]

    # Verify rendering on results page
    res_page = client.get(f'/scanner/network/results/{scan.uuid}')
    assert b"AI Security Analysis" in res_page.data
    assert b"rule-based-fallback" in res_page.data
    assert b"Rule-Based Fallback Analysis" in res_page.data

    # Verify no raw payload or secret leak
    assert b"test_quota_key_network_888" not in res_page.data

