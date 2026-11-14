import os
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import requests
from app.models.scan import Scan
from app.models.network_scan import NetworkScan
from app.models.ai import AIResponse

# Mock Gemini Response
MOCK_ASSISTANT_GEMINI_RESPONSE = {
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": "The available scan data indicates that port 22 is open, which is the SSH service. Exposure increases attack surface but is not a vulnerability itself."
                    }
                ]
            }
        }
    ]
}

@pytest.fixture
def mock_gemini_success():
    """Mock requests.post returning valid text response."""
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_ASSISTANT_GEMINI_RESPONSE
        mock_post.return_value = mock_resp
        yield mock_post


def test_unauthenticated_user_rejected(app):
    """Test that unauthenticated requests are rejected and redirected to sign in."""
    client = app.test_client()
    res = client.get('/assistant/')
    assert res.status_code == 302
    assert '/auth/login' in res.location

    res_post = client.post('/assistant/ask', json={
        "scan_uuid": "some-uuid",
        "scan_type": "website",
        "question": "What is wrong?"
    })
    assert res_post.status_code == 302


@patch.dict(os.environ, {"GEMINI_API_KEY": "assistant_page_key_111"})
def test_assistant_page_load_does_not_call_gemini(app, db, test_users, mock_gemini_success):
    """Test loading the assistant interface retrieves scans but never fires Gemini calls."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.get('/assistant/')
    assert res.status_code == 200
    # Gemini is not called on page load
    assert mock_gemini_success.call_count == 0
    # No API key exposure
    assert b"assistant_page_key_111" not in res.data
    assert b"GEMINI_API_KEY" not in res.data


@patch.dict(os.environ, {"GEMINI_API_KEY": "assistant_api_key_222"})
def test_ask_question_success(app, db, test_users, mock_gemini_success):
    """Test successful contextual query about user's own scan."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # 1. Create scan
    scan = Scan(
        target_type='website',
        target_destination='https://assistant-test.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=75,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # 2. Get CSRF token to pass protection
    res_page = client.get('/assistant/')
    csrf_token_val = ""
    # Retrieve hidden token from input tag
    for line in res_page.data.decode('utf-8').split('\n'):
        if 'id="csrf_token"' in line:
            csrf_token_val = line.split('value="')[1].split('"')[0]
            break

    assert csrf_token_val != ""

    # 3. Post question
    res = client.post('/assistant/ask', json={
        "scan_uuid": scan.uuid,
        "scan_type": "website",
        "question": "Explain my score please."
    }, headers={
        "X-CSRFToken": csrf_token_val
    })
    
    assert res.status_code == 200
    resp_json = res.get_json()
    assert "answer" in resp_json
    assert "port 22 is open" in resp_json["answer"]

    # Verify Gemini prompt contains actual target and question
    assert mock_gemini_success.call_count == 1
    call_args = mock_gemini_success.call_args[1]
    prompt_text = call_args["json"]["contents"][0]["parts"][0]["text"]
    assert "https://assistant-test.com" in prompt_text
    assert "Explain my score please." in prompt_text
    # API key should not leak in output
    assert b"assistant_api_key_222" not in res.data


def test_ask_question_unauthorized_scan(app, db, test_users):
    """Test that a user cannot query another user's scan details."""
    client = app.test_client()
    
    # Create scan for admin user
    admin_scan = Scan(
        target_type='website',
        target_destination='https://admin-only-secret.com',
        user_id=test_users['admin'].id,
        status='completed',
        risk_score=90,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(admin_scan)
    db.session.commit()

    # Log in as standard user
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Retrieve CSRF
    res_page = client.get('/assistant/')
    csrf_token_val = ""
    for line in res_page.data.decode('utf-8').split('\n'):
        if 'id="csrf_token"' in line:
            csrf_token_val = line.split('value="')[1].split('"')[0]
            break

    # Request query for admin scan
    res = client.post('/assistant/ask', json={
        "scan_uuid": admin_scan.uuid,
        "scan_type": "website",
        "question": "What is the vulnerability?"
    }, headers={
        "X-CSRFToken": csrf_token_val
    })
    assert res.status_code == 403
    assert b"Unauthorized access to this scan" in res.data


def test_ask_question_unknown_scan_uuid(app, db, test_users):
    """Test that requesting Q&A for an unknown scan UUID returns 404."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res_page = client.get('/assistant/')
    csrf_token_val = ""
    for line in res_page.data.decode('utf-8').split('\n'):
        if 'id="csrf_token"' in line:
            csrf_token_val = line.split('value="')[1].split('"')[0]
            break

    res = client.post('/assistant/ask', json={
        "scan_uuid": "fake-uuid-12345",
        "scan_type": "website",
        "question": "What is wrong?"
    }, headers={
        "X-CSRFToken": csrf_token_val
    })
    assert res.status_code == 404
    assert b"not found" in res.data


def test_ask_question_empty_or_long(app, db, test_users):
    """Test that empty or excessively long user questions are rejected with 400 Bad Request."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

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

    res_page = client.get('/assistant/')
    csrf_token_val = ""
    for line in res_page.data.decode('utf-8').split('\n'):
        if 'id="csrf_token"' in line:
            csrf_token_val = line.split('value="')[1].split('"')[0]
            break

    # Empty question
    res = client.post('/assistant/ask', json={
        "scan_uuid": scan.uuid,
        "scan_type": "website",
        "question": "   "
    }, headers={
        "X-CSRFToken": csrf_token_val
    })
    assert res.status_code == 400
    assert b"cannot be empty" in res.data

    # Too long question (> 1000 characters)
    res_long = client.post('/assistant/ask', json={
        "scan_uuid": scan.uuid,
        "scan_type": "website",
        "question": "a" * 1001
    }, headers={
        "X-CSRFToken": csrf_token_val
    })
    assert res_long.status_code == 400
    assert b"too long" in res_long.data


@patch.dict(os.environ, {})
def test_ask_question_missing_api_key(app, db, test_users):
    """Test that missing Gemini API key environment triggers a clean 500 error response."""
    if "GEMINI_API_KEY" in os.environ:
        del os.environ["GEMINI_API_KEY"]

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

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

    res_page = client.get('/assistant/')
    csrf_token_val = ""
    for line in res_page.data.decode('utf-8').split('\n'):
        if 'id="csrf_token"' in line:
            csrf_token_val = line.split('value="')[1].split('"')[0]
            break

    res = client.post('/assistant/ask', json={
        "scan_uuid": scan.uuid,
        "scan_type": "website",
        "question": "Explain things."
    }, headers={
        "X-CSRFToken": csrf_token_val
    })
    assert res.status_code == 500
    assert b"GEMINI_API_KEY" in res.data


@patch.dict(os.environ, {"GEMINI_API_KEY": "timeout_key"})
@patch("requests.post")
def test_ask_question_timeout(mock_post, app, db, test_users):
    """Test that Gemini API timeouts trigger a clean 500 error response."""
    mock_post.side_effect = requests.exceptions.Timeout("API Timed Out")

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

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

    res_page = client.get('/assistant/')
    csrf_token_val = ""
    for line in res_page.data.decode('utf-8').split('\n'):
        if 'id="csrf_token"' in line:
            csrf_token_val = line.split('value="')[1].split('"')[0]
            break

    res = client.post('/assistant/ask', json={
        "scan_uuid": scan.uuid,
        "scan_type": "website",
        "question": "Explain things."
    }, headers={
        "X-CSRFToken": csrf_token_val
    })
    assert res.status_code == 500
    assert b"timed out" in res.data


def test_ask_question_csrf_protection(app, db, test_users):
    """Test that POST requests without a valid CSRF token fail with 400 Bad Request."""
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_users['user'].id)
            sess['_fresh'] = True
    
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
    
        # Attempt POST request without X-CSRFToken header
        res = client.post('/assistant/ask', json={
            "scan_uuid": scan.uuid,
            "scan_type": "website",
            "question": "What is the vulnerability?"
        })
        assert res.status_code == 400
        assert b"CSRF" in res.data or b"bad request" in res.data.lower()
    finally:
        app.config['WTF_CSRF_ENABLED'] = False


@patch.dict(os.environ, {"GEMINI_API_KEY": "assistant_quota_test_key_333"})
@patch("requests.post")
def test_ask_question_quota_exceeded(mock_post, app, db, test_users):
    """Test that HTTP 429 quota exhaustion in assistant returns 429 with sanitized retry delay."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {"Retry-After": "18"}
    mock_resp.json.return_value = {
        "error": {
            "code": 429,
            "message": "Resource has been exhausted.",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "18s"
                }
            ]
        }
    }
    mock_post.return_value = mock_resp

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    scan = Scan(
        target_type='website',
        target_destination='https://quota-test.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=85,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    res_page = client.get('/assistant/')
    csrf_token_val = ""
    for line in res_page.data.decode('utf-8').split('\n'):
        if 'id="csrf_token"' in line:
            csrf_token_val = line.split('value="')[1].split('"')[0]
            break

    res = client.post('/assistant/ask', json={
        "scan_uuid": scan.uuid,
        "scan_type": "website",
        "question": "Can you analyze this scan?"
    }, headers={
        "X-CSRFToken": csrf_token_val
    })

    assert res.status_code == 429
    resp_json = res.get_json()
    assert "error" in resp_json
    assert "18 seconds" in resp_json["error"]
    assert "assistant_quota_test_key_333" not in res.data.decode('utf-8')

