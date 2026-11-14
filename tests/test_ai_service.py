import os
import json
import pytest
import requests
from unittest.mock import patch, MagicMock
from app.services.ai_service import (
    AIAnalysisService,
    MissingAPIKeyError,
    NetworkTimeoutError,
    GeminiAPIFailureError,
    InvalidJSONResponseError,
    GeminiQuotaExceededError,
    parse_gemini_quota_error,
    generate_heuristic_fallback,
    reset_quota_cooldown,
    clear_analysis_cache
)

# Sample valid input scan results
VALID_SCAN_RESULTS = {
    "target": "example.com",
    "scan_type": "website",
    "findings": [
        {
            "name": "Missing HSTS Header",
            "severity": "medium",
            "description": "HTTP Strict Transport Security is not enabled.",
            "remediation": "Configure the HTTP Strict Transport Security header."
        }
    ]
}

# Sample valid mock Gemini response body matching the required schema
MOCK_VALID_GEMINI_RESPONSE = {
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": json.dumps({
                            "security_score": 80,
                            "overall_risk": "Medium",
                            "executive_summary": "The website example.com is missing HTTP Strict Transport Security (HSTS).",
                            "critical_findings": ["Missing HSTS Header"],
                            "recommendations": ["Configure HSTS in web server configs."],
                            "remediation_priority": [
                                {
                                    "finding": "Missing HSTS Header",
                                    "priority": "Medium",
                                    "remediation": "Add HSTS headers."
                                }
                            ]
                        })
                    }
                ]
            }
        }
    ]
}

@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_success(mock_post):
    """Test successful AI analysis of scan results with valid response."""
    # Set up mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_VALID_GEMINI_RESPONSE
    mock_post.return_value = mock_response

    result = AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)

    assert result["security_score"] == 80
    assert result["overall_risk"] == "Medium"
    assert "HSTS" in result["executive_summary"]
    assert result["critical_findings"] == ["Missing HSTS Header"]
    assert result["recommendations"] == ["Configure HSTS in web server configs."]
    assert len(result["remediation_priority"]) == 1
    assert result["remediation_priority"][0]["finding"] == "Missing HSTS Header"


@patch.dict(os.environ, {})
def test_analyze_scan_missing_api_key():
    """Test that MissingAPIKeyError is raised when GEMINI_API_KEY environment variable is absent."""
    # Temporarily remove GEMINI_API_KEY if present in environment
    if "GEMINI_API_KEY" in os.environ:
        del os.environ["GEMINI_API_KEY"]

    with pytest.raises(MissingAPIKeyError) as exc_info:
        AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)
    
    assert "GEMINI_API_KEY" in str(exc_info.value)


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_network_timeout(mock_post):
    """Test that NetworkTimeoutError is raised on requests timeout."""
    mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

    with pytest.raises(NetworkTimeoutError) as exc_info:
        AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)
    
    assert "timed out" in str(exc_info.value)


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_api_failure_status(mock_post):
    """Test that GeminiAPIFailureError is raised when API returns non-200 status."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_post.return_value = mock_response

    with pytest.raises(GeminiAPIFailureError) as exc_info:
        AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)
    
    assert "status code 500" in str(exc_info.value)


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_api_invalid_json_body(mock_post):
    """Test that GeminiAPIFailureError is raised when API response body cannot be parsed as JSON."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_post.return_value = mock_response

    with pytest.raises(GeminiAPIFailureError) as exc_info:
        AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)
    
    assert "Failed to parse" in str(exc_info.value)


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_response_invalid_json(mock_post):
    """Test that InvalidJSONResponseError is raised when the LLM text output is not valid JSON."""
    bad_json_response = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": "{invalid-json-content"
                        }
                    ]
                }
            }
        ]
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = bad_json_response
    mock_post.return_value = mock_response

    with pytest.raises(InvalidJSONResponseError) as exc_info:
        AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)
    
    assert "not valid JSON" in str(exc_info.value)


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_response_schema_violation_missing_key(mock_post):
    """Test that InvalidJSONResponseError is raised when the response is missing a required key."""
    # Missing 'security_score' key
    invalid_schema_response = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "overall_risk": "Medium",
                                "executive_summary": "Summary",
                                "critical_findings": [],
                                "recommendations": [],
                                "remediation_priority": []
                            })
                        }
                    ]
                }
            }
        ]
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = invalid_schema_response
    mock_post.return_value = mock_response

    with pytest.raises(InvalidJSONResponseError) as exc_info:
        AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)
    
    assert "Missing required key" in str(exc_info.value)
    assert "security_score" in str(exc_info.value)


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_response_schema_violation_wrong_type(mock_post):
    """Test that InvalidJSONResponseError is raised when a response key has an incorrect type."""
    # 'critical_findings' should be a list, but it is a string here
    invalid_type_response = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "security_score": 90,
                                "overall_risk": "Low",
                                "executive_summary": "Summary",
                                "critical_findings": "No findings",
                                "recommendations": [],
                                "remediation_priority": []
                            })
                        }
                    ]
                }
            }
        ]
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = invalid_type_response
    mock_post.return_value = mock_response

    with pytest.raises(InvalidJSONResponseError) as exc_info:
        AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)
    
    assert "Invalid type" in str(exc_info.value)
    assert "critical_findings" in str(exc_info.value)


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_incomplete_scan_data_flag(mock_post):
    """Test how the service handles and flags incomplete scan data."""
    # Target and findings are missing/incomplete
    incomplete_scan = {
        "scan_type": "website"
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_VALID_GEMINI_RESPONSE
    mock_post.return_value = mock_response

    # Verify that the internal check identifies it as incomplete
    assert AIAnalysisService._is_incomplete(incomplete_scan) is True

    # The service execution should still complete if the model responds successfully
    result = AIAnalysisService.analyze_scan(incomplete_scan)
    assert result["security_score"] == 80


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_markdown_json_wrapping(mock_post):
    """Test that the service successfully strips markdown JSON code blocks returned by Gemini."""
    markdown_wrapped_response = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": "```json\n" + json.dumps({
                                "security_score": 100,
                                "overall_risk": "None",
                                "executive_summary": "Safe website",
                                "critical_findings": [],
                                "recommendations": [],
                                "remediation_priority": []
                            }) + "\n```"
                        }
                    ]
                }
            }
        ]
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = markdown_wrapped_response
    mock_post.return_value = mock_response

    result = AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS)
    assert result["security_score"] == 100
    assert result["overall_risk"] == "None"


def test_parse_gemini_quota_error_with_retry_info():
    """Test parsing HTTP 429 response containing RetryInfo details."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {}
    mock_resp.json.return_value = {
        "error": {
            "code": 429,
            "message": "Resource has been exhausted (check quota).",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "23.456s"
                }
            ]
        }
    }

    user_msg, retry_delay, is_daily = parse_gemini_quota_error(mock_resp)
    assert retry_delay == 23.456
    assert is_daily is False
    assert "23 seconds" in user_msg
    assert "RESOURCE_EXHAUSTED" in user_msg


def test_parse_gemini_quota_error_with_retry_after_header():
    """Test parsing HTTP 429 response with Retry-After header."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {"Retry-After": "45"}
    mock_resp.json.return_value = {
        "error": {
            "code": 429,
            "message": "Quota exceeded.",
            "status": "RESOURCE_EXHAUSTED"
        }
    }

    user_msg, retry_delay, is_daily = parse_gemini_quota_error(mock_resp)
    assert retry_delay == 45.0
    assert is_daily is False
    assert "45 seconds" in user_msg


def test_parse_gemini_quota_error_daily_quota():
    """Test detecting daily quota exhaustion."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {}
    mock_resp.json.return_value = {
        "error": {
            "code": 429,
            "message": "Quota exceeded for quota metric 'Generate Content API requests per day'.",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "metadata": {
                        "quota_limit": "GenerateContentRequestsPerDay"
                    }
                }
            ]
        }
    }

    user_msg, retry_delay, is_daily = parse_gemini_quota_error(mock_resp)
    assert is_daily is True
    assert "daily request quota exceeded" in user_msg


def test_generate_heuristic_fallback_structure():
    """Test that heuristic fallback output strictly complies with schema and tags fallback."""
    fallback = generate_heuristic_fallback(VALID_SCAN_RESULTS, reason="Testing fallback")
    validated = AIAnalysisService._validate_response(fallback)
    assert validated["_fallback"] is True
    assert validated["_model_used"] == "rule-based-fallback"
    assert "[Rule-Based Fallback Analysis]" in validated["executive_summary"]
    assert "Testing fallback" in validated["executive_summary"]
    assert len(validated["critical_findings"]) >= 1
    assert len(validated["recommendations"]) >= 1


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_quota_exceeded_with_fallback(mock_post):
    """Test that 429 quota exhaustion gracefully generates rule-based fallback when enabled."""
    reset_quota_cooldown()
    clear_analysis_cache()

    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {"Retry-After": "30"}
    mock_resp.json.return_value = {
        "error": {
            "code": 429,
            "message": "Resource has been exhausted.",
            "status": "RESOURCE_EXHAUSTED"
        }
    }
    mock_post.return_value = mock_resp

    result = AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS, fallback_on_quota=True)
    assert result["_fallback"] is True
    assert result["_model_used"] == "rule-based-fallback"
    assert "[Rule-Based Fallback Analysis]" in result["executive_summary"]
    assert "RESOURCE_EXHAUSTED" in result["executive_summary"]
    assert result["security_score"] == 90  # 100 - 10 for medium severity
    reset_quota_cooldown()


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analyze_scan_quota_exceeded_without_fallback(mock_post):
    """Test that 429 quota exhaustion raises GeminiQuotaExceededError when fallback is disabled."""
    reset_quota_cooldown()
    clear_analysis_cache()

    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {"Retry-After": "15"}
    mock_resp.json.return_value = {
        "error": {
            "code": 429,
            "message": "Quota exceeded. Please retry after 15s.",
            "status": "RESOURCE_EXHAUSTED"
        }
    }
    mock_post.return_value = mock_resp

    with pytest.raises(GeminiQuotaExceededError) as exc_info:
        AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS, fallback_on_quota=False)

    err = exc_info.value
    assert "15 seconds" in err.user_message
    assert err.retry_delay == 15.0
    reset_quota_cooldown()


@patch.dict(os.environ, {"GEMINI_API_KEY": "test_key_123"})
@patch("requests.post")
def test_analysis_caching_avoids_duplicate_calls(mock_post):
    """Test that identical scan inputs return cached analysis without invoking Gemini again."""
    reset_quota_cooldown()
    clear_analysis_cache()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = MOCK_VALID_GEMINI_RESPONSE
    mock_post.return_value = mock_resp

    # First call - should call API
    res1 = AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS, user_id=42)
    assert mock_post.call_count == 1

    # Second call with same inputs - should return cached copy
    res2 = AIAnalysisService.analyze_scan(VALID_SCAN_RESULTS, user_id=42)
    assert mock_post.call_count == 1
    assert res1["security_score"] == res2["security_score"]
    assert res1["executive_summary"] == res2["executive_summary"]

