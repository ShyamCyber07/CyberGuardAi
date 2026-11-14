import os
import re
import json
import time
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
import requests

logger = logging.getLogger(__name__)

class AIServiceError(Exception):
    """Base exception class for all AI Analysis Service errors."""
    pass

class MissingAPIKeyError(AIServiceError):
    """Raised when the Gemini API Key is missing in the environment or configuration."""
    pass

class NetworkTimeoutError(AIServiceError):
    """Raised when the request to Gemini API times out."""
    pass

class GeminiAPIFailureError(AIServiceError):
    """Raised when the Gemini API request fails or returns an error status code."""
    pass

class InvalidJSONResponseError(AIServiceError):
    """Raised when the response from Gemini API is not valid JSON or does not match the expected schema."""
    pass

class GeminiQuotaExceededError(AIServiceError):
    """Raised when the Gemini API returns HTTP 429 or RESOURCE_EXHAUSTED."""
    def __init__(self, message: str, retry_delay: Optional[float] = None, is_daily_quota: bool = False):
        super().__init__(message)
        self.user_message = message
        self.retry_delay = retry_delay
        self.is_daily_quota = is_daily_quota


# Global Rate-Limit Cooldown & In-Memory Response Cache
_quota_cooldown_until: float = 0.0
_daily_quota_exhausted: bool = False
_scan_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL_SECONDS = 600  # 10 minutes
CACHE_MAX_ENTRIES = 200


def get_quota_cooldown_remaining() -> float:
    """Return remaining cooldown seconds if quota cooldown is active, else 0.0."""
    global _quota_cooldown_until, _daily_quota_exhausted
    now = time.time()
    if _daily_quota_exhausted:
        return 86400.0  # Daily quota active
    if now < _quota_cooldown_until:
        return _quota_cooldown_until - now
    return 0.0


def record_quota_cooldown(delay_seconds: float, is_daily: bool = False) -> None:
    """Record an active quota cooldown window."""
    global _quota_cooldown_until, _daily_quota_exhausted
    if is_daily:
        _daily_quota_exhausted = True
        _quota_cooldown_until = time.time() + 86400.0
    else:
        _quota_cooldown_until = max(_quota_cooldown_until, time.time() + max(1.0, delay_seconds))


def reset_quota_cooldown() -> None:
    """Reset cooldown state (used for testing or environment re-initialization)."""
    global _quota_cooldown_until, _daily_quota_exhausted
    _quota_cooldown_until = 0.0
    _daily_quota_exhausted = False


def clear_analysis_cache() -> None:
    """Clear all entries in the analysis response cache."""
    global _scan_cache
    _scan_cache.clear()


def parse_gemini_quota_error(response: requests.Response) -> Tuple[str, Optional[float], bool]:
    """
    Parse HTTP 429 / RESOURCE_EXHAUSTED response from Gemini.
    Returns:
        (user_friendly_message, retry_delay_seconds, is_daily_quota)
    Never exposes raw internal tracebacks, project numbers, or API keys.
    """
    retry_delay: Optional[float] = None
    is_daily: bool = False

    # 1. Check standard HTTP Retry-After header
    retry_after = response.headers.get("Retry-After") if hasattr(response, "headers") else None
    if retry_after:
        try:
            retry_delay = float(retry_after)
        except (ValueError, TypeError):
            pass

    # 2. Inspect JSON error body
    raw_message = ""
    try:
        data = response.json()
        error_obj = data.get("error", {})
        raw_message = str(error_obj.get("message", ""))
        
        # Check details list for RetryInfo or QuotaFailure
        details = error_obj.get("details", [])
        if isinstance(details, list):
            for item in details:
                if isinstance(item, dict):
                    # Check RetryInfo
                    type_str = str(item.get("@type", ""))
                    if "RetryInfo" in type_str and "retryDelay" in item:
                        delay_str = str(item.get("retryDelay", ""))
                        match = re.search(r"(\d+(?:\.\d+)?)s?", delay_str)
                        if match:
                            try:
                                retry_delay = float(match.group(1))
                            except ValueError:
                                pass
                    # Check ErrorInfo / QuotaFailure metadata
                    metadata = item.get("metadata", {})
                    quota_limit = str(metadata.get("quota_limit", ""))
                    if "PerDay" in quota_limit or "daily" in quota_limit.lower():
                        is_daily = True
    except Exception:
        raw_message = response.text[:200] if hasattr(response, "text") and response.text else ""

    # 3. Text heuristic checks for daily quota or retry delay
    combined_text = (raw_message + " " + (response.headers.get("Retry-After", "") if hasattr(response, "headers") else "")).lower()
    if any(k in combined_text for k in ["perday", "per day", "daily", "day quota", "daily quota"]):
        is_daily = True

    if retry_delay is None and raw_message:
        match = re.search(r"retry\s+(?:after|in)\s+(\d+(?:\.\d+)?)\s*s?", raw_message, re.IGNORECASE)
        if match:
            try:
                retry_delay = float(match.group(1))
            except ValueError:
                pass

    if retry_delay is not None and retry_delay > 300:
        is_daily = True

    # 4. Construct sanitized user-friendly message
    if is_daily:
        user_msg = "Gemini free-tier daily request quota exceeded (RESOURCE_EXHAUSTED). Please try again tomorrow or upgrade your quota."
    elif retry_delay is not None and retry_delay > 0:
        delay_int = int(round(retry_delay))
        user_msg = f"Gemini API request quota temporarily exhausted (RESOURCE_EXHAUSTED). Please retry in approximately {delay_int} seconds."
    else:
        user_msg = "Gemini API request quota exceeded (RESOURCE_EXHAUSTED). The service is temporarily rate-limited."

    return user_msg, retry_delay, is_daily


def generate_heuristic_fallback(scan_results: Dict[str, Any], reason: str = "Quota limit reached") -> Dict[str, Any]:
    """
    Generate an offline rule-based heuristic assessment matching the standard AI response schema.
    Clearly tags the result with executive summary labeling and model_used='rule-based-fallback'.
    """
    if not isinstance(scan_results, dict):
        scan_results = {}

    target = scan_results.get("target") or "Unknown Target"
    scan_type = scan_results.get("scan_type") or "system"
    raw_findings = scan_results.get("findings") if isinstance(scan_results.get("findings"), list) else []

    findings = [f for f in raw_findings if isinstance(f, dict)]

    # Compute rule-based score
    score = 100
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev == "critical":
            score -= 25
        elif sev == "high":
            score -= 20
        elif sev == "medium":
            score -= 10
        elif sev == "low":
            score -= 5
        elif sev == "info":
            score -= 0
    score = max(0, min(100, score))

    # Overall risk determination
    has_critical = any(str(f.get("severity", "")).lower() == "critical" for f in findings)
    has_high = any(str(f.get("severity", "")).lower() == "high" for f in findings)
    has_medium = any(str(f.get("severity", "")).lower() == "medium" for f in findings)

    if not findings:
        overall_risk = "None"
        critical_findings = []
        recommendations = ["Target configuration returned clean audit signatures. Continue routine monitoring."]
        remediation_priority = []
        summary = (
            f"[Rule-Based Fallback Analysis] Live Gemini AI analysis is currently unavailable ({reason}). "
            f"Automated heuristic review confirms target '{target}' has no detected vulnerabilities or exposed risks."
        )
    else:
        from app.models.scan import derive_risk
        overall_risk = str(derive_risk(score, findings))

        # Critical findings list
        critical_findings = []
        for f in findings:
            if str(f.get("severity", "")).lower() in ("critical", "high", "medium"):
                critical_findings.append(f.get("name", "Unknown Finding"))
        if not critical_findings and findings:
            critical_findings.append(findings[0].get("name", "Finding"))

        # Recommendations list
        recommendations = []
        for f in findings:
            remediation = f.get("remediation")
            if remediation and remediation not in recommendations:
                recommendations.append(remediation)
        if not recommendations:
            recommendations.append("Apply standard defensive hardening and restrict unnecessary listening endpoints.")

        # Remediation priority objects
        remediation_priority = []
        valid_priorities = {"Critical", "High", "Medium", "Low"}
        for f in findings:
            raw_prio = str(f.get("severity", "Medium")).capitalize()
            prio = raw_prio if raw_prio in valid_priorities else "Medium"
            remediation_priority.append({
                "finding": str(f.get("name", "Detected Finding")),
                "priority": prio,
                "remediation": str(f.get("remediation", "Implement standard defensive controls."))
            })

        # Use authoritative score and risk if supplied in scan_results
        if scan_results.get("security_score") is not None:
            score = int(scan_results["security_score"])
        if scan_results.get("overall_risk") is not None:
            overall_risk = scan_results["overall_risk"]

        summary = (
            f"[Rule-Based Fallback Analysis] Live Gemini AI analysis is currently unavailable ({reason}). "
            f"Automated heuristic assessment cataloged {len(findings)} finding(s) on target '{target}'. "
            f"Overall defensive posture is rated as {overall_risk}."
        )

    fallback_payload = {
        "security_score": score,
        "overall_risk": overall_risk,
        "executive_summary": summary,
        "critical_findings": critical_findings,
        "recommendations": recommendations,
        "remediation_priority": remediation_priority,
        "_fallback": True,
        "_model_used": "rule-based-fallback"
    }

    return fallback_payload


def _get_cache_key(scan_results: Dict[str, Any], user_id: Optional[int] = None) -> str:
    target = str(scan_results.get("target", ""))
    scan_type = str(scan_results.get("scan_type", ""))
    findings = scan_results.get("findings", [])
    findings_repr = json.dumps(findings, sort_keys=True)
    findings_hash = hashlib.sha256(findings_repr.encode("utf-8")).hexdigest()
    user_prefix = f"user_{user_id}:" if user_id is not None else "global:"
    return f"{user_prefix}{scan_type}:{target}:{findings_hash}"


def _get_cached_analysis(cache_key: str) -> Optional[Dict[str, Any]]:
    now = time.time()
    entry = _scan_cache.get(cache_key)
    if entry:
        timestamp, data = entry
        if now - timestamp < CACHE_TTL_SECONDS:
            return json.loads(json.dumps(data))
        else:
            _scan_cache.pop(cache_key, None)
    return None


def _set_cached_analysis(cache_key: str, data: Dict[str, Any]) -> None:
    now = time.time()
    if len(_scan_cache) >= CACHE_MAX_ENTRIES:
        oldest_key = min(_scan_cache.keys(), key=lambda k: _scan_cache[k][0])
        _scan_cache.pop(oldest_key, None)
    _scan_cache[cache_key] = (now, json.loads(json.dumps(data)))


class AIAnalysisService:
    """Production-ready service for analyzing security scan results using Gemini API."""

    DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    DEFAULT_TIMEOUT = 12.0

    @classmethod
    def _is_incomplete(cls, scan_results: Dict[str, Any]) -> bool:
        """
        Helper method to determine if the provided scan data is incomplete.
        """
        if not isinstance(scan_results, dict):
            return True
        if not scan_results.get("target"):
            return True
        if "findings" not in scan_results or not isinstance(scan_results.get("findings"), list):
            return True
        
        for finding in scan_results["findings"]:
            if not isinstance(finding, dict):
                return True
            if not finding.get("name") or not finding.get("severity"):
                return True
                
        return False

    @classmethod
    def _validate_response(cls, parsed_json: Any, scan_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Validates that the parsed JSON response strictly complies with the required schema.
        Also validates that AI output does not invent findings or contradict scanner evidence.
        """
        if not isinstance(parsed_json, dict):
            raise InvalidJSONResponseError("Gemini response is not a JSON object/dictionary.")

        required_keys = {
            "security_score": (int, float),
            "overall_risk": str,
            "executive_summary": str,
            "critical_findings": list,
            "recommendations": list,
            "remediation_priority": list
        }

        # 1. Validate keys and basic types
        for key, expected_type in required_keys.items():
            if key not in parsed_json:
                raise InvalidJSONResponseError(f"Missing required key in JSON response: '{key}'")
            if not isinstance(parsed_json[key], expected_type):
                raise InvalidJSONResponseError(
                    f"Invalid type for key '{key}'. Expected {expected_type}, got {type(parsed_json[key])}."
                )

        # 2. Normalize and cast security_score to an integer
        try:
            parsed_json["security_score"] = int(parsed_json["security_score"])
        except (ValueError, TypeError) as e:
            raise InvalidJSONResponseError(f"Failed to cast 'security_score' to integer: {e}")

        # 3. Validate overall_risk value
        valid_risks = {"Critical", "High", "Medium", "Low", "None"}
        risk_value = parsed_json["overall_risk"]
        if risk_value not in valid_risks:
            if isinstance(risk_value, str):
                normalized = risk_value.capitalize()
                if normalized in valid_risks:
                    parsed_json["overall_risk"] = normalized
                else:
                    raise InvalidJSONResponseError(
                        f"Invalid 'overall_risk' value: '{risk_value}'. Must be one of {valid_risks}."
                    )
            else:
                raise InvalidJSONResponseError(
                    f"Invalid 'overall_risk' value: '{risk_value}'. Must be one of {valid_risks}."
                )

        # 4. Validate findings & recommendations lists
        for item in parsed_json["critical_findings"]:
            if not isinstance(item, str):
                raise InvalidJSONResponseError("All items in 'critical_findings' must be strings.")

        for item in parsed_json["recommendations"]:
            if not isinstance(item, str):
                raise InvalidJSONResponseError("All items in 'recommendations' must be strings.")

        # 5. Validate remediation_priority list objects
        for item in parsed_json["remediation_priority"]:
            if not isinstance(item, dict):
                raise InvalidJSONResponseError("All items in 'remediation_priority' must be JSON objects/dictionaries.")
            
            for field in ["finding", "priority", "remediation"]:
                if field not in item:
                    raise InvalidJSONResponseError(f"Missing field '{field}' in remediation priority item.")
                if not isinstance(item[field], str):
                    raise InvalidJSONResponseError(f"Field '{field}' in remediation priority item must be a string.")

        # 6. Contradiction & Hallucination Sanitization
        if scan_results and isinstance(scan_results, dict):
            raw_findings = scan_results.get("findings", [])
            valid_findings = [f for f in raw_findings if isinstance(f, dict)]

            if not valid_findings:
                # Clean scan target: AI must not invent critical findings or high risk
                if parsed_json.get("critical_findings"):
                    logger.warning("Sanitizing invented critical findings on clean scan target")
                    parsed_json["critical_findings"] = []
                if parsed_json.get("overall_risk") in ("Critical", "High"):
                    logger.warning("Correcting contradictory AI overall risk on clean target")
                    parsed_json["overall_risk"] = "None"
            else:
                scanner_names_lower = [f.get("name", "").strip().lower() for f in valid_findings]

                # Check for invented critical findings
                sanitized_crit = []
                for cf in parsed_json.get("critical_findings", []):
                    cf_lower = cf.lower()
                    matches = any(name in cf_lower or any(word in cf_lower for word in name.split() if len(word) > 3) for name in scanner_names_lower)
                    if matches:
                        sanitized_crit.append(cf)
                    else:
                        logger.warning(f"Rejecting invented AI critical finding: {cf}")
                parsed_json["critical_findings"] = sanitized_crit

                # Filter invented remediation priorities
                sanitized_prio = []
                for item in parsed_json.get("remediation_priority", []):
                    item_f = item.get("finding", "").lower()
                    matches = any(name in item_f or any(word in item_f for word in name.split() if len(word) > 3) for name in scanner_names_lower)
                    if matches:
                        sanitized_prio.append(item)
                    else:
                        logger.warning(f"Rejecting invented AI remediation item: {item.get('finding')}")

                if not sanitized_prio and valid_findings:
                    for f in valid_findings[:4]:
                        raw_p = str(f.get("severity", "Medium")).capitalize()
                        sanitized_prio.append({
                            "finding": str(f.get("name", "Detected Finding")),
                            "priority": raw_p if raw_p in {"Critical", "High", "Medium", "Low"} else "Medium",
                            "remediation": str(f.get("remediation", "Apply defensive controls."))
                        })
                parsed_json["remediation_priority"] = sanitized_prio

                # Contradiction check on risk severity: AI cannot downgrade High or Critical
                has_critical_scanner = any(str(f.get("severity", "")).lower() == "critical" for f in valid_findings)
                has_high_scanner = any(str(f.get("severity", "")).lower() == "high" for f in valid_findings)
                current_ai_risk = parsed_json.get("overall_risk")
                if has_critical_scanner and current_ai_risk in ("None", "Low", "Medium", "High"):
                    logger.warning("Correcting contradictory AI overall risk to Critical due to critical scanner finding")
                    parsed_json["overall_risk"] = "Critical"
                elif has_high_scanner and current_ai_risk in ("None", "Low", "Medium"):
                    logger.warning("Correcting contradictory AI overall risk to High due to high scanner finding")
                    parsed_json["overall_risk"] = "High"

            # Prefer enforcing exact authoritative risk and score when provided or requested
            if scan_results.get("enforce_authoritative_metrics") or scan_results.get("overall_risk") is not None:
                if "security_score" in scan_results and scan_results["security_score"] is not None:
                    parsed_json["security_score"] = int(scan_results["security_score"])
                if "overall_risk" in scan_results and scan_results["overall_risk"] is not None:
                    parsed_json["overall_risk"] = str(scan_results["overall_risk"]).capitalize()

        return parsed_json

    @classmethod
    def analyze_scan(
        cls,
        scan_results: Dict[str, Any],
        model_name: str = None,
        fallback_on_quota: bool = True,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Analyzes the given structured scan results and returns a structured JSON analysis.
        Gracefully falls back to rule-based analysis if Gemini quota is exhausted and fallback_on_quota is True.
        """
        # 1. API Key Validation
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise MissingAPIKeyError("The GEMINI_API_KEY environment variable is not set.")

        # 2. Check completeness of input scan data
        is_incomplete = cls._is_incomplete(scan_results)

        # 3. Check Response Cache for identical input under user isolation
        cache_key = _get_cache_key(scan_results, user_id=user_id)
        cached_result = _get_cached_analysis(cache_key)
        if cached_result:
            logger.debug(f"Returning cached AI analysis for target {scan_results.get('target')}")
            return cached_result

        # 4. Check active quota cooldown window
        cooldown_remaining = get_quota_cooldown_remaining()
        if cooldown_remaining > 0:
            logger.warning(
                f"Gemini API quota cooldown active ({int(round(cooldown_remaining))}s remaining)."
            )
            if fallback_on_quota:
                fallback_data = generate_heuristic_fallback(
                    scan_results,
                    reason=f"Quota cooldown active, retry in {int(round(cooldown_remaining))}s"
                )
                return cls._validate_response(fallback_data, scan_results=scan_results)
            else:
                raise GeminiQuotaExceededError(
                    f"Gemini API quota temporarily exhausted. Please retry in approximately {int(round(cooldown_remaining))} seconds.",
                    retry_delay=cooldown_remaining,
                    is_daily_quota=_daily_quota_exhausted
                )

        # 5. Build Prompt
        target = scan_results.get("target") if isinstance(scan_results, dict) else None
        scan_type = scan_results.get("scan_type") if isinstance(scan_results, dict) else None
        findings = scan_results.get("findings") if isinstance(scan_results, dict) and isinstance(scan_results.get("findings"), list) else []

        prompt = f"""You are a Senior AI Engineer and Cybersecurity Architect.
Your task is to analyze the security scanner results and generate a structured risk assessment report.

### SCAN INFO
- Target Target: {target or 'Unknown Target'}
- Scan Type: {scan_type or 'Unknown Scan Type'}

### SCAN FINDINGS
"""
        if not findings:
            prompt += "No vulnerabilities or open ports were detected during this scan.\n"
        else:
            for idx, finding in enumerate(findings, start=1):
                if isinstance(finding, dict):
                    prompt += f"Finding #{idx}:\n"
                    prompt += f"- Name: {finding.get('name', 'Unknown')}\n"
                    prompt += f"- Severity: {finding.get('severity', 'Unknown')}\n"
                    prompt += f"- Description: {finding.get('description', 'No description provided')}\n"
                    prompt += f"- Remediation: {finding.get('remediation', 'No remediation provided')}\n\n"

        prompt += """
### CRITICAL COMPLIANCE RULES:
1. You must ONLY analyze the provided scan findings. Under no circumstances may you invent, suggest, assume, or infer that other vulnerabilities or open ports exist.
2. If no vulnerabilities are reported, rate the security score as 100, overall risk as 'None', and confirm that the target is well-secured.
"""

        if is_incomplete:
            prompt += """3. WARNING: The provided scan data is incomplete, truncated, or partially formed. You MUST explicitly state in the 'executive_summary' that this analysis is limited due to incomplete scan data.
"""
        else:
            prompt += """3. If the provided scan data is incomplete (e.g. missing target, description, or severity), you MUST explicitly state in the 'executive_summary' that this analysis is limited due to incomplete scan data.
"""

        prompt += """
### RESPONSE SCHEMA (JSON):
Respond STRICTLY with a valid JSON object matching the following structure:
{
  "security_score": <int: score between 0 and 100 calculated based on severity of findings>,
  "overall_risk": "<string: Critical / High / Medium / Low / None>",
  "executive_summary": "<string: high-level summary of security posture. Mention limited analysis if data is incomplete>",
  "critical_findings": [
    "<string: list of key critical/high-risk findings and their implications>"
  ],
  "recommendations": [
    "<string: actionable recommendation steps>"
  ],
  "remediation_priority": [
    {
      "finding": "<string: name of finding>",
      "priority": "<string: Critical / High / Medium / Low>",
      "remediation": "<string: step-by-step resolution action>"
    }
  ]
}
"""

        # 6. Formulate Request
        model = model_name or cls.DEFAULT_MODEL
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "OBJECT",
                    "properties": {
                        "security_score": {"type": "INTEGER"},
                        "overall_risk": {
                            "type": "STRING",
                            "enum": ["Critical", "High", "Medium", "Low", "None"]
                        },
                        "executive_summary": {"type": "STRING"},
                        "critical_findings": {
                            "type": "ARRAY",
                            "items": {"type": "STRING"}
                        },
                        "recommendations": {
                            "type": "ARRAY",
                            "items": {"type": "STRING"}
                        },
                        "remediation_priority": {
                            "type": "ARRAY",
                            "items": {
                                "type": "OBJECT",
                                "properties": {
                                    "finding": {"type": "STRING"},
                                    "priority": {
                                        "type": "STRING",
                                        "enum": ["Critical", "High", "Medium", "Low"]
                                    },
                                    "remediation": {"type": "STRING"}
                                },
                                "required": ["finding", "priority", "remediation"]
                            }
                        }
                    },
                    "required": [
                        "security_score",
                        "overall_risk",
                        "executive_summary",
                        "critical_findings",
                        "recommendations",
                        "remediation_priority"
                    ]
                }
            }
        }
        
        headers = {"Content-Type": "application/json"}

        # 7. Call API with Rate-Limit & Quota Detection
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=cls.DEFAULT_TIMEOUT)
        except requests.exceptions.Timeout as e:
            raise NetworkTimeoutError(f"Connection to Gemini API timed out: {e}")
        except requests.exceptions.RequestException as e:
            raise GeminiAPIFailureError(f"Gemini API request failed: {e}")

        # Check for Quota Exhaustion (429 or RESOURCE_EXHAUSTED)
        is_quota_error = (response.status_code == 429)
        if not is_quota_error and response.status_code != 200:
            try:
                err_data = response.json()
                if err_data.get("error", {}).get("status") == "RESOURCE_EXHAUSTED":
                    is_quota_error = True
            except Exception:
                pass

        if is_quota_error:
            user_msg, retry_delay, is_daily = parse_gemini_quota_error(response)
            record_quota_cooldown(retry_delay or 30.0, is_daily=is_daily)

            # Retry once only if delay is very small (<= 2 seconds) and not a daily quota
            if retry_delay and retry_delay <= 2.0 and not is_daily:
                logger.info(f"Transient rate limit encountered. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                try:
                    response = requests.post(url, json=payload, headers=headers, timeout=cls.DEFAULT_TIMEOUT)
                    if response.status_code == 200:
                        is_quota_error = False
                except Exception:
                    pass

        if is_quota_error:
            logger.warning(f"Gemini API quota exhausted: {user_msg}")
            if fallback_on_quota:
                fallback_data = generate_heuristic_fallback(scan_results, reason=user_msg)
                return cls._validate_response(fallback_data)
            else:
                raise GeminiQuotaExceededError(user_msg, retry_delay=retry_delay, is_daily_quota=is_daily)

        # 8. Check other non-200 responses
        if response.status_code != 200:
            # Handle transient 503 with single retry
            if response.status_code == 503:
                time.sleep(0.5)
                try:
                    retry_resp = requests.post(url, json=payload, headers=headers, timeout=cls.DEFAULT_TIMEOUT)
                    if retry_resp.status_code == 200:
                        response = retry_resp
                except Exception:
                    pass

        if response.status_code != 200:
            raise GeminiAPIFailureError(
                f"Gemini API request failed with status code {response.status_code}"
            )

        # 9. Extract and parse response payload
        try:
            resp_data = response.json()
        except Exception as e:
            raise GeminiAPIFailureError(f"Failed to parse Gemini API response as JSON: {e}")

        try:
            candidates = resp_data.get('candidates', [])
            if not candidates:
                raise GeminiAPIFailureError("Gemini API response did not return any candidates.")
            parts = candidates[0].get('content', {}).get('parts', [])
            if not parts:
                raise GeminiAPIFailureError("Gemini API response content has no parts.")
            raw_text = parts[0].get('text', '').strip()
        except Exception as e:
            raise GeminiAPIFailureError(f"Error parsing Gemini API candidates/parts: {e}")

        # 10. Clean markdown wrappers and validate
        try:
            if raw_text.startswith("```json"):
                raw_text = raw_text.split("```json", 1)[1]
                if raw_text.endswith("```"):
                    raw_text = raw_text.rsplit("```", 1)[0]
                raw_text = raw_text.strip()
            elif raw_text.startswith("```"):
                raw_text = raw_text.split("```", 1)[1]
                if raw_text.endswith("```"):
                    raw_text = raw_text.rsplit("```", 1)[0]
                raw_text = raw_text.strip()
            
            parsed_data = json.loads(raw_text)
        except json.JSONDecodeError as e:
            raise InvalidJSONResponseError(f"Model response was not valid JSON: {e}. Raw content: {raw_text}")

        validated = cls._validate_response(parsed_data, scan_results=scan_results)
        validated["_model_used"] = model
        validated["_fallback"] = False

        # Store in cache
        _set_cached_analysis(cache_key, validated)

        return validated
