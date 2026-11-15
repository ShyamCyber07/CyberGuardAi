import os
import json
import time
import hashlib
import requests
from typing import Dict, Any, Optional
from app.models.scan import Scan
from app.models.network_scan import NetworkScan
from app.services.ai_service import (
    MissingAPIKeyError,
    NetworkTimeoutError,
    GeminiAPIFailureError,
    AIServiceError,
    GeminiQuotaExceededError,
    get_quota_cooldown_remaining,
    record_quota_cooldown,
    parse_gemini_quota_error
)

class AIAssistantServiceError(AIServiceError):
    """Exception for errors inside the AI Assistant Service."""
    pass

class ScanNotFoundError(AIAssistantServiceError):
    """Raised when the specified scan cannot be found."""
    pass

class UnauthorizedScanAccessError(AIAssistantServiceError):
    """Raised when the user tries to access a scan they do not own."""
    pass


# Question & Answer Cache with User Isolation
_assistant_cache: Dict[str, tuple[float, str]] = {}
ASSISTANT_CACHE_TTL = 300  # 5 minutes


def _get_assistant_cache(user_id: int, scan_uuid: str, question: str) -> Optional[str]:
    now = time.time()
    key = f"{user_id}:{scan_uuid}:{hashlib.sha256(question.strip().lower().encode('utf-8')).hexdigest()}"
    entry = _assistant_cache.get(key)
    if entry:
        ts, answer = entry
        if now - ts < ASSISTANT_CACHE_TTL:
            return answer
        else:
            _assistant_cache.pop(key, None)
    return None


def _set_assistant_cache(user_id: int, scan_uuid: str, question: str, answer: str) -> None:
    now = time.time()
    key = f"{user_id}:{scan_uuid}:{hashlib.sha256(question.strip().lower().encode('utf-8')).hexdigest()}"
    if len(_assistant_cache) > 200:
        oldest = min(_assistant_cache.keys(), key=lambda k: _assistant_cache[k][0])
        _assistant_cache.pop(oldest, None)
    _assistant_cache[key] = (now, answer)


def clear_assistant_cache() -> None:
    """Clear in-memory assistant question cache (useful in tests)."""
    global _assistant_cache
    _assistant_cache.clear()


class AIAssistantService:
    """Service to handle context-aware Q&A based strictly on scanner data and saved AIResponse analysis."""

    DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    DEFAULT_TIMEOUT = 10.0

    @classmethod
    def ask_question(
        cls,
        user_id: int,
        scan_type: str,
        scan_uuid: str,
        user_question: str,
        model_name: str = None
    ) -> str:
        """
        Ask contextual questions about a user's scan using scan data + stored AI response context.
        """
        # 1. Validate user_question
        if not user_question or not user_question.strip():
            raise ValueError("Question cannot be empty.")
        
        if len(user_question) > 1000:
            raise ValueError("Question is too long (maximum 1000 characters).")

        # 2. Fetch scan & verify ownership
        scan_obj = None
        if scan_type == 'website':
            scan_obj = Scan.query.filter_by(uuid=scan_uuid).first()
        elif scan_type == 'network':
            scan_obj = NetworkScan.query.filter_by(uuid=scan_uuid).first()
        else:
            raise ScanNotFoundError(f"Invalid scan type: {scan_type}")

        if not scan_obj:
            raise ScanNotFoundError(f"Scan with UUID {scan_uuid} not found.")

        if scan_obj.user_id != user_id:
            raise UnauthorizedScanAccessError("Unauthorized access to this scan.")

        if scan_obj.status == 'inconclusive':
            raise ValueError("AI Assistant is unavailable for inconclusive scans. Please re-run the scan.")

        # 3. Check question cache to prevent duplicate calls
        cached_answer = _get_assistant_cache(user_id, scan_uuid, user_question)
        if cached_answer:
            return cached_answer

        # 4. Check active quota cooldown window
        cooldown = get_quota_cooldown_remaining()
        if cooldown > 0:
            delay_int = int(round(cooldown))
            raise GeminiQuotaExceededError(
                f"Gemini API request quota temporarily exhausted. Please retry in approximately {delay_int} seconds.",
                retry_delay=cooldown
            )

        # 5. Gather scan context
        is_network = (scan_type == 'network')
        target = scan_obj.ip_address if is_network else scan_obj.target_destination
        scan_type_str = "Network Scan" if is_network else "Website Scan"
        
        if is_network:
            score_info = f"Risk Level: {scan_obj.risk_level}"
        else:
            score_info = f"Security Score: {scan_obj.security_score}/100"

        # Stored AI analysis
        stored_ai_summary = "No previous AI analysis report exists for this scan."
        if scan_obj.ai_response:
            try:
                ai_dict = json.loads(scan_obj.ai_response.response_text)
                if isinstance(ai_dict, dict):
                    from app.services.ai_service import sanitize_ai_data
                    if is_network:
                        score_map = {'Low': 90, 'Medium': 70, 'High': 40, 'Critical': 20}
                        net_score = 100 if not getattr(scan_obj, 'results', None) else score_map.get(scan_obj.risk_level, 70)
                        n_ports = len(scan_obj.results) if getattr(scan_obj, 'results', None) else 0
                        ai_dict = sanitize_ai_data(
                            ai_dict,
                            authoritative_score=net_score,
                            authoritative_risk=scan_obj.risk_level,
                            scan_type='network',
                            findings=scan_obj.results,
                            n_ports=n_ports,
                            is_cached_read=True
                        )
                    else:
                        auth_score = scan_obj.security_score if scan_obj.security_score is not None else 100
                        auth_risk = getattr(scan_obj, 'authoritative_risk', None) or getattr(scan_obj, 'risk_level', None)
                        ai_dict = sanitize_ai_data(
                            ai_dict,
                            authoritative_score=auth_score,
                            authoritative_risk=auth_risk,
                            scan_type='website',
                            findings=scan_obj.results,
                            is_cached_read=True
                        )
                stored_ai_summary = (
                    f"Overall Risk: {ai_dict.get('overall_risk')}\n"
                    f"Executive Summary: {ai_dict.get('executive_summary')}\n"
                    f"Critical Findings: {', '.join(ai_dict.get('critical_findings', []))}\n"
                    f"Recommendations: {', '.join(ai_dict.get('recommendations', []))}"
                )
            except Exception:
                pass

        # Discovered Findings Telemetry
        findings_list = []
        if is_network:
            for r in scan_obj.results:
                version = r.service_version if r.service_version else 'Unknown'
                findings_list.append(
                    f"- Port: {r.port}/{r.protocol} | Service: {r.service_name} (Version: {version}) | Risk Severity: {r.severity} | Remediation: {r.remediation}"
                )
        else:
            for r in scan_obj.results:
                findings_list.append(
                    f"- Finding: {r.vulnerability_name} | Severity: {r.severity} | Remediation: {r.remediation}"
                )

        findings_details = "\n".join(findings_list) if findings_list else "No vulnerabilities or open ports discovered."

        # 6. Formulate prompt
        prompt = f"""You are analyzing a CyberGuard AI security assessment.
Your goal is to answer the user's question about the security scan results using ONLY the supplied scan information.

### STRICT COMPLIANCE RULES:
1. Do not invent facts, open ports, services, vulnerabilities, SSL issues, security headers, or CVEs.
2. Use only the supplied scan results, stored AI response analysis, and metadata.
3. Do not claim that an open port is automatically a vulnerability, or that exploitation occurred, unless explicitly found in the scan details.
4. Do not pretend you performed the scan. The scan was performed by the CyberGuard AI scanner.
5. If the user's question cannot be answered using the provided scan data and analysis, or if the user asks something outside the scope of this scan, you must respond EXACTLY with:
"The available scan data does not provide enough information to determine this."

### SECURITY ASSESSMENT CONTEXT:
- Scan Target: {target}
- Scan Type: {scan_type_str}
- Scanner Rating / Risk level: {score_info}
- Stored AI Analysis:
{stored_ai_summary}

### DETECTED FINDINGS:
{findings_details}

### USER QUESTION:
{user_question}

Answer:"""

        # 7. Call API
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise MissingAPIKeyError("The GEMINI_API_KEY environment variable is not set.")

        model = model_name or cls.DEFAULT_MODEL
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ]
        }
        headers = {"Content-Type": "application/json"}

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

            # Retry once if delay is very small (<= 2 seconds)
            if retry_delay and retry_delay <= 2.0 and not is_daily:
                time.sleep(retry_delay)
                try:
                    response = requests.post(url, json=payload, headers=headers, timeout=cls.DEFAULT_TIMEOUT)
                    if response.status_code == 200:
                        is_quota_error = False
                except Exception:
                    pass

        if is_quota_error:
            raise GeminiQuotaExceededError(user_msg, retry_delay=retry_delay, is_daily_quota=is_daily)

        if response.status_code != 200:
            raise GeminiAPIFailureError(
                f"Gemini API returned status code {response.status_code}"
            )

        try:
            resp_data = response.json()
            candidates = resp_data.get('candidates', [])
            if not candidates:
                raise GeminiAPIFailureError("Gemini API response did not return any candidates.")
            parts = candidates[0].get('content', {}).get('parts', [])
            if not parts:
                raise GeminiAPIFailureError("Gemini API response content has no parts.")
            answer_text = parts[0].get('text', '').strip()

            from app.services.ai_service import validate_ai_text
            if is_network:
                score_map = {'Low': 90, 'Medium': 70, 'High': 40, 'Critical': 20}
                net_score = 100 if not scan_obj.results else score_map.get(scan_obj.risk_level, 70)
                n_ports = len(scan_obj.results) if getattr(scan_obj, 'results', None) else 0
                answer_text = validate_ai_text(
                    answer_text,
                    authoritative_score=net_score,
                    authoritative_risk=scan_obj.risk_level,
                    scan_type='network',
                    findings=scan_obj.results,
                    n_ports=n_ports,
                    is_cached_read=True
                )
            else:
                auth_score = scan_obj.security_score if scan_obj.security_score is not None else 100
                auth_risk = getattr(scan_obj, 'authoritative_risk', None) or getattr(scan_obj, 'risk_level', None)
                answer_text = validate_ai_text(
                    answer_text,
                    authoritative_score=auth_score,
                    authoritative_risk=auth_risk,
                    scan_type='website',
                    findings=scan_obj.results,
                    is_cached_read=True
                )

            # Cache answer
            _set_assistant_cache(user_id, scan_uuid, user_question, answer_text)
            return answer_text
        except Exception as e:
            if isinstance(e, AIServiceError):
                raise
            raise GeminiAPIFailureError(f"Error parsing Gemini API response: {e}")
