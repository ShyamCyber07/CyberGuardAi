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


BANNED_NETWORK_PATTERNS = (
    re.compile(r'\bno\s+(?:critical|high|significant|known)\b', re.IGNORECASE),
    re.compile(r'\bno\s+(?:vulnerabilit\w*|issues?)\b', re.IGNORECASE),
    re.compile(r'\b(?:clean\s+bill|clean\s+scan|is\s+clean)\b', re.IGNORECASE),
    re.compile(r'\brisk\s+posture\b', re.IGNORECASE),
    re.compile(r'\b(?:is|are|remains?|appears?)\s+(?:secure|safe)\b', re.IGNORECASE),
    re.compile(r'\b(?:vulnerabilit\w*)\s+(?:were|was)\s+(?:identified|detected|found)\b', re.IGNORECASE),
)

BANNED_NETWORK_PHRASES = (
    "no critical",
    "no high",
    "no vulnerabilities",
    "no issues",
    "clean bill",
    "clean scan",
    "is clean",
    "risk posture",
    "is secure",
    "is safe",
    "vulnerabilities were identified",
)

RATING_WORDS = {'low', 'medium', 'high', 'critical', 'none'}

UNITS = {'zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'}
TEENS = {'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen'}
TENS = {'twenty', 'thirty', 'forty', 'fifty', 'sixty', 'seventy', 'eighty', 'ninety'}
SCALE = {'hundred'}

SPELLED_NUMBERS = set()
SPELLED_NUMBERS.update(UNITS)
SPELLED_NUMBERS.update(TEENS)
SPELLED_NUMBERS.update(TENS)
SPELLED_NUMBERS.update(SCALE)
for t in TENS:
    for u in UNITS:
        if u != 'zero':
            SPELLED_NUMBERS.add(f'{t}-{u}')
            SPELLED_NUMBERS.add(f'{t} {u}')

TARGET_KEYWORDS = {
    'score', 'scores', 'rating', 'ratings', 'rated', 'rate',
    'risk', 'risks', 'posture', 'postures', 'level', 'levels',
    'severity', 'severities', 'band', 'bands', 'tier', 'tiers'
}

EXPLOIT_ATTACK_PATTERNS = (
    re.compile(r'\bno\s+active\s+exploits?\b', re.IGNORECASE),
    re.compile(r'\bexploits?\s+(?:were|was|are|is)?\s*(?:detected|identified|found|observed|seen)\b', re.IGNORECASE),
    re.compile(r'\b(?:detected|identified|found|observed|seen)\s+(?:any\s+|active\s+)?exploits?\b', re.IGNORECASE),
    re.compile(r'\bno\s+evidence\s+of\b', re.IGNORECASE),
    re.compile(r'\b(?:was|were|is|are|remains?|been|not)\s+(?:not\s+)?exploited\b', re.IGNORECASE),
    re.compile(r'\bnot\s+exploited\b', re.IGNORECASE),
    re.compile(r'\bno\s+signs?\s+of\b', re.IGNORECASE),
    re.compile(r'\bno\s+(?:known\s+|active\s+)?exploits?\b', re.IGNORECASE),
    re.compile(r'\bno\s+(?:active\s+)?attacks?\s+(?:were|was|are|is)?\s*(?:detected|identified|found|observed)\b', re.IGNORECASE),
    re.compile(r'\battacks?\s+(?:were|was|are|is)?\s*(?:detected|identified|found|observed)\b', re.IGNORECASE),
    re.compile(r'\bno\s+(?:indication|evidence|signs?)\s+of\s+(?:malicious\s+|active\s+)?(?:compromise|exploitation|attacks?|exploits?)\b', re.IGNORECASE),
)


def get_short_failure_reason(error: Any) -> str:
    """
    Extract a concise, standardized failure reason for fallback labeling:
    'Rule-based analysis (live AI unavailable: <short reason>)'
    Handles: timeout, connection error, HTTP 5xx, HTTP 429, invalid JSON, validation error, etc.
    """
    if isinstance(error, int):
        return f"HTTP {error}"
    err_str = str(error) if error else "unknown error"
    err_lower = err_str.lower()

    # 1. HTTP 429 / Quota
    if "429" in err_str or "quota" in err_lower or "resource_exhausted" in err_lower or isinstance(error, GeminiQuotaExceededError):
        return "HTTP 429"

    # 2. Timeout
    if isinstance(error, NetworkTimeoutError) or "timeout" in err_lower or "timed out" in err_lower:
        return "timeout"

    # 3. HTTP 5xx
    status_match = re.search(r'\b(?:status\s*(?:code\s*)?|HTTP\s*)(5\d{2})\b', err_str, re.IGNORECASE)
    if status_match:
        return f"HTTP {status_match.group(1)}"
    for code in ("500", "502", "503", "504"):
        if code in err_str:
            return f"HTTP {code}"

    # 4. Connection error
    if isinstance(error, requests.exceptions.ConnectionError) or "connection" in err_lower or "connect" in err_lower or "network down" in err_lower:
        return "connection error"

    # 5. Schema validation error vs unparseable/invalid JSON
    if isinstance(error, InvalidJSONResponseError) or "json" in err_lower or "schema" in err_lower or "validation" in err_lower:
        if any(k in err_lower for k in ("missing required key", "invalid type", "schema", "validation", "overall_risk", "missing_keys")):
            return "validation error"
        return "invalid JSON"

    if isinstance(error, MissingAPIKeyError) or "api key" in err_lower:
        return "missing API key"

    return "generation failure"


def is_restricting_web_ports(text: str) -> bool:
    """Check if recommendation advises restricting, blocking, closing, or firewalling port 80 or 443."""
    if not text or not isinstance(text, str):
        return False
    has_web_port = bool(re.search(r'\b(?:port\s*)?(?:80|443)\b', text, re.IGNORECASE))
    if not has_web_port:
        return False
    has_action = bool(re.search(r'\b(?:restrict|block|close|firewall|shut\s*down|disable)\b', text, re.IGNORECASE))
    return has_action


def is_ai_sentence_blocked(sentence: str) -> Tuple[bool, str]:
    """
    Sentence-level check:
    DROP any sentence that has:
    (a) a rating word (low|medium|high|critical|none, also spelled-out numbers like 'fifty-five')
        or a number from 0 to 100 within 8 words of (score|rating|risk|posture|level|severity|band|tier), or
    (b) a claim about exploits or attacks being absent or detected ('no active exploits',
        'exploits were detected', 'no evidence of', 'not exploited', 'no signs of').
    Ordinary uses ('a critical finding', 'high-severity header') that are not tied to a score or overall rating survive.
    """
    if not sentence or not isinstance(sentence, str):
        return False, ""

    s = sentence.strip()
    if not s:
        return False, ""

    # 0. Authoritative / deterministic system sentences are never blocked
    if (
        "is a rule-based rating of the observed ports; this scan did not test for vulnerabilities" in s
        or "open ports were observed; this scan did not test for vulnerabilities" in s
        or s.startswith("Security Score:")
        or s.startswith("Mode: Rule-based analysis")
        or s.startswith("[Rule-based analysis")
    ):
        return False, ""

    # Criteria (b): Claims about exploits or attacks being absent or detected
    for pat in EXPLOIT_ATTACK_PATTERNS:
        m = pat.search(s)
        if m:
            return True, f"exploit/attack claim '{m.group(0)}'"

    # Criteria (a): Rating word or number within 8 words of target keywords
    raw_tokens = re.findall(r'[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*', s)
    tokens = [t.lower() for t in raw_tokens]

    rating_or_number_indices = []
    target_keyword_indices = []

    for idx, tok in enumerate(tokens):
        if tok in RATING_WORDS:
            rating_or_number_indices.append((idx, tok, "rating_word"))
            continue
        if tok in SPELLED_NUMBERS:
            rating_or_number_indices.append((idx, tok, "spelled_number"))
            continue
        clean_num = tok.split("/")[0]
        if clean_num.isdigit():
            val = int(clean_num)
            if 0 <= val <= 100:
                rating_or_number_indices.append((idx, tok, "number_0_100"))
                continue

    for idx, tok in enumerate(tokens):
        base_tok = tok
        if base_tok.endswith("s") and len(base_tok) > 4 and base_tok[:-1] in TARGET_KEYWORDS:
            base_tok = base_tok[:-1]
        if base_tok in TARGET_KEYWORDS or tok in TARGET_KEYWORDS:
            target_keyword_indices.append((idx, tok))

    blocked_by_pair = False
    pair_reason = ""
    for r_idx, r_tok, r_type in rating_or_number_indices:
        for t_idx, t_tok in target_keyword_indices:
            dist = abs(r_idx - t_idx)
            if dist <= 8:
                # Ordinary use exception:
                # E.g. "high-severity header", "medium-severity finding", "critical-severity issue"
                is_ordinary_severity = False
                if r_tok in ("high", "medium", "low", "critical") and t_tok in ("severity", "severities"):
                    ordinary_match = re.search(
                        r'\b(?:a|an|the|is|as|this)?\s*' + re.escape(r_tok) + r'[-\s]severity\s+(?:header|finding|vulnerability|issue|misconfiguration|directive|flaw|item|check|alert|warning)\b',
                        s,
                        re.IGNORECASE
                    )
                    if ordinary_match:
                        other_targets = [
                            (i, tok) for i, tok in target_keyword_indices
                            if tok not in ("severity", "severities")
                        ]
                        other_scores = [
                            (i, tok, typ) for i, tok, typ in rating_or_number_indices
                            if typ in ("number_0_100", "spelled_number") or (typ == "rating_word" and tok != r_tok)
                        ]
                        if not other_targets and not other_scores:
                            is_ordinary_severity = True

                if not is_ordinary_severity:
                    blocked_by_pair = True
                    pair_reason = f"rating/number '{r_tok}' within {dist} words of '{t_tok}'"
                    break
        if blocked_by_pair:
            break

    if blocked_by_pair:
        return True, pair_reason

    return False, ""


def check_ai_text_blocked(
    text: str,
    authoritative_score: Optional[int] = None,
    authoritative_risk: Optional[str] = None,
    scan_type: str = "website"
) -> Tuple[bool, str]:
    """
    Checks if a given AI text block is blocked due to banned assurance phrases,
    banned score/rating claims, or exploit/attack claims.
    Returns (is_blocked, reason).
    """
    if not text or not isinstance(text, str):
        return False, ""

    stype = (scan_type or "").strip().lower()

    # 1. Banned network patterns (only for network scans)
    if stype == "network":
        for pat in BANNED_NETWORK_PATTERNS:
            m = pat.search(text)
            if m:
                return True, f"banned network assurance claim '{m.group(0)}'"

    # 2. Sentence-level check
    raw_sentences = re.split(r'(?<=[.!?])\s+|\r?\n+', text)
    for s in raw_sentences:
        s_clean = s.strip()
        if not s_clean:
            continue
        blocked, reason = is_ai_sentence_blocked(s_clean)
        if blocked:
            return True, reason

    return False, ""


def find_original_remediation(item: Dict[str, Any], findings: Optional[Any], scan_type: str = "website") -> str:
    """
    Find the original rule-based remediation text for a given port or finding.
    Used when an AI action step is blocked, replacing it with authoritative rule-based guidance.
    """
    stype = (scan_type or "").strip().lower()
    finding_name = str(item.get("finding", "") if isinstance(item, dict) else item)

    # 1. Look for port number in finding_name
    port_num = None
    m = re.search(r'\b(?:port\s*)?(\d{1,5})\b', finding_name, re.IGNORECASE)
    if m:
        try:
            port_num = int(m.group(1))
        except ValueError:
            pass

    # 2. Check findings collection
    if findings:
        for f in findings:
            if stype == "network" and port_num is not None:
                f_port = getattr(f, "port", None) if hasattr(f, "port") else (f.get("port") if isinstance(f, dict) else None)
                if f_port is not None:
                    try:
                        if int(f_port) == port_num:
                            rem = getattr(f, "remediation", None) if hasattr(f, "remediation") else (f.get("remediation") if isinstance(f, dict) else None)
                            if rem:
                                return rem
                    except (ValueError, TypeError):
                        pass

            f_name = ""
            if hasattr(f, "vulnerability_name") and f.vulnerability_name:
                f_name = f.vulnerability_name
            elif hasattr(f, "service_name") and f.service_name:
                f_name = f.service_name
            elif isinstance(f, dict):
                f_name = f.get("name") or f.get("vulnerability_name") or f.get("service_name") or ""

            if f_name and (f_name.lower() in finding_name.lower() or finding_name.lower() in f_name.lower()):
                rem = getattr(f, "remediation", None) if hasattr(f, "remediation") else (f.get("remediation") if isinstance(f, dict) else None)
                if rem:
                    return rem

    # 3. Known standard rule-based fallbacks
    if stype == "network":
        if port_num == 80:
            return "Ensure HTTP traffic redirects automatically to secure HTTPS configurations."
        elif port_num == 443:
            return "Monitor SSL configurations and TLS handshake setups periodically."
        elif port_num == 22:
            return "Restrict SSH source IP addresses using firewalls and disable password logins."
        elif port_num == 3389:
            return "Disable public facing RDP listeners. Force VPN usage to access Remote Desktop."
        elif port_num in (8080, 8443):
            return "Disable public access to admin ports and use SSL/TLS."
        return "Restrict access to trusted hosts using local firewall configurations."
    else:
        return "Implement standard defensive controls and recommended security headers."


def get_deterministic_sentence(
    authoritative_score: Optional[int] = None,
    authoritative_risk: Optional[str] = None,
    scan_type: str = "website",
    findings: Optional[Any] = None,
    n_ports: Optional[int] = None,
    is_summary: bool = False
) -> str:
    """Build the single authoritative deterministic sentence for network or website scans."""
    stype = (scan_type or "").strip().lower()
    auth_risk_str = (str(authoritative_risk) if authoritative_risk is not None else "").strip()
    auth_risk_norm = auth_risk_str.upper()

    if stype == "network":
        n_p = n_ports
        if n_p is None:
            n_p = len(findings) if findings is not None else 0
        risk_str = auth_risk_norm or "LOW"
        if is_summary:
            return (
                f"{n_p} open ports were observed. The {risk_str} exposure level is a "
                f"rule-based rating of the observed ports; this scan did not test for vulnerabilities."
            )
        else:
            return (
                f"{n_p} open ports were observed; this scan did not test for vulnerabilities."
            )
    else:
        auth_score = int(authoritative_score) if authoritative_score is not None else 100
        auth_risk = auth_risk_norm or "LOW"
        missing_items = []
        if findings:
            for f in findings:
                if isinstance(f, dict):
                    raw_name = f.get("name") or f.get("vulnerability_name") or ""
                elif hasattr(f, "vulnerability_name"):
                    raw_name = f.vulnerability_name or ""
                elif isinstance(f, str):
                    raw_name = f
                else:
                    raw_name = str(f)

                clean_name = re.sub(r'^(?:Missing\s+)', '', raw_name, flags=re.IGNORECASE)
                clean_name = re.sub(r'\s+Header$', '', clean_name, flags=re.IGNORECASE).strip()
                if clean_name and clean_name not in missing_items:
                    missing_items.append(clean_name)

        if missing_items:
            items_str = ", ".join(missing_items[:5])
            return f"Security Score: {auth_score}/100, Risk Level: {auth_risk}. Missing headers: {items_str}."
        else:
            return f"Security Score: {auth_score}/100, Risk Level: {auth_risk}."


def filter_ai_text_sentences(
    text: str,
    authoritative_score: Optional[int] = None,
    authoritative_risk: Optional[str] = None,
    scan_type: str = "website",
    findings: Optional[Any] = None,
    n_ports: Optional[int] = None,
    is_summary: bool = False,
    is_cached_read: bool = False
) -> str:
    """
    Sentence-level filter on every AI text block:
    Splits into sentences and drops any sentence that has:
    (a) a rating word (low|medium|high|critical|none, also spelled-out numbers like 'fifty-five')
        or a number from 0 to 100 within 8 words of (score|rating|risk|posture|level|severity|band|tier), or
    (b) a claim about exploits or attacks being absent or detected ('no active exploits', 'exploits were detected',
        'no evidence of', 'not exploited', 'no signs of').
    Ordinary uses ('a critical finding', 'high-severity header') that are not tied to a score or overall rating survive.
    If dropping sentences empties a block, returns the deterministic sentence once.
    Logs at DEBUG when is_cached_read=True, else at WARNING.
    """
    if not text or not isinstance(text, str):
        return text or ""

    stype = (scan_type or "").strip().lower()
    log_fn = logger.debug if is_cached_read else logger.warning

    raw_sentences = re.split(r'(?<=[.!?])\s+|\r?\n+', text)
    surviving = []
    dropped_count = 0

    for s in raw_sentences:
        s_clean = s.strip()
        if not s_clean:
            continue
        blocked, reason = is_ai_sentence_blocked(s_clean)
        if not blocked and stype == "network":
            for pat in BANNED_NETWORK_PATTERNS:
                m = pat.search(s_clean)
                if m:
                    blocked = True
                    reason = f"banned network assurance claim '{m.group(0)}'"
                    break

        if blocked:
            dropped_count += 1
            log_fn(f"Dropped AI sentence due to {reason}")
        else:
            surviving.append(s_clean)

    if surviving:
        return " ".join(surviving)

    log_fn("All sentences in AI text block dropped; replacing with authoritative deterministic sentence.")
    return get_deterministic_sentence(
        authoritative_score=authoritative_score,
        authoritative_risk=authoritative_risk,
        scan_type=stype,
        findings=findings,
        n_ports=n_ports,
        is_summary=is_summary
    )


def validate_ai_text(
    text: str,
    authoritative_score: Optional[int] = None,
    authoritative_risk: Optional[str] = None,
    scan_type: str = "website",
    findings: Optional[Any] = None,
    n_ports: Optional[int] = None,
    is_summary: bool = False,
    is_cached_read: bool = False
) -> str:
    """
    Validates AI free text using sentence-level filtering to ensure it cannot state scores or ratings.
    """
    return filter_ai_text_sentences(
        text,
        authoritative_score=authoritative_score,
        authoritative_risk=authoritative_risk,
        scan_type=scan_type,
        findings=findings,
        n_ports=n_ports,
        is_summary=is_summary,
        is_cached_read=is_cached_read
    )


def sanitize_ai_data(
    ai_data: Dict[str, Any],
    authoritative_score: Optional[int],
    authoritative_risk: Optional[str],
    scan_type: str,
    findings: Optional[Any] = None,
    n_ports: Optional[int] = None,
    is_cached_read: bool = False
) -> Dict[str, Any]:
    """
    Sanitize all text fields in an AI response dict to ensure zero contradictions with authoritative results.
    - Sentence-level filtering drops any sentences asserting scores, ratings, or exploit claims.
    - Dropped blocked list items in critical_findings and recommendations.
    - If critical_findings becomes empty, show the deterministic sentence once.
    - NEVER put the deterministic sentence into a recommendation or action-step slot.
    - For remediation action steps, blocked AI text is replaced by the original rule-based text for that port.
    - Guarantees the deterministic sentence appears at most once per report section.
    - Logs at DEBUG when is_cached_read=True, else at WARNING.
    """
    if not isinstance(ai_data, dict):
        return ai_data

    stype = (scan_type or "").strip().lower()
    log_fn = logger.debug if is_cached_read else logger.warning

    if authoritative_score is not None:
        ai_data["security_score"] = int(authoritative_score)
    if authoritative_risk is not None:
        ai_data["overall_risk"] = str(authoritative_risk).capitalize()

    if stype == "network" and n_ports is None:
        n_ports = len(findings) if findings is not None else 0

    # 1. Executive Summary
    if "executive_summary" in ai_data and isinstance(ai_data["executive_summary"], str):
        ai_data["executive_summary"] = validate_ai_text(
            ai_data["executive_summary"],
            authoritative_score=authoritative_score,
            authoritative_risk=authoritative_risk,
            scan_type=stype,
            findings=findings,
            n_ports=n_ports,
            is_summary=True,
            is_cached_read=is_cached_read
        )

    # 2. Critical Findings Implications
    if "critical_findings" in ai_data and isinstance(ai_data["critical_findings"], list):
        sanitized_crit = []
        for cf in ai_data["critical_findings"]:
            if isinstance(cf, str):
                filtered_cf = filter_ai_text_sentences(
                    cf,
                    authoritative_score=authoritative_score,
                    authoritative_risk=authoritative_risk,
                    scan_type=stype,
                    findings=findings,
                    n_ports=n_ports,
                    is_summary=False,
                    is_cached_read=is_cached_read
                )
                blocked, reason = check_ai_text_blocked(
                    cf,
                    authoritative_score=authoritative_score,
                    authoritative_risk=authoritative_risk,
                    scan_type=stype
                )
                if blocked and (filtered_cf.startswith("Security Score:") or "this scan did not test for vulnerabilities" in filtered_cf):
                    log_fn(f"Dropping critical finding item due to {reason}")
                    continue
                sanitized_crit.append(filtered_cf)
        if not sanitized_crit:
            # Whole list became empty -> show the deterministic sentence once
            if stype == "network":
                n_p = n_ports if n_ports is not None else (len(findings) if findings is not None else 0)
                sanitized_crit.append(f"{n_p} open ports were observed; this scan did not test for vulnerabilities.")
            else:
                auth_score = int(authoritative_score) if authoritative_score is not None else 100
                auth_risk = (str(authoritative_risk) if authoritative_risk is not None else "LOW").upper()
                sanitized_crit.append(f"Security Score: {auth_score}/100, Risk Level: {auth_risk}.")
        ai_data["critical_findings"] = sanitized_crit

    # 3. Recommendations
    if "recommendations" in ai_data and isinstance(ai_data["recommendations"], list):
        sanitized_recs = []
        for rec in ai_data["recommendations"]:
            if isinstance(rec, str):
                if stype == "network" and is_restricting_web_ports(rec):
                    log_fn("Dropped network recommendation that advises restricting, blocking or closing ports 80/443")
                    continue
                blocked, reason = check_ai_text_blocked(
                    rec,
                    authoritative_score=authoritative_score,
                    authoritative_risk=authoritative_risk,
                    scan_type=stype
                )
                if blocked:
                    log_fn(f"Dropping recommendation item due to {reason}")
                    continue
                # Explicit rule: NEVER put the deterministic sentence into a recommendation slot
                if "did not test for vulnerabilities" in rec or "Security Score:" in rec:
                    log_fn("Dropped deterministic sentence placeholder found in recommendation slot")
                    continue
                filtered_rec = filter_ai_text_sentences(
                    rec,
                    authoritative_score=authoritative_score,
                    authoritative_risk=authoritative_risk,
                    scan_type=stype,
                    findings=findings,
                    n_ports=n_ports,
                    is_summary=False,
                    is_cached_read=is_cached_read
                )
                if "did not test for vulnerabilities" in filtered_rec or "Security Score:" in filtered_rec:
                    continue
                sanitized_recs.append(filtered_rec)
        if not sanitized_recs:
            if stype == "network":
                sanitized_recs.append("Verify that each observed exposure is intended for this host's role.")
            else:
                sanitized_recs.append("Apply standard defensive hardening and implement recommended security headers.")
        ai_data["recommendations"] = sanitized_recs

    # 4. Remediation Priority
    if "remediation_priority" in ai_data and isinstance(ai_data["remediation_priority"], list):
        sanitized_prio = []
        for item in ai_data["remediation_priority"]:
            if isinstance(item, dict):
                finding_str = item.get("finding", "")
                rem_str = item.get("remediation", "")

                # If finding itself is blocked, drop the item
                f_blocked, f_reason = check_ai_text_blocked(
                    finding_str,
                    authoritative_score=authoritative_score,
                    authoritative_risk=authoritative_risk,
                    scan_type=stype
                )
                if f_blocked:
                    log_fn(f"Dropping remediation priority item due to blocked finding ({f_reason})")
                    continue

                # Check if remediation action step is blocked, advises restricting web ports, or contains placeholder
                rem_blocked = False
                if stype == "network" and is_restricting_web_ports(rem_str):
                    log_fn("Network remediation step advising restriction of ports 80/443 replaced with original text")
                    rem_blocked = True
                else:
                    b, r_reason = check_ai_text_blocked(
                        rem_str,
                        authoritative_score=authoritative_score,
                        authoritative_risk=authoritative_risk,
                        scan_type=stype
                    )
                    if b or "did not test for vulnerabilities" in rem_str or "Security Score:" in rem_str:
                        log_fn(f"Remediation step replaced with original text due to: {r_reason or 'placeholder found'}")
                        rem_blocked = True

                if rem_blocked:
                    # For remediation action steps, a blocked AI text is replaced by the original rule-based text for that port
                    orig_rem = find_original_remediation(item, findings, scan_type=stype)
                    item["remediation"] = orig_rem
                else:
                    item["remediation"] = filter_ai_text_sentences(
                        rem_str,
                        authoritative_score=authoritative_score,
                        authoritative_risk=authoritative_risk,
                        scan_type=stype,
                        findings=findings,
                        n_ports=n_ports,
                        is_summary=False,
                        is_cached_read=is_cached_read
                    )

                sanitized_prio.append(item)

        ai_data["remediation_priority"] = sanitized_prio

    return ai_data


def filter_network_executive_summary(summary: str, n_ports: int, risk_level: str = "Low") -> str:
    """Backward compatibility alias for validating network executive summary text."""
    return validate_ai_text(
        summary,
        authoritative_score=None,
        authoritative_risk=risk_level,
        scan_type="network",
        n_ports=n_ports,
        is_summary=True
    )


def generate_heuristic_fallback(scan_results: Dict[str, Any], reason: str = "Quota limit reached") -> Dict[str, Any]:
    """
    Generate an offline rule-based heuristic assessment matching the standard AI response schema.
    Clearly tags the result with executive summary labeling and model_used='rule-based-fallback'.
    Label format: 'Rule-based analysis (live AI unavailable: <short reason>)'
    """
    if not isinstance(scan_results, dict):
        scan_results = {}

    short_reason = get_short_failure_reason(reason) if reason else "live AI unavailable"
    fallback_label = f"Rule-based analysis (live AI unavailable: {short_reason})"

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
    is_network = (scan_results.get("scan_type") == "network")

    if not findings:
        if is_network:
            overall_risk = str(scan_results.get("overall_risk") or "Low").capitalize()
            critical_findings = []
            recommendations = [
                "The role of the host is unknown. Do not recommend restricting, closing or firewalling ports. Recommend verifying that each observed exposure is intended."
            ]
            remediation_priority = []
            summary = (
                f"[{fallback_label}] [Rule-Based Fallback Analysis] Live Gemini AI analysis is currently unavailable ({reason}). "
                "0 open ports were observed; this scan did not test for vulnerabilities. The LOW exposure level is a "
                "rule-based rating of the observed ports; this scan did not test for vulnerabilities."
            )
        else:
            overall_risk = "None"
            critical_findings = []
            recommendations = ["Target configuration returned no critical observations. Continue routine monitoring."]
            remediation_priority = []
            summary = (
                f"[{fallback_label}] [Rule-Based Fallback Analysis] Live Gemini AI analysis is currently unavailable ({reason}). "
                f"Automated heuristic review confirms target '{target}' has zero detected security findings."
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
        if is_network:
            recommendations.append(
                "The role of the host is unknown. Do not recommend restricting, closing or firewalling ports. Recommend verifying that each observed exposure is intended."
            )
        else:
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
                "remediation": str(f.get("remediation") or find_original_remediation(f, findings, scan_type="network" if is_network else "website"))
            })

        if is_network:
            summary = (
                f"[{fallback_label}] [Rule-Based Fallback Analysis] Live Gemini AI analysis is currently unavailable ({reason}). "
                f"{len(findings)} open ports were observed; this scan did not test for vulnerabilities. The {overall_risk.upper()} exposure level is a "
                f"rule-based rating of the observed ports; this scan did not test for vulnerabilities."
            )
        else:
            summary = (
                f"[{fallback_label}] [Rule-Based Fallback Analysis] Live Gemini AI analysis is currently unavailable ({reason}). "
                f"Security Score: {score}/100, Risk Level: {overall_risk}. "
                f"Automated heuristic assessment cataloged {len(findings)} finding(s) on target '{target}'."
            )

    # Use authoritative score and risk if supplied in scan_results
    if scan_results.get("security_score") is not None:
        score = int(scan_results["security_score"])
    if scan_results.get("overall_risk") is not None:
        overall_risk = str(scan_results["overall_risk"]).capitalize()

    fallback_payload = {
        "security_score": score,
        "overall_risk": overall_risk,
        "executive_summary": summary,
        "critical_findings": critical_findings,
        "recommendations": recommendations,
        "remediation_priority": remediation_priority,
        "fallback_label": fallback_label,
        "_fallback": True,
        "_model_used": "rule-based-fallback"
    }

    return sanitize_ai_data(
        fallback_payload,
        authoritative_score=score,
        authoritative_risk=overall_risk,
        scan_type="network" if is_network else "website",
        findings=findings,
        n_ports=len(findings) if is_network else None
    )


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
                # Scan target with no findings: AI must not invent critical findings or high risk
                if parsed_json.get("critical_findings"):
                    logger.warning("Sanitizing invented critical findings on target with no findings")
                    parsed_json["critical_findings"] = []
                if scan_results.get("scan_type") == "network":
                    if scan_results.get("overall_risk"):
                        parsed_json["overall_risk"] = str(scan_results["overall_risk"]).capitalize()
                elif parsed_json.get("overall_risk") in ("Critical", "High"):
                    logger.warning("Correcting contradictory AI overall risk on target with no findings")
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

        # Final pass: sanitize all text blocks to strictly prevent contradictions with authoritative results
        auth_score = scan_results.get("security_score") if scan_results else parsed_json.get("security_score")
        auth_risk = scan_results.get("overall_risk") if scan_results else parsed_json.get("overall_risk")
        scan_type = scan_results.get("scan_type", "website") if scan_results else "website"
        findings = scan_results.get("findings") if scan_results else None
        n_ports = len(findings) if findings and scan_type == "network" else None

        parsed_json = sanitize_ai_data(
            parsed_json,
            authoritative_score=auth_score,
            authoritative_risk=auth_risk,
            scan_type=scan_type,
            findings=findings,
            n_ports=n_ports
        )

        return parsed_json

    @classmethod
    def analyze_scan(
        cls,
        scan_results: Dict[str, Any],
        model_name: str = None,
        fallback_on_quota: bool = True,
        fallback_on_failure: bool = False,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Analyzes the given structured scan results and returns a structured JSON analysis.
        Gracefully falls back to rule-based analysis if Gemini quota is exhausted and fallback_on_quota is True,
        or on ANY generation failure if fallback_on_failure is True.
        """
        if fallback_on_failure:
            try:
                return cls._analyze_scan_internal(
                    scan_results=scan_results,
                    model_name=model_name,
                    fallback_on_quota=fallback_on_quota,
                    user_id=user_id
                )
            except MissingAPIKeyError:
                raise
            except Exception as e:
                short_reason = get_short_failure_reason(e)
                logger.warning(
                    f"Live AI analysis failed ({e}). Returning rule-based fallback labeled ({short_reason})."
                )
                fallback_data = generate_heuristic_fallback(scan_results, reason=short_reason)
                return cls._validate_response(fallback_data, scan_results=scan_results)
        else:
            return cls._analyze_scan_internal(
                scan_results=scan_results,
                model_name=model_name,
                fallback_on_quota=fallback_on_quota,
                user_id=user_id
            )

    @classmethod
    def _analyze_scan_internal(
        cls,
        scan_results: Dict[str, Any],
        model_name: str = None,
        fallback_on_quota: bool = True,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
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
        auth_score = scan_results.get("security_score") if isinstance(scan_results, dict) else None
        auth_risk = scan_results.get("overall_risk") if isinstance(scan_results, dict) else None

        score_info = f"- Authoritative Security Score: {auth_score}/100\n" if auth_score is not None else ""
        risk_info = f"- Authoritative Risk Level: {auth_risk}\n" if auth_risk is not None else ""

        prompt = f"""You are a Senior AI Engineer and Cybersecurity Architect.
Your task is to analyze the security scanner results and generate a structured risk assessment report.

### SCAN INFO
- Target: {target or 'Unknown Target'}
- Scan Type: {scan_type or 'Unknown Scan Type'}
{score_info}{risk_info}
### SCAN FINDINGS
"""
        if scan_type == "network":
            n_ports = len(findings)
            prompt += f"{n_ports} open ports were observed; this scan did not test for vulnerabilities.\n\n"
            if findings:
                for idx, finding in enumerate(findings, start=1):
                    if isinstance(finding, dict):
                        prompt += f"Finding #{idx}:\n"
                        prompt += f"- Name: {finding.get('name', 'Unknown')}\n"
                        prompt += f"- Exposure Level: {finding.get('exposure_level') or finding.get('severity', 'Unknown')}\n"
                        if finding.get('rule_id'):
                            prompt += f"- Rule ID: {finding.get('rule_id')}\n"
                        if finding.get('observation'):
                            prompt += f"- Observation: {finding.get('observation')}\n"
                        if finding.get('rationale'):
                            prompt += f"- Rationale: {finding.get('rationale')}\n"
                        if finding.get('basis'):
                            prompt += f"- Basis: {finding.get('basis')}\n"
                        prompt += f"- Description: {finding.get('description', 'No description provided')}\n"
                        prompt += f"- Remediation: {finding.get('remediation', 'No remediation provided')}\n\n"
            prompt += f"""
### CRITICAL COMPLIANCE RULES:
1. For network scans, you are strictly FORBIDDEN from making statements about vulnerabilities being found or not found.
2. The allowed claim is: "{n_ports} open ports were observed; this scan did not test for vulnerabilities."
3. Open ports are observed exposures, NOT confirmed vulnerabilities. Adhere strictly to the authoritative risk level.
4. The role of the host is unknown. Do not recommend restricting, closing or firewalling ports. Recommend verifying that each observed exposure is intended.
5. Rule outputs (Rule ID, Observation, Rationale, Basis, Exposure Level) are verified facts. You must receive them as facts and must not change levels.
6. PROSE RESTRICTION: The authoritative values above are provided for context only. You must NOT state, quote, assert, or mention any score, rating, risk level (Critical, High, Medium, Low, None), or severity ranking in free text prose (executive_summary, critical_findings, recommendations, remediation action steps). Scores and risk ratings are authoritative scanner-level outputs displayed exclusively in report headers; your prose must focus only on technical explanations and remediation guidance.
"""
        else:
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
3. PROSE RESTRICTION: The authoritative values above are provided for context only. You must NOT state, quote, assert, or mention any score, rating, risk level (Critical, High, Medium, Low, None), or severity ranking in free text prose (executive_summary, critical_findings, recommendations, remediation action steps). Scores and risk ratings are authoritative scanner-level outputs displayed exclusively in report headers; your prose must focus only on technical explanations and remediation guidance.
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
        except requests.exceptions.ConnectionError as e:
            raise GeminiAPIFailureError(f"Connection error to Gemini API: {e}")
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
                return cls._validate_response(fallback_data, scan_results=scan_results)
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
