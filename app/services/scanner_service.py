import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import certifi
import requests
import urllib3
from app.extensions import db
from app.models.scan import Scan, ScanResult, derive_risk

# Disable SSL warning messages in requests log
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def redact_cookie_value(cookie_str: str) -> str:
    """
    Redact cookie value in Set-Cookie while keeping cookie name and attribute flags.
    E.g.: 'session_id=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Lax'
    -> 'session_id=[redacted]; Path=/; Secure; HttpOnly; SameSite=Lax'
    """
    if not cookie_str:
        return cookie_str
    parts = [p.strip() for p in cookie_str.split(';')]
    if not parts:
        return cookie_str
    first = parts[0]
    if '=' in first:
        c_name, _ = first.split('=', 1)
        parts[0] = f"{c_name.strip()}=[redacted]"
    else:
        parts[0] = "[redacted]"
    return '; '.join(parts)


def sanitize_headers(headers: dict) -> dict:
    """
    Sanitize response headers for evidence storage:
    - Redact cookie values in Set-Cookie (preserve names and flags)
    - Never store request secrets, API keys, or auth headers
    """
    if not headers:
        return {}
    sensitive_keywords = ('authorization', 'api-key', 'secret', 'token', 'password', 'proxy-authorization')
    sanitized = {}
    for k, v in headers.items():
        k_str = str(k)
        k_lower = k_str.lower()
        # Drop sensitive authorization, API key, token, secret headers
        if any(s in k_lower for s in sensitive_keywords) and 'set-cookie' not in k_lower:
            continue
        if k_lower == 'set-cookie':
            if isinstance(v, list):
                sanitized[k_str] = [redact_cookie_value(str(item)) for item in v]
            else:
                sanitized[k_str] = redact_cookie_value(str(v))
        elif k_lower == 'cookie':
            sanitized[k_str] = '[redacted]'
        else:
            sanitized[k_str] = str(v)
    return sanitized

class ScannerService:
    """Service layer representing Website Scanning business logic and data aggregation."""

    DEFAULT_CONTROL_HOSTS = ("www.google.com", "www.cloudflare.com", "www.microsoft.com")

    @classmethod
    def probe_control_host(cls, host, timeout=3.0):
        """Attempt verified TLS handshake with a single control host using certifi CA bundle."""
        import certifi
        context = ssl.create_default_context(cafile=certifi.where())
        try:
            sock = socket.create_connection((host, 443), timeout=timeout)
            conn = context.wrap_socket(sock, server_hostname=host)
            try:
                conn.getpeercert()
                return True, None
            finally:
                conn.close()
        except Exception as e:
            raw_err = e.strerror if getattr(e, 'strerror', None) else (e.args[0] if getattr(e, 'args', None) and len(e.args) == 1 and isinstance(e.args[0], str) else str(e))
            return False, raw_err

    @classmethod
    def run_control_probes(cls, hosts=None, timeout=3.0):
        """
        Probe control hosts only on target TLS verification failure.
        Attempts verified handshakes to 3 configurable well-known public hosts
        (default: www.google.com, www.cloudflare.com, www.microsoft.com), 3s timeout each.
        """
        if hosts is None:
            try:
                from flask import current_app
                hosts = current_app.config.get('TLS_CONTROL_HOSTS', cls.DEFAULT_CONTROL_HOSTS)
            except Exception:
                hosts = cls.DEFAULT_CONTROL_HOSTS

        results = {}
        errors = {}
        for h in hosts:
            success, err = cls.probe_control_host(h, timeout=timeout)
            results[h] = success
            if not success:
                errors[h] = err

        any_succeeded = any(results.values())
        all_failed = not any_succeeded
        return {
            'results': results,
            'errors': errors,
            'any_succeeded': any_succeeded,
            'all_failed': all_failed
        }

    @staticmethod
    def audit_ssl(hostname, port=443):
        """Analyze target SSL certificate and TLS version via direct socket wrapper."""
        ssl_info = {
            'valid': False,
            'expiry_date': None,
            'days_remaining': 0,
            'tls_version': 'Unknown',
            'issuer': 'Unknown',
            'error': None,
            'error_type': None,
            'control_results': None
        }
        
        # Build the SSL context with the certifi CA bundle
        context = ssl.create_default_context(cafile=certifi.where())
        
        try:
            sock = socket.create_connection((hostname, port), timeout=4.0)
            conn = context.wrap_socket(sock, server_hostname=hostname)
            try:
                cert = conn.getpeercert()
                cipher = conn.cipher()
                
                ssl_info['valid'] = True
                ssl_info['tls_version'] = cipher[1] if cipher else 'Unknown'
                
                # Parse cert subject/issuer details
                issuer_data = dict(x[0] for x in cert.get('issuer', []))
                ssl_info['issuer'] = issuer_data.get('commonName', 'Unknown Issuer')
                
                # Parse certificate expiration datetime strictly from notAfter
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    expiry = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    scan_time = datetime.now(timezone.utc)
                    ssl_info['expiry_date'] = expiry
                    ssl_info['days_remaining'] = (expiry - scan_time).days
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        except ssl.SSLCertVerificationError as e:
            raw_err = e.strerror if getattr(e, 'strerror', None) else (e.args[0] if getattr(e, 'args', None) and len(e.args) == 1 and isinstance(e.args[0], str) else str(e))
            err_lower = raw_err.lower()
            if 'expired' in err_lower or 'has expired' in err_lower:
                ssl_info['error_type'] = 'expired'
                ssl_info['error'] = 'SSL certificate has expired'
            elif 'self-signed' in err_lower or 'self signed' in err_lower:
                ssl_info['error_type'] = 'self_signed'
                ssl_info['error'] = 'Self-signed or untrusted certificate authority'
            elif 'hostname' in err_lower or "doesn't match" in err_lower:
                ssl_info['error_type'] = 'hostname_mismatch'
                ssl_info['error'] = f"Certificate hostname mismatch for '{hostname}'"
            elif (
                'unable to get local issuer certificate' in err_lower
                or 'unable to get issuer certificate' in err_lower
                or 'unable to verify the first certificate' in err_lower
                or 'could not verify from the scanner host' in err_lower
                or 'certificate verify failed' in err_lower
            ):
                # Run control probe to 3 configurable public hosts (3s timeout each, only on failure)
                probe_res = ScannerService.run_control_probes(timeout=3.0)
                ssl_info['control_results'] = probe_res['results']
                if probe_res['all_failed']:
                    ssl_info['error_type'] = 'unverified_scanner_host'
                else:
                    ssl_info['error_type'] = 'unverified_cert_chain'
                ssl_info['error'] = raw_err
            else:
                probe_res = ScannerService.run_control_probes(timeout=3.0)
                ssl_info['control_results'] = probe_res['results']
                if probe_res['all_failed']:
                    ssl_info['error_type'] = 'unverified_scanner_host'
                else:
                    ssl_info['error_type'] = 'unverified_cert_chain'
                ssl_info['error'] = raw_err
        except Exception as e:
            raw_err = e.strerror if getattr(e, 'strerror', None) else (e.args[0] if getattr(e, 'args', None) and len(e.args) == 1 and isinstance(e.args[0], str) else str(e))
            err_lower = raw_err.lower()
            if 'expired' in err_lower:
                ssl_info['error_type'] = 'expired'
                ssl_info['error'] = 'SSL certificate has expired'
            elif 'self-signed' in err_lower or 'self signed' in err_lower:
                ssl_info['error_type'] = 'self_signed'
                ssl_info['error'] = 'Self-signed or untrusted certificate authority'
            elif 'hostname' in err_lower or "doesn't match" in err_lower:
                ssl_info['error_type'] = 'hostname_mismatch'
                ssl_info['error'] = f"Certificate hostname mismatch for '{hostname}'"
            elif (
                'unable to get local issuer certificate' in err_lower
                or 'unable to get issuer certificate' in err_lower
                or 'unable to verify the first certificate' in err_lower
                or 'could not verify from the scanner host' in err_lower
                or 'unverified from the scanner host' in err_lower
            ):
                probe_res = ScannerService.run_control_probes(timeout=3.0)
                ssl_info['control_results'] = probe_res['results']
                if probe_res['all_failed']:
                    ssl_info['error_type'] = 'unverified_scanner_host'
                else:
                    ssl_info['error_type'] = 'unverified_cert_chain'
                ssl_info['error'] = raw_err
            elif 'timed out' in err_lower or 'timeout' in err_lower:
                ssl_info['error_type'] = 'timeout'
                ssl_info['error'] = f'SSL handshake connection timed out on port {port}'
            elif 'refused' in err_lower:
                ssl_info['error_type'] = 'connection_refused'
                ssl_info['error'] = f'Port {port} connection refused (HTTPS service not running)'
            else:
                ssl_info['error_type'] = 'handshake_failure'
                ssl_info['error'] = raw_err
                
        return ssl_info

    @staticmethod
    def run_mock_scan(user_id, target_url):
        # We reuse the active scan flow for run_mock_scan to ensure we implement real audits as requested
        return ScannerService.run_active_scan(user_id, target_url)

    @staticmethod
    def is_private_or_loopback(hostname):
        import ipaddress
        import socket
        try:
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
        except Exception:
            return False

    @staticmethod
    def run_active_scan(user_id, target_url):
        """Inspect target website URL security headers, SSL status, and compile findings."""
        # 1. Create initial Scan model record
        scan = Scan(
            target_type='website',
            target_destination=target_url,
            user_id=user_id,
            status='running',
            started_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.commit()

        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname or target_url

        from flask import current_app
        is_testing = False
        try:
            is_testing = current_app.config.get('TESTING', False)
        except Exception:
            pass

        if not is_testing and ScannerService.is_private_or_loopback(hostname):
            # Log threat event log entry
            try:
                from app.models.threat import ThreatLog
                from flask import request
                threat = ThreatLog(
                    source_ip=request.remote_addr if request else "127.0.0.1",
                    threat_type="SSRF Scan Attempt",
                    severity="High",
                    description=f"Blocked website scanner SSRF target request: User ID {user_id} attempted to scan private/loopback destination: {target_url}"
                )
                db.session.add(threat)
            except Exception:
                pass
            scan.status = 'failed'
            scan.completed_at = datetime.now(timezone.utc)
            db.session.commit()
            raise ValueError("Scanning internal or private IP addresses is blocked for security reasons.")

        findings = []
        score = 100
        
        # Initialize default scanner metrics
        is_https = target_url.lower().startswith('https://')
        ssl_valid = False
        tls_version = 'Unknown'
        
        # 2. Establish SSL Diagnostics Checks if target supports HTTPS
        port = parsed_url.port or (443 if is_https else 80)
        if is_https:
            ssl_data = ScannerService.audit_ssl(hostname, port=port)
            if ssl_data['valid']:
                ssl_valid = True
                tls_version = ssl_data['tls_version']
                
                # Check for outdated TLS protocols (TLSv1.1 or lower)
                if 'TLSv1.0' in tls_version or 'TLSv1.1' in tls_version or 'SSLv' in tls_version:
                    score -= 20
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='Outdated TLS Protocol Version Allowed',
                        severity='high',
                        description=f"The server allows TLS handshakes using {tls_version}. Outdated TLS protocols are vulnerable to POODLE, BEAST, and other cipher attacks.",
                        remediation='Disable TLS 1.0 and TLS 1.1 protocol configurations on your web server and TLS proxies. Enforce TLS 1.2 or TLS 1.3 only.',
                        raw_payload={'target_url': target_url, 'hostname': hostname, 'tls_version': tls_version, 'evidence': f"Server negotiated handshake with deprecated protocol {tls_version}."}
                    ))
                
                # Check for certificate expiration limits
                if ssl_data['days_remaining'] < 0:
                    score -= 30
                    exp_str = ssl_data['expiry_date'].strftime('%Y-%m-%d %H:%M:%S UTC') if ssl_data.get('expiry_date') else 'Unknown'
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='Expired SSL Certificate Detected',
                        severity='critical',
                        description=f"The SSL certificate returned by the server expired {abs(ssl_data['days_remaining'])} days ago on {exp_str}.",
                        remediation='Renew the SSL certificate immediately through your certificate authority or Let\'s Encrypt.',
                        raw_payload={
                            'target_url': target_url,
                            'hostname': hostname,
                            'days_remaining': ssl_data['days_remaining'],
                            'expired_at': ssl_data['expiry_date'].isoformat() if ssl_data.get('expiry_date') else None,
                            'not_after': exp_str,
                            'issuer': ssl_data.get('issuer', 'Unknown Issuer'),
                            'tls_version': ssl_data.get('tls_version', 'Unknown'),
                            'evidence': f"Certificate expired {abs(ssl_data['days_remaining'])} days ago on {exp_str}. Issued by {ssl_data.get('issuer', 'Unknown Issuer')}."
                        }
                    ))
                elif ssl_data['days_remaining'] < 30:
                    score -= 10
                    exp_str = ssl_data['expiry_date'].strftime('%Y-%m-%d %H:%M:%S UTC') if ssl_data.get('expiry_date') else 'Unknown'
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='SSL Certificate Near Expiration',
                        severity='medium',
                        description=f"The SSL certificate for {hostname} expires in {ssl_data['days_remaining']} days ({exp_str}).",
                        remediation='Schedule a certificate renewal deployment before the certificate expires.',
                        raw_payload={
                            'target_url': target_url,
                            'hostname': hostname,
                            'days_remaining': ssl_data['days_remaining'],
                            'expires_at': ssl_data['expiry_date'].isoformat() if ssl_data.get('expiry_date') else None,
                            'not_after': exp_str,
                            'issuer': ssl_data.get('issuer', 'Unknown Issuer'),
                            'tls_version': ssl_data.get('tls_version', 'Unknown'),
                            'evidence': f"Certificate expires in {ssl_data['days_remaining']} days on {exp_str}. Issued by {ssl_data.get('issuer', 'Unknown Issuer')}."
                        }
                    ))
            else:
                # SSL Handshake Failure with specific error categorization
                err_type = ssl_data.get('error_type', 'handshake_failure')
                if err_type == 'expired':
                    score -= 30
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='Expired SSL Certificate Detected',
                        severity='critical',
                        description=f"The SSL certificate for {hostname} has expired.",
                        remediation='Renew the SSL certificate immediately.',
                        raw_payload={'target_url': target_url, 'hostname': hostname, 'error': ssl_data['error'], 'error_type': 'expired', 'evidence': ssl_data['error']}
                    ))
                elif err_type == 'self_signed':
                    score -= 25
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='Self-Signed or Untrusted SSL Certificate',
                        severity='critical',
                        description=f"The SSL certificate for {hostname} is self-signed or not signed by a recognized Certificate Authority.",
                        remediation='Deploy a valid SSL certificate signed by a recognized public CA (e.g. Let\'s Encrypt, DigiCert).',
                        raw_payload={'target_url': target_url, 'hostname': hostname, 'error': ssl_data['error'], 'error_type': 'self_signed', 'evidence': ssl_data['error']}
                    ))
                elif err_type == 'hostname_mismatch':
                    score -= 20
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='SSL Certificate Hostname Mismatch',
                        severity='high',
                        description=f"The hostname '{hostname}' does not match any Common Name (CN) or Subject Alternative Name (SAN) on the certificate.",
                        remediation='Reissue the SSL certificate ensuring the domain name is included in Subject Alternative Names.',
                        raw_payload={'target_url': target_url, 'hostname': hostname, 'error': ssl_data['error'], 'error_type': 'hostname_mismatch', 'evidence': ssl_data['error']}
                    ))
                elif err_type == 'unverified_scanner_host':
                    # All controls also failed: info finding, 0 penalty, text "TLS verification inconclusive: scanner host trust store problem", keep raw error.
                    ctrl_res = ssl_data.get('control_results', {})
                    evidence_text = f"TLS verification inconclusive: scanner host trust store problem. Raw error: {ssl_data['error']}. All control probes failed: {ctrl_res}."
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='TLS verification inconclusive: scanner host trust store problem',
                        severity='info',
                        description=f"TLS verification inconclusive: scanner host trust store problem. Handshake error: {ssl_data['error']}",
                        remediation='Verify the scanner host trust store configuration and local CA certificates.',
                        raw_payload={
                            'target_url': target_url,
                            'hostname': hostname,
                            'error': ssl_data['error'],
                            'error_type': 'unverified_scanner_host',
                            'control_results': ctrl_res,
                            'evidence': evidence_text
                        }
                    ))
                elif err_type == 'unverified_cert_chain':
                    # Any control succeeded: Medium finding "SSL Certificate Chain Could Not Be Verified", -10 score, evidence includes raw error and control results.
                    score -= 10
                    ctrl_res = ssl_data.get('control_results', {})
                    evidence_text = f"The certificate chain could not be validated: {ssl_data['error']}. Control probe results: {ctrl_res}."
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='SSL Certificate Chain Could Not Be Verified',
                        severity='medium',
                        description=f"The SSL certificate chain for {hostname} could not be validated: {ssl_data['error']}. Verified handshakes to control hosts succeeded.",
                        remediation='Configure your web server to serve a complete and valid certificate chain that anchors to a trusted certificate authority.',
                        raw_payload={
                            'target_url': target_url,
                            'hostname': hostname,
                            'error': ssl_data['error'],
                            'error_type': 'unverified_cert_chain',
                            'control_results': ctrl_res,
                            'evidence': evidence_text
                        }
                    ))
                else:
                    score -= 20
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='SSL/TLS Handshake Failure',
                        severity='high',
                        description=f"Could not establish a secure TLS handshake with {hostname}: {ssl_data['error']}",
                        remediation='Verify that port 443 is open, an SSL certificate is properly installed, and cipher suites are compatible.',
                        raw_payload={'target_url': target_url, 'hostname': hostname, 'error': ssl_data['error'], 'error_type': 'handshake_failure', 'evidence': ssl_data['error']}
                    ))

        # 3. Audit HTTP Communication & Security Headers
        response = None
        requests_fallback_verify_false = False
        try:
            # Check certificate validity with standard verify=True first if HTTPS
            try:
                response = requests.get(target_url, timeout=5.0, verify=True, allow_redirects=True)
            except requests.exceptions.SSLError as ssl_err:
                requests_fallback_verify_false = True
                err_str = str(ssl_err)
                err_lower = err_str.lower()
                # If this error is because the scanner host could not verify local issuer,
                # do not penalize score or add a Critical finding.
                if (
                    ssl_data.get('error_type') in ('unverified_scanner_host', 'unverified_cert_chain')
                    or 'unable to get local issuer certificate' in err_lower
                    or 'could not verify from the scanner host' in err_lower
                ):
                    # Inconclusive/informational observation from scanner host - do not deduct score
                    # Fallback to verify=False so we can inspect headers
                    response = requests.get(target_url, timeout=5.0, verify=False, allow_redirects=True)
                else:
                    # SSL verification failed on HTTP request
                    score -= 25
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='Invalid or Untrusted SSL Certificate',
                        severity='critical',
                        description=f"HTTPS connection to target failed certificate verification: {ssl_err}",
                        remediation="Install a valid SSL certificate signed by a trusted public Certificate Authority.",
                        raw_payload={'target_url': target_url, 'ssl_error': str(ssl_err), 'evidence': f"Certificate verification failed: {ssl_err}", 'tls_verified': False}
                    ))
                    # Fallback to verify=False so we can still inspect headers
                    response = requests.get(target_url, timeout=5.0, verify=False, allow_redirects=True)

        except (requests.exceptions.Timeout, requests.exceptions.ConnectTimeout) as timeout_err:
            score -= 35
            findings.append(ScanResult(
                scan_id=scan.id,
                vulnerability_name='Target Request Timed Out',
                severity='high',
                description=f"The scanner timed out while connecting to {target_url} after 5.0 seconds.",
                remediation="Ensure the web server is online, responsive, and not blocking incoming scanner IP addresses.",
                raw_payload={'target_url': target_url, 'error': str(timeout_err), 'evidence': 'HTTP request timed out.'}
            ))
        except requests.exceptions.ConnectionError as conn_err:
            score -= 35
            findings.append(ScanResult(
                scan_id=scan.id,
                vulnerability_name='Target Connection Failed',
                severity='high',
                description=f"The scanner was unable to establish a connection with {target_url}: {conn_err}",
                remediation="Check DNS configuration, ensure the domain name resolves properly, and verify that web ports (80/443) are accessible.",
                raw_payload={'target_url': target_url, 'error': str(conn_err), 'evidence': 'DNS resolution or TCP connection failed.'}
            ))
        except requests.exceptions.RequestException as req_err:
            score -= 30
            findings.append(ScanResult(
                scan_id=scan.id,
                vulnerability_name='Target Request Failed',
                severity='high',
                description=f"HTTP request to {target_url} encountered an error: {req_err}",
                remediation="Ensure web server configurations permit incoming HTTP requests.",
                raw_payload={'target_url': target_url, 'error': str(req_err), 'evidence': str(req_err)}
            ))

        # Only audit headers if a response was successfully received
        if response is not None:
            final_url = response.url
            http_status = response.status_code
            headers = response.headers

            # Plain HTTP Redirect Inspection
            if not is_https:
                redirected_to_https = final_url.lower().startswith('https://') or any(
                    r.is_redirect and r.headers.get('Location', '').lower().startswith('https://')
                    for r in response.history
                )
                if redirected_to_https:
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='HTTP to HTTPS Redirection Enforced',
                        severity='info',
                        description=f"Initial HTTP request to '{target_url}' automatically redirected to secure HTTPS endpoint '{final_url}'.",
                        remediation='Maintain existing HTTP to HTTPS redirection configurations.',
                        raw_payload={'target_url': target_url, 'final_url': final_url, 'redirect_chain': len(response.history), 'evidence': f"Redirected to {final_url}"}
                    ))
                else:
                    score -= 30
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='Plain HTTP Transmission (No HTTPS)',
                        severity='high',
                        description="The website is served over unencrypted HTTP without automatic redirection to HTTPS. Sensitive user traffic can be intercepted in clear text.",
                        remediation='Configure web server redirect rules (HTTP 301/308) to force all HTTP traffic to HTTPS.',
                        raw_payload={'target_url': target_url, 'final_url': final_url, 'protocol': 'HTTP', 'evidence': f"Target remained on HTTP ({final_url})"}
                    ))

            # Flag HTTP error responses so findings are placed in context
            if http_status >= 400:
                score -= 5
                findings.append(ScanResult(
                    scan_id=scan.id,
                    vulnerability_name=f'Target Returned HTTP {http_status} Error',
                    severity='medium',
                    description=f"The server responded with HTTP status code {http_status} for '{final_url}'. Security headers evaluated on error pages may differ from application endpoints.",
                    remediation="Verify target URL route and ensure backend application serves HTTP 200 OK for standard requests.",
                    raw_payload={'target_url': target_url, 'final_url': final_url, 'http_status': http_status, 'evidence': f"Server returned HTTP status code {http_status}"}
                ))

            # Audit standard security headers with structured evidence
            header_checks = [
                (
                    'Strict-Transport-Security',
                    'Missing Strict-Transport-Security (HSTS) Header',
                    'medium',
                    15,
                    "The 'Strict-Transport-Security' (HSTS) header is missing. HSTS instructs browsers to exclusively communicate via HTTPS, defending against SSL-stripping and MITM attacks. Absence of this header increases protocol downgrade exposure, but does not itself confirm traffic interception is taking place.",
                    "Configure your web server to append the 'Strict-Transport-Security' response header (e.g. Strict-Transport-Security: max-age=31536000; includeSubDomains)."
                ),
                (
                    'Content-Security-Policy',
                    'Missing Content-Security-Policy (CSP) Header',
                    'high',
                    15,
                    "The 'Content-Security-Policy' (CSP) header is missing. CSP provides defense-in-depth against Content Injection and Cross-Site Scripting (XSS) by restricting sources of executable scripts. Absence of this header reduces browser-side defense-in-depth, but does not itself prove that XSS is present or exploitable.",
                    "Add a 'Content-Security-Policy' header to your web server configurations (e.g. Content-Security-Policy: default-src 'self')."
                ),
                (
                    'X-Frame-Options',
                    'Missing X-Frame-Options Header',
                    'medium',
                    10,
                    "The 'X-Frame-Options' header is missing. This header restricts whether the webpage can be framed inside <iframe> or <object> tags. Absence of this header increases framing exposure against Clickjacking, but does not itself confirm an exploitable framing flaw exists.",
                    "Configure 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' headers."
                ),
                (
                    'X-Content-Type-Options',
                    'Missing X-Content-Type-Options Header',
                    'low',
                    5,
                    "The 'X-Content-Type-Options' header is missing. Setting 'nosniff' prevents browsers from MIME-sniffing response payloads. Absence of this header leaves MIME sniffing enabled in older browsers, reducing defense-in-depth.",
                    "Configure your web server to include 'X-Content-Type-Options: nosniff'."
                ),
                (
                    'Referrer-Policy',
                    'Missing Referrer-Policy Header',
                    'low',
                    5,
                    "The 'Referrer-Policy' header is missing. This header dictates whether referrer URL information (which may contain private path parameters) is sent along with outbound clicks. Absence of this header leaves default browser referrer behavior active.",
                    "Configure the 'Referrer-Policy: strict-origin-when-cross-origin' header."
                ),
                (
                    'Permissions-Policy',
                    'Missing Permissions-Policy Header',
                    'low',
                    5,
                    "The 'Permissions-Policy' header is missing. This header allows site administrators to restrict browser features (such as camera, microphone, and geolocation APIs). Absence of this header leaves device API feature permissions at default browser settings.",
                    "Configure the 'Permissions-Policy' header to disable unused device APIs (e.g. Permissions-Policy: camera=(), microphone=())."
                ),
            ]

            for header_name, vuln_name, severity, penalty, description, remediation in header_checks:
                val = headers.get(header_name)
                if not val:
                    # Also check legacy alias for Permissions-Policy
                    if header_name == 'Permissions-Policy' and headers.get('Feature-Policy'):
                        continue
                    score -= penalty
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name=vuln_name,
                        severity=severity,
                        description=description,
                        remediation=remediation,
                        raw_payload={
                            'target_url': target_url,
                            'final_url': final_url,
                            'http_status': http_status,
                            'header_checked': header_name,
                            'confirmed_missing': True,
                            'evidence': f"Header '{header_name}' was not present in response headers from {final_url} (HTTP {http_status})."
                        }
                    ))

            # Check Server banner info disclosures
            server_banner = headers.get('Server')
            if server_banner:
                has_details = any(char.isdigit() for char in server_banner)
                if has_details:
                    score -= 5
                    findings.append(ScanResult(
                        scan_id=scan.id,
                        vulnerability_name='Server Software Version Banner Disclosure',
                        severity='info',
                        description=f"The Server response header discloses specific backend software version specifications ({server_banner}). This helps attackers target known CVEs.",
                        remediation="Configure your web server (Nginx: server_tokens off; Apache: ServerTokens Prod) to hide precise version details.",
                        raw_payload={
                            'target_url': target_url,
                            'final_url': final_url,
                            'header_checked': 'Server',
                            'disclosed_banner': server_banner,
                            'evidence': f"Server response header returned: '{server_banner}'."
                        }
                    ))


        # If requests fell back to verify=False, store tls_verified=False in the finding's raw_payload
        if requests_fallback_verify_false:
            for r in findings:
                if any(k in r.vulnerability_name.lower() for k in ('ssl', 'tls', 'certificate', 'handshake')):
                    if r.raw_payload is None:
                        r.raw_payload = {}
                    r.raw_payload['tls_verified'] = False

        # 4. Finalize database entries
        scan.status = 'completed'
        scan.completed_at = datetime.now(timezone.utc)
        final_score = max(0, min(100, score))
        scan.security_score = final_score  # Keep risk score locked within [0, 100]

        # Determine deterministic overall risk from derive_risk (score bands + critical floor)
        det_risk = derive_risk(final_score, findings)
        scan.risk_level = str(det_risk)

        # Build website scan evidence payload
        tls_verified = not requests_fallback_verify_false if is_https else None
        audit_ssl_evidence = None
        if is_https and 'ssl_data' in locals() and ssl_data:
            exp_date_str = ssl_data.get('expiry_date').isoformat() if ssl_data.get('expiry_date') else None
            audit_ssl_evidence = {
                'valid': ssl_data.get('valid'),
                'expiry_date': exp_date_str,
                'days_remaining': ssl_data.get('days_remaining'),
                'tls_version': ssl_data.get('tls_version'),
                'issuer': ssl_data.get('issuer'),
                'error': ssl_data.get('error'),
                'error_type': ssl_data.get('error_type'),
                'control_results': ssl_data.get('control_results'),
                'tls_verified': tls_verified
            }

        def _clean_str_val(val, fallback=""):
            if val is None:
                return fallback
            if hasattr(val, '_mock_name') or type(val).__name__ == 'MagicMock':
                return fallback
            return str(val)

        redirect_chain = []
        if response is not None and hasattr(response, 'history') and response.history:
            for r in response.history:
                r_u = getattr(r, 'url', None)
                if r_u is not None and not hasattr(r_u, '_mock_name'):
                    redirect_chain.append(str(r_u))

        final_url_val = _clean_str_val(getattr(response, 'url', None), str(target_url)) if response is not None else str(target_url)

        status_code_val = None
        if response is not None and getattr(response, 'status_code', None) is not None:
            sc = response.status_code
            if isinstance(sc, int):
                status_code_val = sc
            elif not hasattr(sc, '_mock_name'):
                try:
                    status_code_val = int(sc)
                except Exception:
                    status_code_val = None

        raw_headers = {}
        if response is not None and hasattr(response, 'headers') and response.headers:
            try:
                raw_headers = dict(response.headers)
            except Exception:
                raw_headers = {}
        response_headers_val = sanitize_headers(raw_headers)

        evidence_payload = {
            "final_url": final_url_val,
            "status_code": status_code_val,
            "redirect_chain": redirect_chain,
            "response_headers": response_headers_val,
            "audit_ssl": audit_ssl_evidence
        }
        scan.evidence_json = json.dumps(evidence_payload, default=str)

        for result in findings:
            db.session.add(result)
            
        db.session.commit()

        # 5. Trigger AI Analysis Service automatically
        try:
            from app.services.ai_service import AIAnalysisService
            from app.models.ai import AIResponse

            # Format findings for AIAnalysisService
            findings_data = []
            for result in findings:
                findings_data.append({
                    "name": result.vulnerability_name,
                    "severity": result.severity,
                    "description": result.description,
                    "remediation": result.remediation
                })

            scan_results_payload = {
                "target": scan.target_destination,
                "scan_type": "website",
                "security_score": final_score,
                "overall_risk": det_risk,
                "enforce_authoritative_metrics": True,
                "findings": findings_data
            }

            # Call AI Service (falls back safely on quota exhaustion)
            ai_data = AIAnalysisService.analyze_scan(scan_results_payload, fallback_on_quota=True, user_id=user_id)
            model_used = ai_data.get("_model_used", AIAnalysisService.DEFAULT_MODEL)

            # Persist AI response
            db_response = AIResponse(
                prompt="Automatically generated report from website scanner results.",
                response_text=json.dumps(ai_data),
                model_used=model_used,
                scan_id=scan.id
            )
            db.session.add(db_response)
            db.session.commit()
        except Exception as e:
            # AI analysis must fail gracefully and not prevent the scan itself from succeeding
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"AI analysis failed gracefully for scan {scan.uuid}: {e}")

        return scan
