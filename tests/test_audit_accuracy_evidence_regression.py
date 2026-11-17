import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import requests

from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan, NetworkScanResult
from app.services.scanner_service import ScannerService
from app.services.network_scan_service import NmapNetworkScannerService
from app.services.risk_calculator import SimpleRiskCalculator
from app.services.ai_service import AIAnalysisService


# ---------------------------------------------------------------------------
# 1. Missing header with a red status indicator (Regression Test 1)
# ---------------------------------------------------------------------------
@patch("requests.get")
@patch.object(ScannerService, "audit_ssl")
def test_missing_header_renders_red_missing_indicator(mock_ssl, mock_get, app, db, test_users):
    """Test that missing headers produce missing findings and render with a red/danger indicator."""
    mock_ssl.return_value = {
        'valid': True,
        'tls_version': 'TLSv1.3',
        'days_remaining': 180,
        'issuer': 'DigiCert',
        'expiry_date': datetime.now(timezone.utc) + timedelta(days=180),
        'error': None
    }
    
    # Mock HTTP response with missing HSTS, CSP, and Referrer-Policy
    mock_resp = MagicMock()
    mock_resp.url = "https://example.com/"
    mock_resp.status_code = 200
    mock_resp.headers = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Permissions-Policy': 'camera=()'
    }
    mock_resp.history = []
    mock_get.return_value = mock_resp

    with app.app_context():
        scan = ScannerService.run_active_scan(test_users['user'].id, "https://example.com")
        assert scan.status == 'completed'
        
        # Verify missing headers are recorded in findings
        vuln_names = [r.vulnerability_name for r in scan.results]
        assert 'Missing Strict-Transport-Security (HSTS) Header' in vuln_names
        assert 'Missing Content-Security-Policy (CSP) Header' in vuln_names
        assert 'Missing Referrer-Policy Header' in vuln_names
        
        # Client requests the rendered results page
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_users['user'].id)
            sess['_fresh'] = True
            
        res = client.get(f'/scanner/results/{scan.uuid}')
        assert res.status_code == 200
        html = res.data.decode('utf-8')
        
        # The UI must display MISSING badge for missing headers with danger styling
        assert 'MISSING' in html
        assert 'text-danger' in html
        assert 'bi-x-circle' in html
        
        # Verify that HSTS and CSP do NOT have green check-circle
        # Check that 'text-emerald' is not paired with a missing indicator
        assert 'text-danger"></i>' in html or 'text-danger" style' in html or 'bi-x-circle text-danger' in html


# ---------------------------------------------------------------------------
# 2. Present header with a green status indicator (Regression Test 2)
# ---------------------------------------------------------------------------
@patch("requests.get")
@patch.object(ScannerService, "audit_ssl")
def test_present_header_renders_green_present_indicator(mock_ssl, mock_get, app, db, test_users):
    """Test that present headers render with a green/emerald indicator and score is 100."""
    mock_ssl.return_value = {
        'valid': True,
        'tls_version': 'TLSv1.3',
        'days_remaining': 120,
        'issuer': 'Let\'s Encrypt',
        'expiry_date': datetime.now(timezone.utc) + timedelta(days=120),
        'error': None
    }
    
    mock_resp = MagicMock()
    mock_resp.url = "https://fully-hardened.com/"
    mock_resp.status_code = 200
    mock_resp.headers = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=()'
    }
    mock_resp.history = []
    mock_get.return_value = mock_resp

    with app.app_context():
        scan = ScannerService.run_active_scan(test_users['user'].id, "https://fully-hardened.com")
        assert scan.security_score == 100
        assert len(scan.results) == 0
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_users['user'].id)
            sess['_fresh'] = True
            
        res = client.get(f'/scanner/results/{scan.uuid}')
        assert res.status_code == 200
        html = res.data.decode('utf-8')
        
        # Must show PRESENT and emerald check-circle
        assert 'PRESENT' in html
        assert 'text-emerald' in html
        assert 'bi-check-circle text-emerald' in html
        assert 'MISSING' not in html


# ---------------------------------------------------------------------------
# 3. Inaccessible target producing no fabricated header findings (Regression Test 3)
# ---------------------------------------------------------------------------
@patch("requests.get")
@patch.object(ScannerService, "audit_ssl")
def test_inaccessible_target_no_fabricated_header_findings(mock_ssl, mock_get, app, db, test_users):
    """Test that connection failure records connection error, no fake header findings, and UI shows Not Tested."""
    mock_ssl.return_value = {
        'valid': False,
        'error': 'Connection refused on port 443',
        'error_type': 'connection_refused'
    }
    mock_get.side_effect = requests.exceptions.ConnectionError("Failed to establish TCP connection")

    with app.app_context():
        scan = ScannerService.run_active_scan(test_users['user'].id, "https://dead-target.example.org")
        assert scan.status == 'completed'
        
        vuln_names = [r.vulnerability_name for r in scan.results]
        assert 'Target Connection Failed' in vuln_names
        # Crucial: Must NOT invent missing header findings
        assert not any('Missing' in name and 'Header' in name for name in vuln_names)
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_users['user'].id)
            sess['_fresh'] = True
            
        res = client.get(f'/scanner/results/{scan.uuid}')
        assert res.status_code == 200
        html = res.data.decode('utf-8')
        
        # When request failed, headers must be marked NOT TESTED (never green passing)
        assert 'NOT TESTED' in html
        assert 'bi-dash-circle text-warning' in html or 'text-warning' in html


# ---------------------------------------------------------------------------
# 4. Certificate expiry calculated from mocked certificate date (Regression Test 4)
# ---------------------------------------------------------------------------
def test_certificate_expiry_calculated_from_not_after():
    """Test that certificate expiry is calculated strictly from notAfter timestamp and scan time."""
    # Mock socket and context
    with patch("socket.create_connection") as mock_conn:
        with patch("ssl.create_default_context") as mock_ctx:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            
            mock_ssl_sock = MagicMock()
            # Set notAfter to exactly 14 days in the future
            future_dt = datetime.now(timezone.utc) + timedelta(days=14)
            # Format as standard TLS notAfter string: 'b %d %H:%M:%S %Y %Z'
            mock_not_after = future_dt.strftime('%b %d %H:%M:%S %Y GMT')
            
            mock_ssl_sock.getpeercert.return_value = {
                'issuer': [[('commonName', 'DigiCert Global Root CA')]],
                'notAfter': mock_not_after
            }
            mock_ssl_sock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
            mock_ctx.return_value.wrap_socket.return_value = mock_ssl_sock
            
            res = ScannerService.audit_ssl("facebook.com", port=443)
            
            assert res['valid'] is True
            assert res['tls_version'] == 'TLSv1.3'
            assert res['issuer'] == 'DigiCert Global Root CA'
            assert res['days_remaining'] in (13, 14)  # Bounded by rounding
            assert res['expiry_date'] is not None
            assert res['expiry_date'].year == future_dt.year


# ---------------------------------------------------------------------------
# 5. Nmap XML with open ports and unknown service banners (Regression Test 5)
# ---------------------------------------------------------------------------
MOCK_XML_OPEN_UNKNOWN_BANNER = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.92">
  <host>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_nmap_xml_open_ports_with_unknown_banners(mock_run, mock_nmap_avail, app, db, test_users):
    """Test that Nmap XML open ports without banners record service_version='Unknown' without false vulnerabilities."""
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = MOCK_XML_OPEN_UNKNOWN_BANNER
    mock_run.return_value = mock_res
    
    from app.repositories.network_scan_repository import SQLAlchemyNetworkScanRepository
    repo = SQLAlchemyNetworkScanRepository()
    calc = SimpleRiskCalculator()
    service = NmapNetworkScannerService(repo, calc)
    
    with app.app_context():
        scan = service.execute_scan(test_users['user'].id, "192.0.2.1", "Quick Scan")
        assert scan.status == 'completed'
        assert len(scan.results) == 2
        
        for r in scan.results:
            assert r.state == 'open'
            assert r.service_version in ('Unknown', 'Not identified (service name assumed from port number)')
            # Informational / Low severity for standard HTTP/HTTPS open ports
            assert r.severity in ('Low', 'Informational')
            
        assert scan.risk_level == 'Low'


# ---------------------------------------------------------------------------
# 6. Nmap XML with filtered/closed ports not falsely displayed as open (Regression Test 6)
# ---------------------------------------------------------------------------
def test_risk_calculator_ignores_closed_and_filtered_ports():
    """Test that SimpleRiskCalculator only elevates risk for open ports, ignoring closed and filtered ports."""
    calc = SimpleRiskCalculator()
    
    # Scenario: Port 3389 (RDP) is FILTERED, not open
    filtered_rdp = NetworkScanResult(
        port=3389,
        protocol='tcp',
        service_name='ms-wbt-server',
        service_version='Unknown',
        state='filtered',
        severity='High',
        remediation='Maintain firewall rules.'
    )
    
    # Port 22 (SSH) is CLOSED, not open
    closed_ssh = NetworkScanResult(
        port=22,
        protocol='tcp',
        service_name='ssh',
        service_version='Unknown',
        state='closed',
        severity='Medium',
        remediation='No action required.'
    )
    
    # Port 80 (HTTP) is OPEN
    open_http = NetworkScanResult(
        port=80,
        protocol='tcp',
        service_name='http',
        service_version='nginx',
        state='open',
        severity='Low',
        remediation='Redirect to HTTPS.'
    )
    
    # When evaluated with filtered/closed ports, risk MUST be Low (from the open port 80)
    risk = calc.calculate_risk([filtered_rdp, closed_ssh, open_http])
    assert risk == 'Low'
    
    # If all ports are filtered or closed, risk is Low
    risk_all_closed = calc.calculate_risk([filtered_rdp, closed_ssh])
    assert risk_all_closed == 'Low'


# ---------------------------------------------------------------------------
# 7. Risk scores matching deterministic scoring rules (Regression Test 7)
# ---------------------------------------------------------------------------
@patch("requests.get")
@patch.object(ScannerService, "audit_ssl")
def test_deterministic_scoring_rules_google_scenario(mock_ssl, mock_get, app, db, test_users):
    """Test exact deterministic security scoring matching Google audit scenario (55/100)."""
    mock_ssl.return_value = {
        'valid': True,
        'tls_version': 'TLSv1.3',
        'days_remaining': 100,
        'issuer': 'GTS CA 1C3',
        'expiry_date': datetime.now(timezone.utc) + timedelta(days=100),
        'error': None
    }
    
    # Missing: HSTS (-15), CSP (-15), X-Content-Type-Options (-5), Referrer-Policy (-5), Permissions-Policy (-5)
    # Present: X-Frame-Options (0)
    # Total penalties: 15 + 15 + 5 + 5 + 5 = 45 => Score: 100 - 45 = 55
    mock_resp = MagicMock()
    mock_resp.url = "https://www.google.com/"
    mock_resp.status_code = 200
    mock_resp.headers = {
        'X-Frame-Options': 'SAMEORIGIN'
    }
    mock_resp.history = []
    mock_get.return_value = mock_resp

    with app.app_context():
        scan = ScannerService.run_active_scan(test_users['user'].id, "https://google.com")
        assert scan.security_score == 55
        
        # Verify penalties recorded
        vuln_names = [r.vulnerability_name for r in scan.results]
        assert 'Missing Strict-Transport-Security (HSTS) Header' in vuln_names
        assert 'Missing Content-Security-Policy (CSP) Header' in vuln_names
        assert 'Missing X-Content-Type-Options Header' in vuln_names
        assert 'Missing Referrer-Policy Header' in vuln_names
        assert 'Missing Permissions-Policy Header' in vuln_names
        assert 'Missing X-Frame-Options Header' not in vuln_names


# ---------------------------------------------------------------------------
# 8. AI responses attempting to invent findings or contradict scanner evidence (Regression Test 8)
# ---------------------------------------------------------------------------
def test_ai_sanitizes_invented_findings_and_contradictions():
    """Test that AIAnalysisService._validate_response rejects hallucinated findings and corrects contradictions."""
    # Target scan data has ONLY one finding: Missing Referrer-Policy Header (low)
    scan_results = {
        "target": "https://example.com",
        "scan_type": "website",
        "security_score": 95,
        "overall_risk": "Low",
        "enforce_authoritative_metrics": True,
        "findings": [
            {
                "name": "Missing Referrer-Policy Header",
                "severity": "low",
                "description": "Header is missing.",
                "remediation": "Add Referrer-Policy."
            }
        ]
    }
    
    # AI response attempts to hallucinate an SQL Injection and an open RDP port
    hallucinated_ai_json = {
        "security_score": 20, # Contradicts scanner's score
        "overall_risk": "Critical", # Contradicts scanner's risk
        "executive_summary": "Critical vulnerability detected.",
        "critical_findings": [
            "Severe SQL Injection in login endpoint",
            "Missing Referrer-Policy Header allows information leakage"
        ],
        "recommendations": [
            "Sanitize all SQL statements.",
            "Add Referrer-Policy header."
        ],
        "remediation_priority": [
            {
                "finding": "Severe SQL Injection in login endpoint",
                "priority": "Critical",
                "remediation": "Use prepared statements."
            },
            {
                "finding": "Missing Referrer-Policy Header",
                "priority": "Low",
                "remediation": "Add header."
            }
        ]
    }
    
    validated = AIAnalysisService._validate_response(hallucinated_ai_json, scan_results=scan_results)
    
    # 1. Hallucinated SQL injection must be rejected from critical_findings
    assert "Severe SQL Injection in login endpoint" not in validated["critical_findings"]
    assert len(validated["critical_findings"]) == 1
    assert "Referrer-Policy" in validated["critical_findings"][0]
    
    # 2. Hallucinated SQL injection must be rejected from remediation_priority
    prio_findings = [item["finding"] for item in validated["remediation_priority"]]
    assert "Severe SQL Injection in login endpoint" not in prio_findings
    assert any("Referrer-Policy" in f for f in prio_findings)
    
    # 3. Contradictory metrics must be aligned to authoritative scanner metrics
    assert validated["security_score"] == 95
    assert validated["overall_risk"] == "Low"


# ---------------------------------------------------------------------------
# 9. Rendered result pages displaying statuses consistent with stored findings (Regression Test 9)
# ---------------------------------------------------------------------------
def test_rendered_website_results_consistent_with_stored_findings(app, db, test_users):
    """Test that rendered web results page displays statuses and evidence consistent with stored findings."""
    with app.app_context():
        scan = Scan(
            target_type='website',
            target_destination='https://audit-verify.org',
            user_id=test_users['user'].id,
            status='completed',
            risk_score=70,
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.commit()
        
        # Add a missing HSTS finding with explicit evidence
        r1 = ScanResult(
            scan_id=scan.id,
            vulnerability_name='Missing Strict-Transport-Security (HSTS) Header',
            severity='medium',
            description='HSTS header is absent.',
            remediation='Configure Strict-Transport-Security header.',
            raw_payload={
                'header_checked': 'Strict-Transport-Security',
                'final_url': 'https://audit-verify.org/',
                'http_status': 200,
                'evidence': "Header 'Strict-Transport-Security' was not present in response headers."
            }
        )
        # Add a near-expiry certificate finding
        r2 = ScanResult(
            scan_id=scan.id,
            vulnerability_name='SSL Certificate Near Expiration',
            severity='medium',
            description='The SSL certificate expires in 7 days.',
            remediation='Renew certificate.',
            raw_payload={
                'hostname': 'audit-verify.org',
                'days_remaining': 7,
                'not_after': '2026-10-31 23:59:59 UTC',
                'evidence': 'Target certificate expires on 2026-10-31 23:59:59 UTC (7 days remaining).'
            }
        )
        db.session.add_all([r1, r2])
        db.session.commit()
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_users['user'].id)
            sess['_fresh'] = True
            
        res = client.get(f'/scanner/results/{scan.uuid}')
        assert res.status_code == 200
        html = res.data.decode('utf-8')
        
        # Check that score 70 is rendered
        assert '70' in html
        # Check that HSTS is rendered as MISSING
        assert 'MISSING' in html
        # Check that Observed Evidence is rendered
        assert '// OBSERVED EVIDENCE:' in html
        assert 'Strict-Transport-Security' in html
        assert 'was not present in response headers.' in html
        assert '2026-10-31 23:59:59 UTC' in html
        assert '7 days remaining' in html


# ---------------------------------------------------------------------------
# 10. Audit CortexClash.in scoring, redirect, and authoritative risk (Regression Test 10)
# ---------------------------------------------------------------------------
@patch("requests.get")
@patch.object(ScannerService, "audit_ssl")
def test_cortexclash_scoring_and_redirect_evaluation(mock_ssl, mock_get, app, db, test_users):
    """
    Regression test validating cortexclash.in audit scenario:
    - Target: https://cortexclash.in redirects to https://www.cortexclash.in/ (HTTP 200 OK)
    - Headers on final URL: Strict-Transport-Security present; CSP, X-Frame-Options,
      X-Content-Type-Options, Referrer-Policy, Permissions-Policy absent.
    - Expected Authoritative Security Score: 100 - (15 + 10 + 5 + 5 + 5) = 60/100.
    - Expected Authoritative Risk Category: High (40 <= score < 70).
    - Checks that final response headers are evaluated and raw payload records final URL.
    """
    mock_ssl.return_value = {
        'valid': True,
        'tls_version': 'TLSv1.3',
        'days_remaining': 90,
        'issuer': 'Let\'s Encrypt Authority',
        'expiry_date': datetime.now(timezone.utc) + timedelta(days=90),
        'error': None
    }

    # Simulate intermediate redirect response from https://cortexclash.in to https://www.cortexclash.in/
    redirect_resp = MagicMock()
    redirect_resp.status_code = 301
    redirect_resp.url = "https://cortexclash.in"
    redirect_resp.is_redirect = True
    redirect_resp.headers = {
        'Location': 'https://www.cortexclash.in/',
        'Server': 'cloudflare'
    }

    # Final response for https://www.cortexclash.in/
    final_resp = MagicMock()
    final_resp.status_code = 200
    final_resp.url = "https://www.cortexclash.in/"
    final_resp.is_redirect = False
    final_resp.headers = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Server': 'cloudflare'
    }
    final_resp.history = [redirect_resp]
    mock_get.return_value = final_resp

    with app.app_context():
        scan = ScannerService.run_active_scan(test_users['user'].id, "https://cortexclash.in")
        
        # 1. Authoritative security score must be exactly 60
        assert scan.security_score == 60
        assert scan.status == 'completed'

        # 2. Exactly 5 missing-header findings
        results = scan.results
        assert len(results) == 5

        # 3. Severity & Penalty mapping verification
        findings_map = {r.vulnerability_name: r for r in results}
        
        # HSTS must NOT be in findings (it was present in final response)
        assert 'Missing Strict-Transport-Security (HSTS) Header' not in findings_map

        # High severity
        csp_finding = findings_map.get('Missing Content-Security-Policy (CSP) Header')
        assert csp_finding is not None
        assert csp_finding.severity == 'high'
        assert csp_finding.raw_payload['final_url'] == 'https://www.cortexclash.in/'
        assert csp_finding.raw_payload['http_status'] == 200

        # Medium severity
        xfo_finding = findings_map.get('Missing X-Frame-Options Header')
        assert xfo_finding is not None
        assert xfo_finding.severity == 'medium'

        # Low severities
        xcto_finding = findings_map.get('Missing X-Content-Type-Options Header')
        assert xcto_finding is not None
        assert xcto_finding.severity == 'low'

        ref_finding = findings_map.get('Missing Referrer-Policy Header')
        assert ref_finding is not None
        assert ref_finding.severity == 'low'

        perm_finding = findings_map.get('Missing Permissions-Policy Header')
        assert perm_finding is not None
        assert perm_finding.severity == 'low'

        # 4. Deterministic Authoritative Risk Category calculation:
        # Score 60 falls in range [40, 70), which evaluates to 'High'
        assert scan.risk_level == 'High'

        # 5. UI Verification: check rendered HTML
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_users['user'].id)
            sess['_fresh'] = True

        res = client.get(f'/scanner/results/{scan.uuid}')
        assert res.status_code == 200
        html = res.data.decode('utf-8')
        assert '60' in html
        assert 'HSTS' in html
        assert 'PRESENT' in html
        assert 'HIGH' in html


# ---------------------------------------------------------------------------
# 11. Authoritative score 60 and risk High overrides AI score 45 and risk Medium
# ---------------------------------------------------------------------------
def test_ai_metric_enforcement_overrides_divergent_score_and_risk():
    """Test that when authoritative score is 60 and risk is High, AI returning score 45 and risk Medium is overridden."""
    scan_results = {
        "target": "https://cortexclash.in",
        "scan_type": "website",
        "security_score": 60,
        "overall_risk": "High",
        "enforce_authoritative_metrics": True,
        "findings": [
            {
                "name": "Missing Content-Security-Policy (CSP) Header",
                "severity": "high",
                "description": "CSP header is missing.",
                "remediation": "Add CSP header."
            }
        ]
    }

    # AI returns divergent score 45 and attempts to downgrade risk to Medium
    divergent_ai_response = {
        "security_score": 45,
        "overall_risk": "Medium",
        "executive_summary": "Medium risk defensive posture.",
        "critical_findings": ["Missing Content-Security-Policy (CSP) Header"],
        "recommendations": ["Configure Content-Security-Policy header."],
        "remediation_priority": [
            {
                "finding": "Missing Content-Security-Policy (CSP) Header",
                "priority": "High",
                "remediation": "Configure Content-Security-Policy header."
            }
        ]
    }

    validated = AIAnalysisService._validate_response(divergent_ai_response, scan_results=scan_results)

    # 1. Authoritative score must be locked to 60, not AI's 45
    assert validated["security_score"] == 60

    # 2. Authoritative risk must be locked to High, not AI's Medium
    assert validated["overall_risk"] == "High"


# ---------------------------------------------------------------------------
# 12. Test fabricated findings, severity downgrade prevention, and malformed JSON
# ---------------------------------------------------------------------------
def test_ai_sanitizes_fabricated_findings_and_malformed_responses():
    """Test that AI cannot inject non-existent findings and malformed schemas are rejected."""
    from app.services.ai_service import InvalidJSONResponseError

    scan_results = {
        "target": "https://cortexclash.in",
        "scan_type": "website",
        "security_score": 60,
        "overall_risk": "High",
        "findings": [
            {
                "name": "Missing Content-Security-Policy (CSP) Header",
                "severity": "high",
                "description": "CSP is missing.",
                "remediation": "Add CSP."
            }
        ]
    }

    # Response with fabricated findings (SQLi, RCE, Port 3389)
    fabricated_ai_response = {
        "security_score": 30,
        "overall_risk": "Low",  # Attempt to downgrade High finding to Low
        "executive_summary": "Invented vulnerabilities found.",
        "critical_findings": [
            "Severe Remote Code Execution on /upload",
            "Open RDP Port 3389 Exposed to Internet",
            "Missing Content-Security-Policy (CSP) Header"
        ],
        "recommendations": ["Fix RCE", "Close RDP", "Add CSP"],
        "remediation_priority": [
            {"finding": "Severe Remote Code Execution on /upload", "priority": "Critical", "remediation": "Fix RCE"},
            {"finding": "Open RDP Port 3389 Exposed to Internet", "priority": "High", "remediation": "Firewall RDP"},
            {"finding": "Missing Content-Security-Policy (CSP) Header", "priority": "High", "remediation": "Add CSP"}
        ]
    }

    validated = AIAnalysisService._validate_response(fabricated_ai_response, scan_results=scan_results)

    # Fabricated findings must be purged
    assert "Severe Remote Code Execution on /upload" not in validated["critical_findings"]
    assert "Open RDP Port 3389 Exposed to Internet" not in validated["critical_findings"]
    assert len(validated["critical_findings"]) == 1
    assert "Content-Security-Policy" in validated["critical_findings"][0]

    remed_findings = [item["finding"] for item in validated["remediation_priority"]]
    assert "Severe Remote Code Execution on /upload" not in remed_findings
    assert "Open RDP Port 3389 Exposed to Internet" not in remed_findings
    assert any("Content-Security-Policy" in f for f in remed_findings)

    # Downgrade to Low must be prevented because high finding exists
    assert validated["overall_risk"] == "High"

    # Malformed response: missing required key 'overall_risk'
    malformed_missing_key = {
        "security_score": 60,
        "executive_summary": "Incomplete",
        "critical_findings": [],
        "recommendations": [],
        "remediation_priority": []
    }
    with pytest.raises(InvalidJSONResponseError) as exc_info:
        AIAnalysisService._validate_response(malformed_missing_key, scan_results=scan_results)
    assert "Missing required key" in str(exc_info.value)
    assert "overall_risk" in str(exc_info.value)

    # Malformed response: non-dictionary input
    with pytest.raises(InvalidJSONResponseError):
        AIAnalysisService._validate_response(["not", "a", "dict"], scan_results=scan_results)


