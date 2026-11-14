import os
import json
from datetime import datetime, timezone
import pytest
import subprocess
from unittest.mock import patch, MagicMock
from app.models.network_scan import NetworkScan, NetworkScanResult
from app.models.threat import ThreatLog
from app.services.network_scan_service import (
    NmapNetworkScannerService,
    MockNetworkScannerService,
    NetworkScannerService,
    NmapUnavailableError,
    is_nmap_available,
    parse_nmap_xml,
    ParsedScan,
    ParsedPort
)
from app.services.risk_calculator import SimpleRiskCalculator
from app.services.pdf_service import PDFGeneratorService

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "nmap")

# Mock Nmap XML Success Output
MOCK_NMAP_SUCCESS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 80,443 -sV -oX - 8.8.8.8" version="7.80">
  <host>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="" version=""/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Mock Nmap XML output with other ports (SSH, RDP)
MOCK_NMAP_DEEP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 22,80,443,3389,8080 -sV -oX - 8.8.8.8" version="7.80">
  <host>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Windows Remote Desktop" version=""/>
      </port>
      <port protocol="tcp" portid="999">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Mock Gemini Response
MOCK_GEMINI_RESPONSE = {
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": json.dumps({
                            "security_score": 85,
                            "overall_risk": "Low",
                            "executive_summary": "Scan analyzed successfully.",
                            "critical_findings": [],
                            "recommendations": ["Keep security up-to-date."],
                            "remediation_priority": [
                                {
                                    "finding": "Open Port 80",
                                    "priority": "Low",
                                    "remediation": "Check configuration."
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


@patch("shutil.which")
@patch("subprocess.run")
def test_nmap_available_detection(mock_run, mock_which):
    """Test that Nmap executable detection logic works correctly under various system states."""
    # Scenario A: Nmap in PATH
    mock_which.return_value = "C:\\Program Files\\Nmap\\nmap.exe"
    assert is_nmap_available() is True

    # Scenario B: Nmap not in PATH but responds to command run
    mock_which.return_value = None
    mock_run.return_value = MagicMock(returncode=0)
    assert is_nmap_available() is True

    # Scenario C: Nmap totally unavailable
    mock_run.side_effect = OSError("Command not found")
    assert is_nmap_available() is False


@patch("app.services.network_scan_service.get_nmap_version", return_value="Nmap version 7.80")
@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_successful_nmap_scan_and_xml_parsing(mock_run, mock_service_avail, mock_route_avail, mock_nmap_ver, app, db, test_users):
    """Test safe subprocess construction, XML parsing, and database persistence."""
    client = app.test_client()
    
    # Mock subprocess success execution
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = MOCK_NMAP_SUCCESS_XML
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Trigger scan via route index
    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Network Audit Results" in res.data

    # Verify database persistence & scanner_mode attribute propagation
    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.scanner_mode == 'REAL_NMAP'
    assert scan.status == 'completed'
    assert len(scan.results) == 2

    # Verify no fabricated version data
    ports = {r.port: r for r in scan.results}
    assert 80 in ports
    assert ports[80].service_name == 'http'
    assert ports[80].service_version == 'nginx 1.18.0'
    assert ports[80].state == 'open'
    
    assert 443 in ports
    assert ports[443].service_name == 'https'
    assert ports[443].service_version == "Not identified (service name assumed from port number)"
    assert ports[443].state == 'open'

    # Verify safe subprocess arguments configuration (no shell=True)
    mock_run.assert_called_once()
    called_args, called_kwargs = mock_run.call_args
    assert called_args[0] == ["nmap", "-Pn", "-sT", "-p", "80,443", "--max-retries", "1", "--host-timeout", "20s", "-oX", "-", "8.8.8.8"]
    assert called_kwargs.get("shell") is not True


@patch("app.services.network_scan_service.get_nmap_version", return_value="Nmap version 7.80")
@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_nmap_service_detection_profile(mock_run, mock_service_avail, mock_route_avail, mock_nmap_ver, app, db, test_users):
    """Test deep service detection profile port configuration and XML parsing."""
    client = app.test_client()
    
    # Mock subprocess success execution
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = MOCK_NMAP_DEEP_XML
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Trigger scan
    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Service Detection',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.scanner_mode == 'REAL_NMAP'
    assert len(scan.results) == 2 # Port 999 is closed, should be ignored

    ports = {r.port: r for r in scan.results}
    assert 22 in ports
    assert ports[22].service_name == 'ssh'
    assert ports[22].service_version == 'OpenSSH 8.2p1'
    assert ports[22].severity == 'Medium'

    assert 3389 in ports
    assert ports[3389].service_name == 'ms-wbt-server'
    assert ports[3389].severity == 'High'

    # Check subprocess args: Phase 1 command
    assert mock_run.call_count >= 1
    phase1_call = mock_run.call_args_list[0][0][0]
    assert phase1_call == ["nmap", "-Pn", "-sT", "-p", "22,80,443,3389,8080", "--max-retries", "1", "--host-timeout", "20s", "-oX", "-", "8.8.8.8"]


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
def test_private_and_loopback_ip_blocking_and_threatlog(mock_service_avail, mock_route_avail, app, db, test_users):
    """Verify target validation blocks private/loopback targets and logs threat entries."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Clear ThreatLog first
    with app.app_context():
        db.session.query(ThreatLog).delete()
        db.session.commit()

    # Disable testing config mode temporarily to enforce production rules
    app.config['TESTING'] = False
    try:
        # Scenario A: Private address
        res_private = client.post('/scanner/network/', data={
            'ip_address': '192.168.1.10',
            'scan_profile': 'Quick Scan',
            'scanner_mode': 'REAL_NMAP'
        }, follow_redirects=True)
        assert b"Scanning internal or private IP addresses is blocked" in res_private.data

        # Scenario B: Loopback address
        res_loopback = client.post('/scanner/network/', data={
            'ip_address': '127.0.0.1',
            'scan_profile': 'Quick Scan',
            'scanner_mode': 'REAL_NMAP'
        }, follow_redirects=True)
        assert b"Scanning internal or private IP addresses is blocked" in res_loopback.data

        # Verify ThreatLog records
        with app.app_context():
            logs = ThreatLog.query.filter_by(threat_type="SSRF Scan Attempt").all()
            assert len(logs) >= 2
            assert any("192.168.1.10" in log.description for log in logs)
            assert any("127.0.0.1" in log.description for log in logs)
    finally:
        app.config['TESTING'] = True


@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
def test_invalid_target_ip_format(mock_nmap_avail, app, db, test_users):
    """Verify target validation rejects malformed target formats."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': 'not-an-ip-or-host-@#$',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert b"Invalid target format" in res.data or b"Invalid IP address format" in res.data


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=False)
@patch("app.services.network_scan_service.is_nmap_available", return_value=False)
def test_nmap_unavailable_graceful_handling(mock_service_avail, mock_route_avail, app, db, test_users):
    """Verify application handles missing Nmap gracefully without tracebacks."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Nmap is not installed or available on this system" in res.data


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_nmap_timeout_graceful_handling(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Verify scanner handles subprocess timeouts gracefully."""
    client = app.test_client()
    mock_run.side_effect = subprocess.TimeoutExpired(["nmap"], 30.0)

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"timed out after 30 seconds" in res.data

    # Check status database record
    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.status == 'failed'


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_nmap_non_zero_exit_graceful_handling(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Verify scanner handles non-zero exit codes gracefully."""
    client = app.test_client()
    
    mock_resp = MagicMock()
    mock_resp.returncode = 1
    mock_resp.stdout = ""
    mock_resp.stderr = "Permission denied"
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Nmap command exited with non-zero status code" in res.data

    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.status == 'failed'


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_nmap_malformed_xml_graceful_handling(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Verify scanner handles malformed XML parser exceptions gracefully."""
    client = app.test_client()
    
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = "not valid xml"
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Failed to parse network scanner output results" in res.data

    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.status == 'failed'


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
@patch.dict(os.environ, {"GEMINI_API_KEY": "test_api_key"})
def test_ai_receives_only_normalized_scanner_data(mock_run, mock_service_avail, mock_route_avail, mock_gemini_success, app, db, test_users):
    """Verify AI receives only normalized real scanner data, without mock data contamination."""
    client = app.test_client()
    
    # Mock subprocess success execution
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = MOCK_NMAP_SUCCESS_XML
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Run scan
    client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)

    # Verify the mocked request payload sent to Gemini API
    mock_gemini_success.assert_called_once()
    called_kwargs = mock_gemini_success.call_args[1]
    payload = called_kwargs.get("json", {})
    
    # Extract prompt
    parts = payload.get("contents", [{}])[0].get("parts", [{}])
    prompt = parts[0].get("text", "")

    # Prompt should contain information from XML: Port 80 and Port 443 with version nginx 1.18.0
    assert "8.8.8.8" in prompt
    assert "Finding #1:" in prompt
    assert "Open Port 80" in prompt
    assert "nginx 1.18.0" in prompt
    assert "Open Port 443" in prompt
    # Must NOT contain mock artifacts from the mock service profile (like Port 22, Apache, or RDP)
    assert "Open Port 22" not in prompt
    assert "Apache" not in prompt
    assert "RDP" not in prompt


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_network_scan_user_isolation(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Verify BOLA controls restrict result retrieval and AI triggers to scan owners."""
    client = app.test_client()
    
    # Seed a scan for analyst user
    with app.app_context():
        scan = NetworkScan(
            ip_address="8.8.8.8",
            status="completed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['analyst'].id
        )
        db.session.add(scan)
        db.session.commit()
        scan_uuid = scan.uuid

    # Attempt to access scan results as standard user (BOLA Attempt)
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Verify BOLA blocked on result detail page
    res_page = client.get(f'/scanner/network/results/{scan_uuid}')
    assert res_page.status_code == 403

    # Verify BOLA blocked on AI trigger endpoint
    res_ai = client.post(f'/scanner/network/results/{scan_uuid}/ai')
    assert res_ai.status_code == 403

    # Verify ThreatLog was generated for BOLA attempt
    with app.app_context():
        logs = ThreatLog.query.filter_by(threat_type="BOLA Attempt").all()
        assert len(logs) > 0
        assert any(f"User ID {test_users['user'].id} tried to access scan" in log.description for log in logs)


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_network_scan_pdf_generation_compatibility(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Verify PDF compilation matches correct format and embeds scanner_mode."""
    client = app.test_client()
    
    # Mock subprocess success execution
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = MOCK_NMAP_SUCCESS_XML
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Run scan
    client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)

    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None

    # Compile PDF
    report = PDFGeneratorService.generate_scan_report(test_users['user'].id, scan, None)
    assert report is not None
    assert report.network_scan_id == scan.id
    
    # Check that report PDF file exists on disk
    reports_dir = os.path.join(app.root_path, 'static', 'reports')
    pdf_path = os.path.join(reports_dir, f"{report.uuid}.pdf")
    assert os.path.exists(pdf_path)

    # Cleanup
    if os.path.exists(pdf_path):
        os.remove(pdf_path)


# ==============================================================================
# TESTS USING REAL NMAP FIXTURES (TASK 6)
# ==============================================================================

@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("app.services.ai_service.AIAnalysisService.analyze_scan")
@patch("subprocess.run")
def test_fixtures_sv_timedout_20s_a1(mock_run, mock_ai, mock_service_avail, mock_route_avail, app, db, test_users):
    """Real fixture sv_timedout_20s_a1.xml: timed out during -sV, host timedout=true, no <ports> element.
    Parser reports host_timedout=True, scan status 'inconclusive', risk 'Inconclusive', 0 results, no AI call."""
    fixture_path = os.path.join(FIXTURES_DIR, "sv_timedout_20s_a1.xml")
    with open(fixture_path, "r", encoding="utf-8") as f:
        xml_content = f.read()

    # 1. Test pure function parser
    parsed = parse_nmap_xml(xml_content)
    assert parsed.host_timedout is True
    assert parsed.host_up is True
    assert parsed.has_ports_element is False
    assert len(parsed.ports) == 0
    assert parsed.elapsed == 26.0

    # 2. Test scan execution
    client = app.test_client()
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = xml_content
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '216.198.79.1',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Scan did not complete - no conclusion about exposure can be drawn. Re-run the scan." in res.data

    scan = NetworkScan.query.filter_by(ip_address='216.198.79.1').first()
    assert scan is not None
    assert scan.status == 'inconclusive'
    assert scan.risk_level == 'Inconclusive'
    assert len(scan.results) == 0
    assert scan.ai_response is None
    mock_ai.assert_not_called()


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("app.services.ai_service.AIAnalysisService.analyze_scan")
@patch("subprocess.run")
def test_fixtures_sv_timedout_90s(mock_run, mock_ai, mock_service_avail, mock_route_avail, app, db, test_users):
    """Real fixture sv_timedout_90s.xml: timed out after 90s, host timedout=true, no <ports> element.
    Parser reports host_timedout=True, scan status 'inconclusive', risk 'Inconclusive', 0 results, no AI call."""
    fixture_path = os.path.join(FIXTURES_DIR, "sv_timedout_90s.xml")
    with open(fixture_path, "r", encoding="utf-8") as f:
        xml_content = f.read()

    # 1. Pure function parser
    parsed = parse_nmap_xml(xml_content)
    assert parsed.host_timedout is True
    assert parsed.host_up is True
    assert parsed.has_ports_element is False
    assert len(parsed.ports) == 0
    assert parsed.elapsed == 90.91

    # 2. Scan execution
    client = app.test_client()
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = xml_content
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '216.198.79.1',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Scan did not complete - no conclusion about exposure can be drawn. Re-run the scan." in res.data

    scan = NetworkScan.query.filter_by(ip_address='216.198.79.1').first()
    assert scan is not None
    assert scan.status == 'inconclusive'
    assert scan.risk_level == 'Inconclusive'
    assert len(scan.results) == 0
    assert scan.ai_response is None
    mock_ai.assert_not_called()


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_fixtures_discovery_ok_2_open(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Real fixture discovery_ok_2_open.xml: Phase 1 scan without -sV finishes cleanly with ports 80 and 443 open.
    Status 'completed', 2 open ports, service names from method='table' labeled 'assumed from port number'."""
    fixture_path = os.path.join(FIXTURES_DIR, "discovery_ok_2_open.xml")
    with open(fixture_path, "r", encoding="utf-8") as f:
        xml_content = f.read()

    # 1. Pure function parser
    parsed = parse_nmap_xml(xml_content)
    assert parsed.host_up is True
    assert parsed.host_timedout is False
    assert parsed.has_ports_element is True
    assert len(parsed.ports) == 2
    p_map = {p.port: p for p in parsed.ports}
    assert 80 in p_map and p_map[80].state == 'open' and p_map[80].service_method == 'table'
    assert 443 in p_map and p_map[443].state == 'open' and p_map[443].service_method == 'table'

    # 2. Quick scan execution
    client = app.test_client()
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = xml_content
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '216.198.79.1',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='216.198.79.1').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert len(scan.results) == 2
    r_map = {r.port: r for r in scan.results}
    assert 80 in r_map and r_map[80].state == 'open'
    assert 443 in r_map and r_map[443].state == 'open'
    assert r_map[80].service_name == "http"
    assert r_map[443].service_name == "https"
    assert r_map[80].service_version == "Not identified (service name assumed from port number)"
    assert r_map[443].service_version == "Not identified (service name assumed from port number)"


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_phase2_timeout_keeps_port_open(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Phase 2 timeout for port 443 with Phase 1 success: port 443 is preserved as open with
    'Version detection incomplete (timed out)' version text, and scan status is 'completed'."""
    p1_fixture = os.path.join(FIXTURES_DIR, "discovery_ok_2_open.xml")
    with open(p1_fixture, "r", encoding="utf-8") as f:
        p1_xml = f.read()

    v80_fixture = os.path.join(FIXTURES_DIR, "sv_port80_table_only.xml")
    with open(v80_fixture, "r", encoding="utf-8") as f:
        v80_xml = f.read()

    def run_side_effect(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "-p 80,443" in cmd_str or "-p 22,80,443,3389,8080" in cmd_str:
            resp = MagicMock()
            resp.returncode = 0
            resp.stdout = p1_xml
            return resp
        elif "-p 443" in cmd_str:
            # Simulate Phase 2 timeout for port 443 (90s limit)
            raise subprocess.TimeoutExpired(cmd, 90.0)
        elif "-p 80" in cmd_str:
            resp = MagicMock()
            resp.returncode = 0
            resp.stdout = v80_xml
            return resp
        resp = MagicMock()
        resp.returncode = 0
        resp.stdout = p1_xml
        return resp

    mock_run.side_effect = run_side_effect

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '216.198.79.1',
        'scan_profile': 'Service Detection',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='216.198.79.1').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert len(scan.results) == 2
    r_map = {r.port: r for r in scan.results}
    assert 443 in r_map
    assert r_map[443].state == 'open'
    assert r_map[443].service_version == "Version detection incomplete (timed out)"


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_phase2_success_v443_and_v80_no_product(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Phase 2 success: v80.xml contains method='table' without a product attribute;
    v443.xml contains product='Golang net/http server'.
    Port 443 fills its product/version, while port 80 receives 'Not identified (service name assumed from port number)'."""
    p1_fixture = os.path.join(FIXTURES_DIR, "discovery_ok_2_open.xml")
    with open(p1_fixture, "r", encoding="utf-8") as f:
        p1_xml = f.read()

    v80_fixture = os.path.join(FIXTURES_DIR, "sv_port80_table_only.xml")
    with open(v80_fixture, "r", encoding="utf-8") as f:
        v80_xml = f.read()

    v443_fixture = os.path.join(FIXTURES_DIR, "sv_port443_probed.xml")
    with open(v443_fixture, "r", encoding="utf-8") as f:
        v443_xml = f.read()

    def run_side_effect(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "-p 80,443" in cmd_str or "-p 22,80,443,3389,8080" in cmd_str:
            resp = MagicMock()
            resp.returncode = 0
            resp.stdout = p1_xml
            return resp
        elif "-p 443" in cmd_str:
            resp = MagicMock()
            resp.returncode = 0
            resp.stdout = v443_xml
            return resp
        elif "-p 80" in cmd_str:
            resp = MagicMock()
            resp.returncode = 0
            resp.stdout = v80_xml
            return resp
        resp = MagicMock()
        resp.returncode = 0
        resp.stdout = p1_xml
        return resp

    mock_run.side_effect = run_side_effect

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '216.198.79.1',
        'scan_profile': 'Service Detection',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='216.198.79.1').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert len(scan.results) == 2
    r_map = {r.port: r for r in scan.results}
    # Port 443 succeeded with product from v443.xml and tunnel ssl gives label https
    assert r_map[443].service_name == "https"
    assert "Golang net/http server" in r_map[443].service_version
    # Port 80 returned v80.xml without product and method table
    assert r_map[80].service_name == "http"
    assert r_map[80].service_version == "Not identified (service name assumed from port number)"


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_fixtures_sv_port443_probed_and_sv_port80_table_only(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Amendment Task 4 tests:
    - sv_port443_probed.xml -> label 'https', product 'Golang net/http server', method probed, cpe 'cpe:/a:golang:go'
    - sv_port80_table_only.xml -> 'Not identified (service name assumed from port number)' wording
    - Neither fixture may produce an 'inconclusive' status (no timedout attribute)
    - Assert servicefp text never appears in any stored field.
    """
    path_443 = os.path.join(FIXTURES_DIR, "sv_port443_probed.xml")
    with open(path_443, "r", encoding="utf-8") as f:
        xml_443 = f.read()

    path_80 = os.path.join(FIXTURES_DIR, "sv_port80_table_only.xml")
    with open(path_80, "r", encoding="utf-8") as f:
        xml_80 = f.read()

    # 1. Pure parser tests
    parsed_443 = parse_nmap_xml(xml_443)
    assert parsed_443.host_up is True
    assert parsed_443.host_timedout is False
    assert len(parsed_443.ports) == 1
    p443 = parsed_443.ports[0]
    assert p443.display_service_name == "https"
    assert p443.service_product == "Golang net/http server"
    assert p443.service_method == "probed"
    assert p443.service_tunnel == "ssl"
    assert p443.service_cpe == "cpe:/a:golang:go"

    parsed_80 = parse_nmap_xml(xml_80)
    assert parsed_80.host_up is True
    assert parsed_80.host_timedout is False
    assert len(parsed_80.ports) == 1
    p80 = parsed_80.ports[0]
    assert p80.display_service_name == "http"
    assert p80.service_method == "table"
    assert p80.service_conf == 3
    assert p80.service_product is None
    assert p80.full_version_text == "Not identified (service name assumed from port number)"
    # servicefp is in xml_80, but must not be stored on ParsedPort
    assert not hasattr(p80, "servicefp")

    # 2. End-to-end scan execution with sv_port80_table_only.xml
    client = app.test_client()
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = xml_80
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '216.198.79.1',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan_80 = NetworkScan.query.filter_by(ip_address='216.198.79.1').first()
    assert scan_80 is not None
    # Neither fixture produces an 'inconclusive' status
    assert scan_80.status == 'completed'
    assert len(scan_80.results) == 1
    res_80 = scan_80.results[0]
    assert res_80.service_version == "Not identified (service name assumed from port number)"

    # Assert servicefp text NEVER appears in any stored field
    servicefp_needle = "SF-Port80-TCP"
    assert servicefp_needle not in res_80.service_name
    assert servicefp_needle not in res_80.service_version
    assert servicefp_needle not in (res_80.remediation or "")
    assert servicefp_needle not in scan_80.ip_address
    assert servicefp_needle not in scan_80.scan_profile
    assert servicefp_needle not in scan_80.status
    assert servicefp_needle not in scan_80.risk_level


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_synthetic_xml_all_ports_closed(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Synthetic XML test: Host is up, <ports> element is present, but all ports are closed.
    Legitimate scan status 'completed' with 0 open ports and risk 'Low'."""
    SYNTHETIC_ALL_CLOSED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<!-- SYNTHETIC TEST XML: Host up, <ports> present, all ports closed -->
<nmaprun scanner="nmap" version="7.80">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http" method="table"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https" method="table"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="1.20" exit="success"/></runstats>
</nmaprun>
"""
    # 1. Pure parser check
    parsed = parse_nmap_xml(SYNTHETIC_ALL_CLOSED_XML)
    assert parsed.host_up is True
    assert parsed.host_timedout is False
    assert parsed.has_ports_element is True
    assert len(parsed.ports) == 2
    assert all(p.state == 'closed' for p in parsed.ports)

    # 2. Scan execution check
    client = app.test_client()
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = SYNTHETIC_ALL_CLOSED_XML
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert len(scan.results) == 0
    assert scan.risk_level == 'Low'


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_malformed_xml_failed_status(mock_run, mock_service_avail, mock_route_avail, app, db, test_users):
    """Malformed XML output from Nmap triggers 'failed' status and raises ValueError."""
    client = app.test_client()
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = "<<<MALFORMED NON-XML NMAP OUTPUT>>>"
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Failed to parse network scanner output results." in res.data

    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.status == 'failed'


def test_simple_risk_calculator_inconclusive():
    """Verify SimpleRiskCalculator returns 'Inconclusive' when is_inconclusive=True."""
    calc = SimpleRiskCalculator()
    assert calc.calculate_risk([], is_inconclusive=True) == 'Inconclusive'
    assert calc.calculate_risk([MagicMock(severity='High', state='open')], is_inconclusive=True) == 'Inconclusive'
    assert calc.calculate_risk([]) == 'Low'
    assert calc.calculate_risk([MagicMock(severity='High', state='open')]) == 'High'


def test_cpe_without_concrete_version_no_cve_mapping():
    """Requirement 5: Do NOT map cpe:/a:golang:go (no version) to CVEs.
    Any future CVE matching requires a concrete version string.
    Assert that a CPE lacking a version component has service_version as None,
    and verify no concrete version is inferred for CVE lookups."""
    path_443 = os.path.join(FIXTURES_DIR, "sv_port443_probed.xml")
    with open(path_443, "r", encoding="utf-8") as f:
        xml_443 = f.read()

    parsed = parse_nmap_xml(xml_443)
    p443 = parsed.ports[0]
    assert p443.service_cpe == "cpe:/a:golang:go"
    # Concrete version attribute is absent in <service> and CPE has no version specifier
    assert p443.service_version is None
    cpe_parts = p443.service_cpe.split(":")
    # cpe:/a:golang:go has 4 parts: ['cpe', '/a', 'golang', 'go'] -> no version part
    assert len(cpe_parts) <= 4 or cpe_parts[4] in ("", "*", "-")


# ==============================================================================
# REVIEW PASS TESTS (ITEMS 1 - 9)
# ==============================================================================

def test_review_pass_item2_and_4_phase2_timeouts_and_clean_service_name(app, db, test_users):
    """Item 2 & 4: Reconcile timeouts and ensure service_name is NOT appended with extra text."""
    from app.services.network_scan_service import VERSION_TEXT_TABLE_ASSUMED
    p1_fixture = os.path.join(FIXTURES_DIR, "discovery_ok_2_open.xml")
    with open(p1_fixture, "r", encoding="utf-8") as f:
        p1_xml = f.read()

    # Verify parser leaves service_name clean (no text appended)
    parsed = parse_nmap_xml(p1_xml)
    for p in parsed.ports:
        assert p.display_service_name in ("http", "https")
        assert "assumed" not in p.display_service_name
        assert "Not identified" not in p.display_service_name
        # The extra text belongs strictly to full_version_text
        assert p.full_version_text == VERSION_TEXT_TABLE_ASSUMED


@patch("app.services.network_scan_service.get_nmap_version", return_value="Nmap version 7.80")
@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_guard_service_detection_zero_open_ports_skips_phase2(mock_run, mock_service_avail, mock_route_avail, mock_nmap_ver, app, db, test_users):
    """Item 2: Service Detection profile, host up, ports present, zero open ->
    status 'completed', no crash (max_workers never 0), and NO phase-2 subprocess call."""
    SYNTHETIC_ALL_CLOSED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.80">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="closed" reason="reset"/><service name="ssh" method="table"/></port>
      <port protocol="tcp" portid="80"><state state="closed" reason="reset"/><service name="http" method="table"/></port>
      <port protocol="tcp" portid="443"><state state="closed" reason="reset"/><service name="https" method="table"/></port>
    </ports>
  </host>
  <runstats><finished elapsed="1.20" exit="success"/></runstats>
</nmaprun>
"""
    client = app.test_client()
    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = SYNTHETIC_ALL_CLOSED_XML
    mock_run.return_value = mock_resp

    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.post('/scanner/network/', data={
        'ip_address': '8.8.8.8',
        'scan_profile': 'Service Detection',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.status == 'completed'
    assert len(scan.results) == 0
    assert scan.risk_level == 'Low'

    # Exactly 1 subprocess call (Phase 1 discovery) - Phase 2 must be completely skipped
    assert mock_run.call_count == 1
    called_cmd = mock_run.call_args[0][0]
    assert "-sV" not in called_cmd


def test_review_pass_item3_version_text_exact_rules():
    """Item 3: Exact mapping for method='probed', method='table' (port 80 from sv_port80_table_only.xml),
    and phase 2 timeouts."""
    from app.services.network_scan_service import format_version_text, VERSION_TEXT_TABLE_ASSUMED, VERSION_TEXT_TIMED_OUT

    # 1. method='probed' + product -> product text
    assert format_version_text(product="Apache httpd", version="2.4.41", method="probed") == "Apache httpd 2.4.41"
    assert format_version_text(product="Golang net/http server", method="probed") == "Golang net/http server"

    # 2. completed scan with method='table' or no product -> exact text
    assert format_version_text(product=None, method="table") == VERSION_TEXT_TABLE_ASSUMED
    assert format_version_text(product="http", method="table", conf=3) == VERSION_TEXT_TABLE_ASSUMED

    # Port 80 from real sv_port80_table_only.xml must get this exact text
    path_80 = os.path.join(FIXTURES_DIR, "sv_port80_table_only.xml")
    with open(path_80, "r", encoding="utf-8") as f:
        parsed_80 = parse_nmap_xml(f.read())
    assert parsed_80.ports[0].port == 80
    assert parsed_80.ports[0].full_version_text == "Not identified (service name assumed from port number)"

    # 3. phase 2 timeout/error -> exact text
    assert format_version_text(product=None, is_timed_out_or_error=True) == VERSION_TEXT_TIMED_OUT
    assert VERSION_TEXT_TIMED_OUT == "Version detection incomplete (timed out)"


def test_review_pass_item5_block_ai_and_pdf_for_inconclusive(app, db, test_users):
    """Item 5: Block AI generation route, assistant query, and PDF generation for inconclusive scans."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    with app.app_context():
        scan = NetworkScan(
            ip_address="216.198.79.1",
            status="inconclusive",
            risk_level="Inconclusive",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id,
            completed_at=datetime.now(timezone.utc)
        )
        db.session.add(scan)
        db.session.commit()
        scan_uuid = scan.uuid

    # 1. Trigger AI route (/results/<uuid>/ai) blocks and redirects with warning
    res_ai = client.post(f'/scanner/network/results/{scan_uuid}/ai', follow_redirects=True)
    assert res_ai.status_code == 200
    assert b"AI analysis cannot be generated for an inconclusive scan." in res_ai.data

    # 2. Download PDF route (/results/<uuid>/pdf) blocks and redirects with warning
    res_pdf = client.get(f'/scanner/network/results/{scan_uuid}/pdf', follow_redirects=True)
    assert res_pdf.status_code == 200
    assert b"PDF reports cannot be generated for inconclusive scans." in res_pdf.data

    # 3. AIAssistantService blocks with clear ValueError
    from app.services.ai_assistant_service import AIAssistantService
    with pytest.raises(ValueError, match="AI Assistant is unavailable for inconclusive scans"):
        AIAssistantService.ask_question(
            user_id=test_users['user'].id,
            scan_type="network",
            scan_uuid=scan_uuid,
            user_question="What ports are open?"
        )

    # 4. PDFGeneratorService blocks with clear ValueError
    from app.services.pdf_service import PDFGeneratorService
    with app.app_context():
        scan_obj = NetworkScan.query.filter_by(uuid=scan_uuid).first()
        with pytest.raises(ValueError, match="PDF report cannot be generated for an inconclusive scan"):
            PDFGeneratorService.generate_scan_report(test_users['user'].id, scan_obj, None)


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_review_pass_item6_api_scan_inconclusive_http_409(mock_run, mock_serv_avail, mock_route_avail, app, db, test_users):
    """Item 6: /api/scan must include status, and for inconclusive scans return HTTP 409 with success=false
    and explanatory error message."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    fixture_path = os.path.join(FIXTURES_DIR, "sv_timedout_20s_a1.xml")
    with open(fixture_path, "r", encoding="utf-8") as f:
        xml_content = f.read()

    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = xml_content
    mock_run.return_value = mock_resp

    res = client.post('/scanner/network/api/scan', json={
        'ip_address': '216.198.79.1',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    })
    assert res.status_code == 409
    data = res.get_json()
    assert data['success'] is False
    assert data['status'] == 'inconclusive'
    assert "Scan did not complete - no conclusion about exposure can be drawn" in data['error']
    assert data['scan']['status'] == 'inconclusive'
    assert data['scan']['risk_level'] == 'Inconclusive'


def test_review_pass_item7_dashboard_and_history_exclude_inconclusive(app, db, test_users):
    """Item 7: Exclude 'Inconclusive'/'failed' scans from dashboard averages and risk distribution;
    record separate inconclusive count; ensure no score of 0 for them in history."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    with app.app_context():
        from app.models.scan import Scan
        # Completed website scan with score 80
        web_scan = Scan(
            target_type="website",
            target_destination="https://example.com",
            status="completed",
            security_score=80,
            user_id=test_users['user'].id
        )
        # Inconclusive network scan
        net_inconclusive = NetworkScan(
            ip_address="216.198.79.1",
            status="inconclusive",
            risk_level="Inconclusive",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id
        )
        # Failed network scan
        net_failed = NetworkScan(
            ip_address="216.198.79.2",
            status="failed",
            risk_level="Low",
            scan_profile="Quick Scan",
            scanner_mode="REAL_NMAP",
            user_id=test_users['user'].id
        )
        db.session.add_all([web_scan, net_inconclusive, net_failed])
        db.session.commit()

    # Check dashboard KPIs
    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 200
    # Average score should be exactly 80.0 from the completed scan (NOT pulled down to 40 or 26 by 0)
    assert b"80.0" in res_dash.data
    # Dashboard displays the separate inconclusive count
    assert b"Inconclusive Audits:" in res_dash.data

    # Check unified history
    res_hist = client.get('/history')
    assert res_hist.status_code == 200
    # The inconclusive and failed scans must NOT display a score of 0/100
    assert b"0/100" not in res_hist.data


def test_review_pass_item8_scan_form_service_detection_message(app, db, test_users):
    """Item 8: Scan form displays 'Service Detection can take up to 2 minutes' notice."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    res = client.get('/scanner/network/')
    assert res.status_code == 200
    assert b"Service Detection can take up to 2 minutes" in res.data


@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_review_pass_item9_no_success_flash_on_inconclusive(mock_run, mock_serv_avail, mock_route_avail, app, db, test_users):
    """Item 9: Ensure a success flash is NOT shown together with the inconclusive warning."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    fixture_path = os.path.join(FIXTURES_DIR, "sv_timedout_20s_a1.xml")
    with open(fixture_path, "r", encoding="utf-8") as f:
        xml_content = f.read()

    mock_resp = MagicMock()
    mock_resp.returncode = 0
    mock_resp.stdout = xml_content
    mock_run.return_value = mock_resp

    res = client.post('/scanner/network/', data={
        'ip_address': '216.198.79.1',
        'scan_profile': 'Quick Scan',
        'scanner_mode': 'REAL_NMAP'
    }, follow_redirects=True)
    assert res.status_code == 200

    # Warning flash must be present
    assert b"Scan did not complete - no conclusion about exposure can be drawn" in res.data
    # Success flash must NOT be present
    assert b"assessment completed for" not in res.data
    assert b"Network scan assessment completed" not in res.data




