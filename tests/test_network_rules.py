import os
import shutil
import tempfile
import sqlite3
import json
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import pytest
import pdfplumber

from app.models.network_scan import NetworkScan, NetworkScanResult, NetworkScanEvidence
from app.services.network_rules import (
    INITIAL_RULES,
    match_port_rule,
    calculate_network_risk,
    COMMON_PORTS_STR,
    COMMON_PORTS_LIST,
    BASIS_PORT_ONLY,
    BASIS_PROBED_BANNER
)
from app.services.pdf_service import PDFGeneratorService


# ---------------------------------------------------------------------------
# 1. Table-driven test per rule (25 initial rules)
# ---------------------------------------------------------------------------
RULE_TEST_CASES = [
    # High: 14 rules
    (23, "tcp", "RULE-TELNET-23", "High"),
    (21, "tcp", "RULE-FTP-21", "High"),
    (3389, "tcp", "RULE-RDP-3389", "High"),
    (445, "tcp", "RULE-SMB-445", "High"),
    (139, "tcp", "RULE-NETBIOS-139", "High"),
    (135, "tcp", "RULE-MSRPC-135", "High"),
    (3306, "tcp", "RULE-MYSQL-3306", "High"),
    (5432, "tcp", "RULE-POSTGRES-5432", "High"),
    (1433, "tcp", "RULE-MSSQL-1433", "High"),
    (27017, "tcp", "RULE-MONGODB-27017", "High"),
    (6379, "tcp", "RULE-REDIS-6379", "High"),
    (9200, "tcp", "RULE-ELASTIC-9200", "High"),
    (11211, "tcp", "RULE-MEMCACHED-11211", "High"),
    (5900, "tcp", "RULE-VNC-5900", "High"),
    # Medium: 4 rules
    (25, "tcp", "RULE-SMTP-25", "Medium"),
    (110, "tcp", "RULE-POP3-110", "Medium"),
    (143, "tcp", "RULE-IMAP-143", "Medium"),
    (161, "udp", "RULE-SNMP-161", "Medium"),
    # Low: 5 rules
    (22, "tcp", "RULE-SSH-22", "Low"),
    (8080, "tcp", "RULE-HTTP-ALT-8080", "Low"),
    (8000, "tcp", "RULE-HTTP-ALT-8000", "Low"),
    (8443, "tcp", "RULE-HTTPS-ALT-8443", "Low"),
    (53, "tcp", "RULE-DNS-53", "Low"),
    # Informational: 2 rules
    (80, "tcp", "RULE-HTTP-80", "Informational"),
    (443, "tcp", "RULE-HTTPS-443", "Informational"),
]


@pytest.mark.parametrize("port,protocol,expected_rule_id,expected_level", RULE_TEST_CASES)
def test_initial_rules_table_driven(port, protocol, expected_rule_id, expected_level):
    """Verify each of the 25 initial rules produces expected ID, exposure level, and compliant text."""
    match = match_port_rule(port=port, protocol=protocol)
    assert match.rule_id == expected_rule_id
    assert match.exposure_level == expected_level

    # Rationale and observation must be non-empty plain-language explanations
    assert len(match.rationale.strip()) > 15
    assert len(match.observation.strip()) > 10

    # Remediation must be conditional and honest (never use 'ensure')
    assert len(match.remediation.strip()) > 15
    assert "ensure" not in match.remediation.lower()

    # Must never use the word 'vulnerability' for observed ports
    assert "vulnerabilit" not in match.rationale.lower()
    assert "vulnerabilit" not in match.remediation.lower()
    assert "vulnerabilit" not in match.observation.lower()


def test_rule_80_remediation_exact_phrasing():
    """Requirement 3: Port 80 remediation matches conditional phrasing."""
    match = match_port_rule(port=80, protocol="tcp")
    assert match.remediation == "If this host should serve only HTTPS, redirect HTTP to HTTPS."


# ---------------------------------------------------------------------------
# 2. Overall-risk function
# ---------------------------------------------------------------------------
def test_overall_risk_function_levels():
    """Requirement 4: Overall risk calculation formula."""
    # Empty / zero ports -> Low
    assert calculate_network_risk([]) == 'Low'

    # Informational counts as Low
    assert calculate_network_risk(['Informational']) == 'Low'
    assert calculate_network_risk(['Informational', 'Informational']) == 'Low'

    # Low -> Low
    assert calculate_network_risk(['Low']) == 'Low'
    assert calculate_network_risk(['Informational', 'Low']) == 'Low'

    # Medium -> Medium
    assert calculate_network_risk(['Medium']) == 'Medium'
    assert calculate_network_risk(['Informational', 'Medium']) == 'Medium'
    assert calculate_network_risk(['Low', 'Medium']) == 'Medium'

    # High -> High
    assert calculate_network_risk(['High']) == 'High'
    assert calculate_network_risk(['Informational', 'Medium', 'High']) == 'High'

    # Critical -> Critical
    assert calculate_network_risk(['Critical']) == 'Critical'
    assert calculate_network_risk(['Informational', 'High', 'Critical']) == 'Critical'

    # Inconclusive scan
    assert calculate_network_risk([], is_inconclusive=True) == 'Inconclusive'
    assert calculate_network_risk(['High'], is_inconclusive=True) == 'Inconclusive'


def test_overall_risk_function_with_objects():
    """Verify calculate_network_risk works with objects possessing severity attributes."""
    class DummyFinding:
        def __init__(self, severity, state='open'):
            self.severity = severity
            self.state = state

    f_info = DummyFinding('Informational')
    f_med = DummyFinding('Medium')
    f_high = DummyFinding('High')

    assert calculate_network_risk([f_info]) == 'Low'
    assert calculate_network_risk([f_info, f_med]) == 'Medium'
    assert calculate_network_risk([f_info, f_med, f_high]) == 'High'

    # Closed ports are ignored
    f_closed_high = DummyFinding('High', state='closed')
    assert calculate_network_risk([f_info, f_closed_high]) == 'Low'


# ---------------------------------------------------------------------------
# 3. "Port number only" wording vs "probed service banner"
# ---------------------------------------------------------------------------
def test_port_number_only_basis_wording():
    """Requirement 2: Triggered by port number alone must say 'Basis: port number only (service not verified)'."""
    # When method is None (phase 1 only)
    match_unprobed = match_port_rule(port=22, method=None)
    assert match_unprobed.basis == BASIS_PORT_ONLY
    assert "port number only" in match_unprobed.basis
    assert "port number only (service not verified)" in match_unprobed.basis

    # When method is 'table' (nmap-services mapping)
    match_table = match_port_rule(port=80, method='table')
    assert match_table.basis == BASIS_PORT_ONLY
    assert "port number only" in match_table.basis


def test_probed_service_banner_basis_wording():
    """Requirement 1: Triggered when method == 'probed' must record 'probed service banner'."""
    match_probed = match_port_rule(
        port=80,
        service_name="http",
        service_version="Apache 2.4.41",
        method="probed"
    )
    assert match_probed.basis == BASIS_PROBED_BANNER
    assert "banner probed" in match_probed.observation


# ---------------------------------------------------------------------------
# 4. Old rows still render in results page and PDF (NULL rule_id)
# ---------------------------------------------------------------------------
def test_old_rows_with_null_rule_id_render_results_page(app, db, test_users):
    """Requirement 5: Old rows with NULL rule_id keep old behavior and render on results page."""
    client = app.test_client()
    user = test_users['user']
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    scan = NetworkScan(
        user_id=user.id,
        ip_address="198.51.100.5",
        status="completed",
        scan_profile="Quick Scan",
        scanner_mode="REAL_NMAP",
        risk_level="Low",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # Result row with NULL rule columns (simulating pre-migration legacy row)
    old_result = NetworkScanResult(
        network_scan_id=scan.id,
        port=80,
        protocol="tcp",
        service_name="http",
        service_version="Unknown",
        state="open",
        severity="Low",
        remediation="Ensure HTTP traffic redirects automatically.",
        rule_id=None,
        observation=None,
        rationale=None,
        basis=None
    )
    db.session.add(old_result)
    db.session.commit()

    res = client.get(f"/scanner/network/results/{scan.uuid}")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "198.51.100.5" in html
    assert "80" in html
    assert "http" in html
    # Old row renders banner telemetry block
    assert "BANNER TELEMETRY:" in html


def test_old_rows_with_null_rule_id_render_pdf(app, db, test_users):
    """Requirement 5: Old rows with NULL rule_id still generate valid PDF reports."""
    user = test_users['user']
    scan = NetworkScan(
        user_id=user.id,
        ip_address="198.51.100.6",
        status="completed",
        scan_profile="Quick Scan",
        scanner_mode="REAL_NMAP",
        risk_level="Low",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    old_result = NetworkScanResult(
        network_scan_id=scan.id,
        port=443,
        protocol="tcp",
        service_name="https",
        service_version="Unknown",
        state="open",
        severity="Low",
        remediation="Monitor SSL configurations periodically.",
        rule_id=None,
        observation=None,
        rationale=None,
        basis=None
    )
    db.session.add(old_result)
    db.session.commit()

    report = PDFGeneratorService.generate_scan_report(user_id=user.id, scan_obj=scan)
    assert report is not None
    pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")
    assert os.path.exists(pdf_path)

    with pdfplumber.open(pdf_path) as pdf:
        text = "\n".join(p.extract_text() or "" for p in pdf.pages)
        assert "198.51.100.6" in text
        assert "443/tcp" in text
        assert "https" in text


# ---------------------------------------------------------------------------
# 5. PDF text contains rationale and never "vulnerability" for ports
# ---------------------------------------------------------------------------
def test_pdf_contains_rationale_and_no_vulnerability_for_ports(app, db, test_users):
    """Requirement 6 & 8: PDF contains the rationale per port and never 'vulnerability' for ports."""
    user = test_users['user']
    scan = NetworkScan(
        user_id=user.id,
        ip_address="198.51.100.7",
        status="completed",
        scan_profile="Service Detection",
        scanner_mode="REAL_NMAP",
        risk_level="High",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # Rule-matched result
    match_rdp = match_port_rule(port=3389, protocol="tcp", method="probed", service_name="ms-wbt-server", service_version="Windows RDP")
    res_rdp = NetworkScanResult(
        network_scan_id=scan.id,
        port=3389,
        protocol="tcp",
        service_name="ms-wbt-server",
        service_version="Windows RDP",
        state="open",
        severity=match_rdp.exposure_level,
        remediation=match_rdp.remediation,
        rule_id=match_rdp.rule_id,
        observation=match_rdp.observation,
        rationale=match_rdp.rationale,
        basis=match_rdp.basis
    )
    db.session.add(res_rdp)
    db.session.commit()

    report = PDFGeneratorService.generate_scan_report(user_id=user.id, scan_obj=scan)
    pdf_path = os.path.join(app.root_path, 'static', 'reports', f"{report.uuid}.pdf")

    with pdfplumber.open(pdf_path) as pdf:
        full_text = "\n".join(p.extract_text() or "" for p in pdf.pages)

        # 1. Rationale is present in PDF text (verified via extracted table cells)
        page1_tables = pdf.pages[0].extract_tables()
        findings_table = page1_tables[1]  # Second table on page 1 is the findings table
        rationale_cell = " ".join((findings_table[1][3] or "").split())
        assert match_rdp.rationale in rationale_cell
        assert "RULE-RDP-3389" in full_text
        assert "probed service banner" in full_text

        # 2. Methodology note is present
        assert "Methodology" in full_text
        assert "Risk Formula" in full_text

        # 3. For observed ports, 'vulnerability' must NOT be used in the findings table
        findings_table_text = " ".join(" ".join(str(c) for c in row if c) for row in findings_table).lower()
        assert "vulnerability" not in findings_table_text, "Found 'vulnerability' in ports findings table!"
        assert "vulnerabilities" not in findings_table_text, "Found 'vulnerabilities' in ports findings table!"


# ---------------------------------------------------------------------------
# 6. Migration upgrade and downgrade on temporary DB
# ---------------------------------------------------------------------------
def test_migration_upgrade_downgrade_temp_db():
    """Requirement 5 & 8: Test migration upgrade to c4d6e8f0a1b2 and downgrade to a2e4b6c8d0f1."""
    from alembic.config import Config
    from alembic import command
    from flask import Flask
    from app.extensions import db as shared_db, migrate as shared_migrate

    real_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "instance", "cyberguard.db"))
    tmp_dir = tempfile.mkdtemp()
    try:
        copy_db_path = os.path.join(tmp_dir, "migration_test.db")
        shutil.copy(real_db_path, copy_db_path)

        migrations_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "migrations"))
        alembic_cfg = Config(os.path.join(migrations_dir, "alembic.ini"))
        alembic_cfg.set_main_option("script_location", migrations_dir)
        sqlite_url = f"sqlite:///{copy_db_path.replace(os.sep, '/')}"
        alembic_cfg.set_main_option("sqlalchemy.url", sqlite_url)

        temp_app = Flask(__name__)
        temp_app.config['SQLALCHEMY_DATABASE_URI'] = sqlite_url
        shared_db.init_app(temp_app)
        shared_migrate.init_app(temp_app, shared_db)

        with temp_app.app_context():
            # 1. UPGRADE TO HEAD (c4d6e8f0a1b2)
            command.upgrade(alembic_cfg, "head")

            conn = sqlite3.connect(copy_db_path)
            cur = conn.cursor()
            cols = {row[1] for row in cur.execute("PRAGMA table_info(network_scan_results)").fetchall()}
            assert {"rule_id", "observation", "rationale", "basis"}.issubset(cols)

            rev = cur.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            assert rev == "c4d6e8f0a1b2"
            conn.close()

            # 2. DOWNGRADE TO PREVIOUS HEAD (a2e4b6c8d0f1)
            command.downgrade(alembic_cfg, "a2e4b6c8d0f1")

            conn = sqlite3.connect(copy_db_path)
            cur = conn.cursor()
            cols_down = {row[1] for row in cur.execute("PRAGMA table_info(network_scan_results)").fetchall()}
            assert "rule_id" not in cols_down
            assert "observation" not in cols_down
            assert "rationale" not in cols_down
            assert "basis" not in cols_down

            rev_down = cur.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            assert rev_down == "a2e4b6c8d0f1"
            conn.close()

            # 3. RE-UPGRADE TO HEAD
            command.upgrade(alembic_cfg, "head")
            conn = sqlite3.connect(copy_db_path)
            cur = conn.cursor()
            rev_re = cur.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            assert rev_re == "c4d6e8f0a1b2"
            conn.close()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 7. New profile "Common Ports" command line and timeouts
# ---------------------------------------------------------------------------
@patch("app.routes.network_scanner.routes.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_common_ports_profile_command_line_and_timeouts(mock_run, mock_is_nmap, app, db, test_users):
    """Requirement 7 & 8: 'Common Ports' profile runs phase 1 only, with 30s host-timeout, 45s subprocess timeout."""
    client = app.test_client()
    user = test_users['user']
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    # Mock phase 1 returning open port 22 and 80
    mock_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" version="7.94">
        <host>
            <status state="up"/>
            <ports>
                <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="table"/></port>
                <port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table"/></port>
            </ports>
        </host>
        <runstats><hosts up="1" down="0" total="1"/></runstats>
    </nmaprun>
    """
    mock_run.return_value = MagicMock(returncode=0, stdout=mock_xml, stderr="")

    res = client.post("/scanner/network/", data={
        "ip_address": "8.8.8.8",
        "scan_profile": "Common Ports",
        "scanner_mode": "REAL_NMAP"
    }, follow_redirects=True)
    assert res.status_code == 200

    scan = NetworkScan.query.filter_by(ip_address="8.8.8.8").order_by(NetworkScan.id.desc()).first()
    assert scan is not None
    assert scan.scan_profile == "Common Ports"
    assert len(scan.results) == 2

    # Find the Phase 1 Nmap scan execution call (ignoring any --version call)
    phase1_calls = [c for c in mock_run.call_args_list if "-Pn" in c[0][0]]
    assert len(phase1_calls) == 1, f"Expected exactly 1 Phase 1 discovery call, got: {phase1_calls}"

    # Verify Phase 2 (-sV) was NOT called
    assert not any("-sV" in c[0][0] for c in mock_run.call_args_list), "Phase 2 (-sV) must NOT run for Common Ports profile"

    call_args, call_kwargs = phase1_calls[0]
    cmd = call_args[0]

    # Verify command line arguments
    assert cmd[0] == "nmap"
    assert "-Pn" in cmd
    assert "-sT" in cmd
    assert "-p" in cmd
    idx_p = cmd.index("-p")
    assert cmd[idx_p + 1] == COMMON_PORTS_STR

    assert "--host-timeout" in cmd
    idx_ht = cmd.index("--host-timeout")
    assert cmd[idx_ht + 1] == "30s"

    # Verify subprocess timeout
    assert call_kwargs.get("timeout") == 45.0

    # Verify port findings have rule information populated
    port_map = {r.port: r for r in scan.results}
    assert 22 in port_map
    assert port_map[22].rule_id == "RULE-SSH-22"
    assert port_map[22].severity == "Low"
    assert "port number only" in port_map[22].basis

    assert 80 in port_map
    assert port_map[80].rule_id == "RULE-HTTP-80"
    assert port_map[80].severity == "Informational"
    assert "port number only" in port_map[80].basis
