import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
from alembic import command
from alembic.config import Config

from app import create_app
from app.extensions import db as _db
from app.models.network_scan import NetworkScan, NetworkScanResult, NetworkScanEvidence
from app.models.scan import Scan, ScanResult
from app.models.user import User
from app.services.network_scan_service import (
    NmapNetworkScannerService,
    get_nmap_version,
    reset_cached_nmap_version,
    truncate_evidence_text,
    ParsedPort
)
from app.services.scanner_service import ScannerService, sanitize_headers, redact_cookie_value
from app.services.risk_calculator import SimpleRiskCalculator
from app.services.pdf_service import PDFGeneratorService

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "nmap")


# ============================================================================
# 1. ALEMBIC MIGRATION ON DB COPY & OLD ROWS PDF TEST
# ============================================================================

def test_alembic_migration_upgrade_downgrade_and_old_rows_on_db_copy():
    """
    Apply Alembic migration to a COPY of instance/cyberguard.db first.
    Verify old rows load, verify PDF generation for old network and website scans,
    and verify downgrade / re-upgrade consistency.
    """
    real_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "instance", "cyberguard.db"))
    assert os.path.exists(real_db_path), f"Database {real_db_path} must exist"

    tmp_dir = tempfile.mkdtemp()
    try:
        copy_db_path = os.path.join(tmp_dir, "cyberguard_copy.db")
        shutil.copy(real_db_path, copy_db_path)

        # Configure Alembic pointing to copied SQLite database
        migrations_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "migrations"))
        alembic_cfg = Config(os.path.join(migrations_dir, "alembic.ini"))
        alembic_cfg.set_main_option("script_location", migrations_dir)
        # On Windows, SQLite URLs require forward slashes
        sqlite_url = f"sqlite:///{copy_db_path.replace(os.sep, '/')}"
        alembic_cfg.set_main_option("sqlalchemy.url", sqlite_url)

        from config import TestingConfig
        from flask import Flask
        from app.extensions import db as shared_db, migrate as shared_migrate

        class CopyDbTestingConfig(TestingConfig):
            SQLALCHEMY_DATABASE_URI = sqlite_url

        temp_app = Flask(__name__)
        temp_app.config.from_object(CopyDbTestingConfig)
        shared_db.init_app(temp_app)
        shared_migrate.init_app(temp_app, shared_db)

        with temp_app.app_context():
            # 1. UPGRADE TO HEAD
            command.upgrade(alembic_cfg, "head")

            conn = sqlite3.connect(copy_db_path)
            cur = conn.cursor()

            # Verify network_scan_evidence table
            tables = [row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            assert "network_scan_evidence" in tables

            # Verify columns of network_scan_evidence
            ev_cols = {row[1]: row[2] for row in cur.execute("PRAGMA table_info(network_scan_evidence)").fetchall()}
            expected_cols = {
                "id", "network_scan_id", "phase", "command", "exit_code",
                "duration_seconds", "raw_xml", "stderr", "nmap_version", "created_at"
            }
            assert expected_cols.issubset(set(ev_cols.keys()))

            # Verify index on network_scan_id
            indices = [row[1] for row in cur.execute("PRAGMA index_list(network_scan_evidence)").fetchall()]
            assert any("network_scan_id" in idx for idx in indices)

            # Verify evidence_json column on scans table
            scan_cols = {row[1] for row in cur.execute("PRAGMA table_info(scans)").fetchall()}
            assert "evidence_json" in scan_cols

            # Verify alembic_version table has head
            rev = cur.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            assert rev in ("a2e4b6c8d0f1", "c4d6e8f0a1b2")
            conn.close()

            # 2. PROVE OLD ROWS STILL LOAD AND GENERATE PDFS
            old_web_scan = Scan.query.filter_by(status='completed').first()
            assert old_web_scan is not None, "Old completed website scan should exist in copy"
            assert old_web_scan.evidence_json is None, "Old scan predates evidence storage"

            old_net_scan = NetworkScan.query.filter_by(status='completed').first()
            assert old_net_scan is not None, "Old completed network scan should exist in copy"
            assert len(old_net_scan.evidence) == 0, "Old network scan has no evidence rows"

            # Generate PDF for old website scan
            web_rep = PDFGeneratorService.generate_scan_report(
                user_id=old_web_scan.user_id,
                scan_obj=old_web_scan,
                ai_data=json.loads(old_web_scan.ai_response.response_text) if old_web_scan.ai_response else None
            )
            assert web_rep is not None
            web_pdf_path = os.path.join(temp_app.root_path, 'static', 'reports', f"{web_rep.uuid}.pdf")
            assert os.path.exists(web_pdf_path)

            # Generate PDF for old network scan
            net_rep = PDFGeneratorService.generate_scan_report(
                user_id=old_net_scan.user_id,
                scan_obj=old_net_scan,
                ai_data=json.loads(old_net_scan.ai_response.response_text) if old_net_scan.ai_response else None
            )
            assert net_rep is not None
            net_pdf_path = os.path.join(temp_app.root_path, 'static', 'reports', f"{net_rep.uuid}.pdf")
            assert os.path.exists(net_pdf_path)

            # Clean up generated test PDFs
            for p in (web_pdf_path, net_pdf_path):
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

            # 3. DOWNGRADE TO PREVIOUS HEAD (f2f9468a7a48)
            command.downgrade(alembic_cfg, "f2f9468a7a48")

            conn = sqlite3.connect(copy_db_path)
            cur = conn.cursor()
            tables_down = [row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            assert "network_scan_evidence" not in tables_down

            scan_cols_down = {row[1] for row in cur.execute("PRAGMA table_info(scans)").fetchall()}
            assert "evidence_json" not in scan_cols_down

            rev_down = cur.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            assert rev_down == "f2f9468a7a48"
            conn.close()

            # 4. RE-UPGRADE TO HEAD
            command.upgrade(alembic_cfg, "head")
            conn = sqlite3.connect(copy_db_path)
            cur = conn.cursor()
            rev_re = cur.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            assert rev_re in ("a2e4b6c8d0f1", "c4d6e8f0a1b2")
            conn.close()
        conn = sqlite3.connect(copy_db_path)
        cur = conn.cursor()
        rev_re = cur.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        assert rev_re in ("a2e4b6c8d0f1", "c4d6e8f0a1b2")
        conn.close()

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
# 2. NETWORK SCAN EVIDENCE RECORDING TESTS
# ============================================================================

def test_truncate_evidence_text_limits_to_1mb():
    """Verify evidence text truncation to maximum 1 MB (1,048,576 chars)."""
    assert truncate_evidence_text(None) is None
    short_text = "Nmap output"
    assert truncate_evidence_text(short_text) == short_text

    one_mb = 1024 * 1024
    oversized = "A" * (one_mb + 5000)
    truncated = truncate_evidence_text(oversized)
    assert len(truncated) == one_mb
    assert truncated == "A" * one_mb


def test_nmap_version_lazy_detection_success_and_cache():
    """Item 1: Verify get_nmap_version detects lazily after _ensure_nmap_on_path, caches only success."""
    import app.services.network_scan_service as nss
    nss.reset_cached_nmap_version()
    assert nss._cached_nmap_version is None

    with patch("app.services.network_scan_service._ensure_nmap_on_path") as mock_ensure, \
         patch("subprocess.run") as mock_run:
        mock_resp = MagicMock()
        mock_resp.returncode = 0
        mock_resp.stdout = "Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64\n"
        mock_run.return_value = mock_resp

        ver1 = nss.get_nmap_version()
        assert ver1 == "7.95"
        assert nss._cached_nmap_version == ver1
        mock_ensure.assert_called_once()
        assert mock_run.call_count == 1

        # Second call hits cache without calling subprocess.run again
        ver2 = nss.get_nmap_version()
        assert ver2 == ver1
        assert mock_run.call_count == 1
        assert mock_ensure.call_count == 1


def test_nmap_version_detection_failure_no_cache_retry_and_unknown_in_evidence(app, db, test_users):
    """Item 1: Verify get_nmap_version retries on failure (no None caching) and stores 'unknown' in evidence."""
    import app.services.network_scan_service as nss
    nss.reset_cached_nmap_version()
    assert nss._cached_nmap_version is None

    # Step 1: First call fails (e.g. non-zero returncode or OSError)
    with patch("subprocess.run") as mock_run:
        mock_resp = MagicMock()
        mock_resp.returncode = 1
        mock_resp.stdout = "error"
        mock_run.return_value = mock_resp

        ver_failed = nss.get_nmap_version()
        assert ver_failed is None
        # Must NOT cache None
        assert nss._cached_nmap_version is None
        assert mock_run.call_count == 1

    # Step 2: Next call retries because cache was None, and succeeds
    with patch("subprocess.run") as mock_run:
        mock_resp = MagicMock()
        mock_resp.returncode = 0
        mock_resp.stdout = "Nmap version 7.991 ( https://nmap.org )\n"
        mock_run.return_value = mock_resp

        ver_retry = nss.get_nmap_version()
        assert ver_retry == "7.991"
        assert nss._cached_nmap_version == ver_retry
        assert mock_run.call_count == 1

    # Step 3: Verify "unknown" is stored in evidence if detection fails during scan
    nss.reset_cached_nmap_version()
    scanner = nss.NmapNetworkScannerService(repository=MagicMock(), risk_calculator=MagicMock())
    scan = NetworkScan(
        ip_address='192.0.2.1',
        scan_profile='Quick Scan',
        risk_level='Low',
        user_id=test_users['user'].id,
        status='running'
    )
    db.session.add(scan)
    db.session.commit()

    scanner._record_evidence(
        scan_id=scan.id,
        phase='discovery',
        command=['nmap', '-Pn'],
        exit_code=0,
        duration_seconds=0.5,
        raw_xml='<nmaprun></nmaprun>',
        stderr='',
        nmap_version=None
    )
    ev = NetworkScanEvidence.query.filter_by(network_scan_id=scan.id).first()
    assert ev is not None
    assert ev.nmap_version == "unknown"


@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_network_scan_evidence_success_run(mock_run, mock_avail, app, db, test_users):
    """
    Test successful Service Detection scan records:
    - Phase 1 discovery evidence row
    - Phase 2 per-port evidence rows
    - Monotonic duration, exit code, command, raw_xml, and nmap_version.
    """
    discovery_xml = open(os.path.join(FIXTURES_DIR, "discovery_ok_2_open.xml")).read()
    p80_xml = open(os.path.join(FIXTURES_DIR, "sv_port80_table_only.xml")).read()
    p443_xml = open(os.path.join(FIXTURES_DIR, "sv_port443_probed.xml")).read()

    def fake_subprocess(cmd, *args, **kwargs):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stderr = ""
        cmd_str = " ".join(cmd)
        if "-p 80,443" in cmd_str or "-p 22,80,443,3389,8080" in cmd_str:
            mock_res.stdout = discovery_xml
        elif "-p 80" in cmd_str:
            mock_res.stdout = p80_xml
        elif "-p 443" in cmd_str:
            mock_res.stdout = p443_xml
        else:
            mock_res.stdout = discovery_xml
        return mock_res

    mock_run.side_effect = fake_subprocess

    repo = MagicMock()
    # Real DB persistence for scan
    def save_scan(s):
        _db.session.add(s)
        _db.session.commit()
        return s
    repo.save.side_effect = save_scan

    scanner = NmapNetworkScannerService(repo, SimpleRiskCalculator())
    scan = scanner.execute_scan(
        user_id=test_users['user'].id,
        ip_address='8.8.8.8',
        scan_profile='Service Detection',
        scanner_mode='REAL_NMAP'
    )

    assert scan.status == 'completed'
    assert len(scan.results) == 2

    # Check evidence rows in DB
    evidence_rows = NetworkScanEvidence.query.filter_by(network_scan_id=scan.id).order_by(NetworkScanEvidence.id).all()
    assert len(evidence_rows) == 3, f"Expected 1 discovery + 2 version probe rows, got {len(evidence_rows)}"

    phase1_ev = evidence_rows[0]
    assert phase1_ev.phase == 'discovery'
    assert "nmap" in phase1_ev.command
    assert phase1_ev.exit_code == 0
    assert phase1_ev.duration_seconds is not None and phase1_ev.duration_seconds >= 0.0
    assert "nmaprun" in phase1_ev.raw_xml
    assert phase1_ev.stderr == ""

    # Phase 2 port evidence rows
    p2_phases = {ev.phase: ev for ev in evidence_rows[1:]}
    assert "version:80" in p2_phases
    assert "version:443" in p2_phases

    ev_80 = p2_phases["version:80"]
    assert "-sV" in ev_80.command
    assert "-p 80" in ev_80.command
    assert ev_80.exit_code == 0
    assert "nmaprun" in ev_80.raw_xml

    ev_443 = p2_phases["version:443"]
    assert "-sV" in ev_443.command
    assert "-p 443" in ev_443.command
    assert ev_443.exit_code == 0
    assert "nmaprun" in ev_443.raw_xml


@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_network_scan_evidence_timeout_run(mock_run, mock_avail, app, db, test_users):
    """Verify Phase 1 subprocess timeout records evidence row with failed scan."""
    mock_run.side_effect = subprocess.TimeoutExpired(["nmap"], 35.0, stderr=b"Timed out after 35s")

    repo = MagicMock()
    def save_scan(s):
        _db.session.add(s)
        _db.session.commit()
        return s
    repo.save.side_effect = save_scan

    scanner = NmapNetworkScannerService(repo, SimpleRiskCalculator())
    with pytest.raises(ValueError, match="timed out"):
        scanner.execute_scan(
            user_id=test_users['user'].id,
            ip_address='8.8.8.8',
            scan_profile='Quick Scan',
            scanner_mode='REAL_NMAP'
        )

    scan = NetworkScan.query.filter_by(ip_address='8.8.8.8').first()
    assert scan is not None
    assert scan.status == 'failed'

    evidence_rows = NetworkScanEvidence.query.filter_by(network_scan_id=scan.id).all()
    assert len(evidence_rows) == 1
    ev = evidence_rows[0]
    assert ev.phase == 'discovery'
    assert ev.exit_code is None
    assert "Timed out" in ev.stderr
    assert ev.duration_seconds is not None and ev.duration_seconds >= 0.0


@patch("app.services.network_scan_service.is_nmap_available", return_value=True)
@patch("subprocess.run")
def test_network_scan_evidence_inconclusive_run(mock_run, mock_avail, app, db, test_users):
    """Verify inconclusive run (host timed out fixture) records discovery evidence row."""
    timedout_xml = open(os.path.join(FIXTURES_DIR, "sv_timedout_20s_a1.xml")).read()
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = timedout_xml
    mock_res.stderr = ""
    mock_run.return_value = mock_res

    repo = MagicMock()
    def save_scan(s):
        _db.session.add(s)
        _db.session.commit()
        return s
    repo.save.side_effect = save_scan

    scanner = NmapNetworkScannerService(repo, SimpleRiskCalculator())
    scan = scanner.execute_scan(
        user_id=test_users['user'].id,
        ip_address='8.8.8.8',
        scan_profile='Quick Scan',
        scanner_mode='REAL_NMAP'
    )

    assert scan.status == 'inconclusive'
    evidence_rows = NetworkScanEvidence.query.filter_by(network_scan_id=scan.id).all()
    assert len(evidence_rows) == 1
    ev = evidence_rows[0]
    assert ev.phase == 'discovery'
    assert ev.exit_code == 0
    assert "timedout=\"true\"" in ev.raw_xml


def test_network_scan_evidence_cascade_delete(app, db, test_users):
    """Verify cascade delete deletes evidence when scan is deleted."""
    scan = NetworkScan(
        ip_address='1.2.3.4',
        status='completed',
        scan_profile='Quick Scan',
        risk_level='Low',
        user_id=test_users['user'].id
    )
    db.session.add(scan)
    db.session.commit()

    ev = NetworkScanEvidence(
        network_scan_id=scan.id,
        phase='discovery',
        command='nmap test',
        exit_code=0
    )
    db.session.add(ev)
    db.session.commit()

    ev_id = ev.id
    assert db.session.get(NetworkScanEvidence, ev_id) is not None

    db.session.delete(scan)
    db.session.commit()
    assert db.session.get(NetworkScanEvidence, ev_id) is None


# ============================================================================
# 3. WEBSITE SCAN EVIDENCE RECORDING & COOKIE REDACTION TESTS
# ============================================================================

def test_cookie_redaction_and_sensitive_headers():
    """Verify cookie value redaction preserves name and flags while dropping auth secrets."""
    # Test cookie value redaction
    raw_cookie = "session_id=SECRET123456789; Path=/; Secure; HttpOnly; SameSite=Lax"
    redacted = redact_cookie_value(raw_cookie)
    assert redacted == "session_id=[redacted]; Path=/; Secure; HttpOnly; SameSite=Lax"

    single_cookie = "tracker=abc"
    assert redact_cookie_value(single_cookie) == "tracker=[redacted]"

    # Test sanitize_headers
    raw_headers = {
        "Content-Type": "text/html; charset=UTF-8",
        "Server": "nginx/1.18.0",
        "Set-Cookie": "auth_token=super_confidential_session_value; Path=/auth; Secure; HttpOnly",
        "Authorization": "Bearer confidential_bearer_token",
        "X-Api-Key": "confidential_api_key_value",
        "X-Secret-Header": "do_not_leak"
    }

    clean = sanitize_headers(raw_headers)
    assert clean["Content-Type"] == "text/html; charset=UTF-8"
    assert clean["Server"] == "nginx/1.18.0"
    assert clean["Set-Cookie"] == "auth_token=[redacted]; Path=/auth; Secure; HttpOnly"

    # Must NEVER store request secrets, API keys, or auth headers
    assert "Authorization" not in clean
    assert "X-Api-Key" not in clean
    assert "X-Secret-Header" not in clean


@patch("app.services.scanner_service.ScannerService.audit_ssl")
@patch("requests.get")
def test_website_scan_records_evidence_json(mock_get, mock_audit_ssl, app, db, test_users):
    """Verify run_active_scan stores sanitized evidence_json with redirect chain and SSL audit."""
    mock_audit_ssl.return_value = {
        'valid': True,
        'expiry_date': datetime(2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        'days_remaining': 150,
        'tls_version': 'TLSv1.3',
        'issuer': 'Let\'s Encrypt Authority X3',
        'error': None,
        'error_type': None,
        'control_results': {'www.google.com': True, 'www.cloudflare.com': True}
    }

    mock_history_item = MagicMock()
    mock_history_item.url = "https://example.com"
    mock_history_item.is_redirect = True
    mock_history_item.headers = {'Location': 'https://example.com/home'}

    mock_resp = MagicMock()
    mock_resp.url = "https://example.com/home"
    mock_resp.status_code = 200
    mock_resp.history = [mock_history_item]
    mock_resp.headers = {
        'Content-Type': 'text/html',
        'Server': 'Apache/2.4.41',
        'Set-Cookie': 'session=secret_token_val_999; Path=/; HttpOnly',
        'Authorization': 'Bearer confidential_user_token',
        'X-API-Key': 'confidential_key'
    }
    mock_get.return_value = mock_resp

    scan = ScannerService.run_active_scan(test_users['user'].id, "https://example.com")
    assert scan.status == 'completed'
    assert scan.evidence_json is not None

    evidence = json.loads(scan.evidence_json)
    assert evidence['final_url'] == 'https://example.com/home'
    assert evidence['status_code'] == 200
    assert evidence['redirect_chain'] == ["https://example.com"]

    # Cookie redacted, auth headers omitted
    headers = evidence['response_headers']
    assert headers['Set-Cookie'] == 'session=[redacted]; Path=/; HttpOnly'
    assert 'Authorization' not in headers
    assert 'X-API-Key' not in headers

    # SSL telemetry
    ssl_ev = evidence['audit_ssl']
    assert ssl_ev is not None
    assert ssl_ev['valid'] is True
    assert ssl_ev['tls_version'] == 'TLSv1.3'
    assert ssl_ev['tls_verified'] is True
    assert 'www.google.com' in ssl_ev['control_results']


@patch("app.services.ai_service.AIAnalysisService.analyze_scan")
@patch("app.services.scanner_service.ScannerService.audit_ssl")
@patch("requests.get")
def test_evidence_never_included_in_ai_prompts(mock_get, mock_audit_ssl, mock_analyze, app, db, test_users):
    """Assert scan evidence is never passed to AI prompts or payload."""
    mock_audit_ssl.return_value = {
        'valid': True,
        'expiry_date': datetime(2027, 1, 1, tzinfo=timezone.utc),
        'days_remaining': 100,
        'tls_version': 'TLSv1.3',
        'issuer': 'Test CA',
        'error': None,
        'error_type': None,
        'control_results': None
    }
    mock_resp = MagicMock()
    mock_resp.url = "https://example.com"
    mock_resp.status_code = 200
    mock_resp.history = []
    mock_resp.headers = {'Set-Cookie': 'token=SECRET_VALUE_123; Secure'}
    mock_get.return_value = mock_resp

    mock_analyze.return_value = {
        "_model_used": "test-model",
        "security_score": 90,
        "overall_risk": "Low",
        "executive_summary": "Test summary",
        "critical_findings": [],
        "recommendations": ["Defensive hardening"],
        "remediation_priority": []
    }

    ScannerService.run_active_scan(test_users['user'].id, "https://example.com")
    assert mock_analyze.call_count == 1
    ai_payload = mock_analyze.call_args[0][0]

    # Verify no raw evidence in payload
    assert "evidence_json" not in ai_payload
    assert "response_headers" not in ai_payload
    assert "SECRET_VALUE_123" not in str(ai_payload)


# ============================================================================
# 4. UI TEMPLATES & ACCESS CONTROL (BOLA) TESTS
# ============================================================================

def test_ui_old_rows_without_evidence_render_fallback_message(client, test_users, db):
    """Old scans without evidence render 'No evidence recorded (scan predates evidence storage)'."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Old website scan
    old_web = Scan(
        target_type='website',
        target_destination='https://old-site.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=90,
        completed_at=datetime.now(timezone.utc),
        evidence_json=None
    )
    # Old network scan
    old_net = NetworkScan(
        ip_address='10.10.10.10',
        scan_profile='Quick Scan',
        risk_level='Low',
        status='completed',
        completed_at=datetime.now(timezone.utc),
        user_id=test_users['user'].id
    )
    db.session.add_all([old_web, old_net])
    db.session.commit()

    # View website results
    res_web = client.get(f'/scanner/results/{old_web.uuid}')
    assert res_web.status_code == 200
    assert b"No evidence recorded (scan predates evidence storage)" in res_web.data

    # View network results
    res_net = client.get(f'/scanner/network/results/{old_net.uuid}')
    assert res_net.status_code == 200
    assert b"No evidence recorded (scan predates evidence storage)" in res_net.data


def test_ui_new_rows_render_evidence_and_xml_is_escaped(client, test_users, db):
    """
    New rows render evidence elements and raw XML is strictly HTML-escaped
    preventing any script/markup injection.
    """
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Network scan with malicious or unescaped XML characters
    net_scan = NetworkScan(
        ip_address='8.8.8.8',
        scan_profile='Service Detection',
        risk_level='Low',
        status='completed',
        user_id=test_users['user'].id
    )
    db.session.add(net_scan)
    db.session.commit()

    untrusted_xml = '<nmaprun><host><service name="http" product="<script>alert(1)</script>"/></host></nmaprun>'
    ev = NetworkScanEvidence(
        network_scan_id=net_scan.id,
        phase='discovery',
        command='nmap -Pn -sT -p 80,443 -oX - 8.8.8.8',
        exit_code=0,
        duration_seconds=1.45,
        raw_xml=untrusted_xml,
        nmap_version='Nmap 7.95'
    )
    db.session.add(ev)
    db.session.commit()

    res = client.get(f'/scanner/network/results/{net_scan.uuid}')
    assert res.status_code == 200
    assert b"Show raw XML" in res.data
    assert b"Nmap 7.95" in res.data
    assert b"1.45s" in res.data

    # XML must be HTML-escaped: no raw <script> in HTML stream
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in res.data
    assert b"<script>alert(1)</script>" not in res.data


def test_bola_403_for_non_owner_on_results_and_evidence(client, test_users, db):
    """Non-owners receive HTTP 403 when trying to access another user's scan results."""
    # Create scans owned by 'user'
    web_scan = Scan(
        target_type='website',
        target_destination='https://private-user-scan.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=90
    )
    net_scan = NetworkScan(
        ip_address='8.8.8.8',
        scan_profile='Quick Scan',
        risk_level='Low',
        status='completed',
        user_id=test_users['user'].id
    )
    db.session.add_all([web_scan, net_scan])
    db.session.commit()

    # Log in as a different user ('analyst')
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['analyst'].id)
        sess['_fresh'] = True

    # Attempt to view User's website scan
    res_web = client.get(f'/scanner/results/{web_scan.uuid}')
    assert res_web.status_code == 403

    # Attempt to view User's network scan
    res_net = client.get(f'/scanner/network/results/{net_scan.uuid}')
    assert res_net.status_code == 403


def test_xss_payload_in_response_header_and_fake_nmap_banner_html_escaped(client, test_users, db):
    """Item 3: Verify XSS payload in response header and in fake Nmap banner are HTML-escaped on both results pages."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    xss_payload = "<script>alert(1)</script>"

    # 1. Website scan with XSS payload in response header
    web_evidence = {
        "final_url": "https://example.com",
        "status_code": 200,
        "redirect_chain": [],
        "response_headers": {
            "Server": f"Apache/2.4 {xss_payload}",
            "X-Custom-Header": xss_payload
        },
        "audit_ssl": {"valid": True, "tls_version": "TLSv1.3", "tls_verified": True}
    }
    web_scan = Scan(
        target_type='website',
        target_destination='https://example.com',
        user_id=test_users['user'].id,
        status='completed',
        risk_score=85,
        evidence_json=json.dumps(web_evidence)
    )
    db.session.add(web_scan)
    db.session.commit()

    res_web = client.get(f'/scanner/results/{web_scan.uuid}')
    assert res_web.status_code == 200
    # Must NOT contain raw unescaped script tags
    assert b"<script>alert(1)</script>" not in res_web.data
    # Must contain HTML-escaped script tags
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in res_web.data

    # 2. Network scan with XSS payload in fake Nmap banner (service_version)
    net_scan = NetworkScan(
        ip_address='8.8.8.8',
        scan_profile='Service Detection',
        user_id=test_users['user'].id,
        status='completed',
        risk_level='Medium'
    )
    db.session.add(net_scan)
    db.session.commit()

    net_result = NetworkScanResult(
        network_scan_id=net_scan.id,
        port=8080,
        protocol='tcp',
        state='open',
        service_name='http-proxy',
        service_version=xss_payload,
        severity='Medium',
        remediation='Verify proxy configurations'
    )
    db.session.add(net_result)
    db.session.commit()

    res_net = client.get(f'/scanner/network/results/{net_scan.uuid}')
    assert res_net.status_code == 200
    # Must NOT contain raw unescaped script tag
    assert b"<script>alert(1)</script>" not in res_net.data
    # Must contain HTML-escaped script tag
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in res_net.data
