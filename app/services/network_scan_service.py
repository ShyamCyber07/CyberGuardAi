import shutil
import subprocess
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import socket
import logging
import concurrent.futures
import time
from typing import List, Optional, Tuple

from app.models.network_scan import NetworkScan, NetworkScanResult, NetworkScanEvidence
from app.repositories.network_scan_repository import NetworkScanRepositoryInterface
from app.services.risk_calculator import RiskCalculatorInterface

logger = logging.getLogger(__name__)

MAX_EVIDENCE_TEXT_LENGTH = 1024 * 1024  # 1 MB


def truncate_evidence_text(text: Optional[str]) -> Optional[str]:
    """Truncate evidence text to maximum 1 MB (1,048,576 chars)."""
    if text is None:
        return None
    if len(text) > MAX_EVIDENCE_TEXT_LENGTH:
        return text[:MAX_EVIDENCE_TEXT_LENGTH]
    return text


class NmapUnavailableError(ValueError):
    """Exception raised when Nmap is not installed or available in the system PATH."""
    pass


class VersionStatus(str, Enum):
    """Enumeration of version detection outcome states."""
    PROBED = "probed"
    TABLE_ASSUMED = "table_assumed"
    TIMED_OUT = "timed_out"


VERSION_TEXT_TABLE_ASSUMED = "Not identified (service name assumed from port number)"
VERSION_TEXT_TIMED_OUT = "Version detection incomplete (timed out)"


def format_version_text(
    product: Optional[str],
    version: Optional[str] = None,
    extrainfo: Optional[str] = None,
    method: Optional[str] = None,
    conf: Optional[int] = None,
    is_timed_out_or_error: bool = False
) -> str:
    """Format service_version according to amendment specifications:
    - phase-2 run timed out or errored -> 'Version detection incomplete (timed out)'
    - method == 'probed' and product present -> product [+ version] [+ extrainfo]
    - method == 'table' (conf <= 3) or no product -> 'Not identified (service name assumed from port number)'
    """
    if is_timed_out_or_error:
        return VERSION_TEXT_TIMED_OUT

    if (method == "probed" or (method is None and product)) and product:
        parts = [p for p in [product, version, extrainfo] if p]
        version_str = " ".join(parts).strip() if parts else product
        return version_str[:100]

    return VERSION_TEXT_TABLE_ASSUMED


@dataclass
class ParsedPort:
    port: int
    protocol: str = 'tcp'
    state: str = 'unknown'
    service_name: str = 'unknown'
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extrainfo: Optional[str] = None
    service_tunnel: Optional[str] = None
    service_method: Optional[str] = None
    service_conf: Optional[int] = None
    service_cpe: Optional[str] = None

    @property
    def display_service_name(self) -> str:
        """Display label following Nmap convention:
        if tunnel == 'ssl' and name == 'http' use 'https';
        otherwise if tunnel is set use f'{tunnel}/{name}'.
        """
        raw_name = self.service_name or 'unknown'
        if self.service_tunnel:
            t = self.service_tunnel.lower()
            if t == "ssl" and raw_name.lower() == "http":
                return "https"
            return f"{self.service_tunnel}/{raw_name}"
        return raw_name

    @property
    def full_version_text(self) -> str:
        return format_version_text(
            product=self.service_product,
            version=self.service_version,
            extrainfo=self.service_extrainfo,
            method=self.service_method,
            conf=self.service_conf
        )


@dataclass
class ParsedScan:
    host_up: bool = False
    host_timedout: bool = False
    elapsed: Optional[float] = None
    ports: List[ParsedPort] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    has_ports_element: bool = False


def parse_nmap_xml(xml_text: str) -> ParsedScan:
    """Pure function to parse Nmap XML output into a structured ParsedScan object.
    Per <service>, extracts name, product, version, extrainfo, tunnel, method, conf, and child <cpe>.
    IGNORES servicefp attribute entirely (never copied into any field).
    """
    root = ET.fromstring(xml_text)

    host_up = False
    host_timedout = False
    has_ports_element = False
    ports: List[ParsedPort] = []
    warnings: List[str] = []

    elapsed: Optional[float] = None
    finished_el = root.find('.//finished')
    if finished_el is not None and finished_el.get('elapsed'):
        try:
            elapsed = float(finished_el.get('elapsed'))
        except (ValueError, TypeError):
            elapsed = None

    hosts = root.findall('host')
    for host in hosts:
        if host.get('timedout', '').lower() == 'true':
            host_timedout = True
            warnings.append("Host timed out during scan.")

        status_el = host.find('status')
        if status_el is not None:
            if status_el.get('state') == 'up':
                host_up = True
            elif status_el.get('state') == 'down':
                host_up = False
        else:
            # -Pn was used, assuming host is up when <status> is omitted in XML
            host_up = True

        ports_el = host.find('ports')
        if ports_el is not None:
            has_ports_element = True
            for port in ports_el.findall('port'):
                try:
                    port_id = int(port.get('portid'))
                except (ValueError, TypeError):
                    continue
                protocol = port.get('protocol', 'tcp')

                state_el = port.find('state')
                state = state_el.get('state', 'unknown') if state_el is not None else 'unknown'

                service_el = port.find('service')
                service_name = 'unknown'
                service_product = None
                service_version = None
                service_extrainfo = None
                service_tunnel = None
                service_method = None
                service_conf = None
                service_cpe = None

                if service_el is not None:
                    # Note: servicefp is deliberately ignored entirely
                    service_name = service_el.get('name', 'unknown')
                    service_product = service_el.get('product') or None
                    service_version = service_el.get('version') or None
                    service_extrainfo = service_el.get('extrainfo') or None
                    service_tunnel = service_el.get('tunnel') or None
                    service_method = service_el.get('method') or None

                    conf_val = service_el.get('conf')
                    if conf_val is not None:
                        try:
                            service_conf = int(conf_val)
                        except (ValueError, TypeError):
                            service_conf = None

                    cpe_el = service_el.find('cpe')
                    if cpe_el is not None and cpe_el.text:
                        service_cpe = cpe_el.text.strip()

                ports.append(ParsedPort(
                    port=port_id,
                    protocol=protocol,
                    state=state,
                    service_name=service_name,
                    service_product=service_product,
                    service_version=service_version,
                    service_extrainfo=service_extrainfo,
                    service_tunnel=service_tunnel,
                    service_method=service_method,
                    service_conf=service_conf,
                    service_cpe=service_cpe
                ))

    return ParsedScan(
        host_up=host_up,
        host_timedout=host_timedout,
        elapsed=elapsed,
        ports=ports,
        warnings=warnings,
        has_ports_element=has_ports_element
    )


def _ensure_nmap_on_path() -> None:
    """Ensure standard Nmap installation directories are in PATH if present."""
    import os
    if shutil.which("nmap") is not None:
        return
    candidates = [
        r"C:\Program Files (x86)\Nmap",
        r"C:\Program Files\Nmap",
        "/usr/bin",
        "/usr/local/bin",
    ]
    for c in candidates:
        exe = os.path.join(c, "nmap.exe") if os.name == 'nt' else os.path.join(c, "nmap")
        if os.path.isfile(exe):
            if c not in os.environ.get("PATH", ""):
                os.environ["PATH"] = c + os.pathsep + os.environ.get("PATH", "")
            break


def is_nmap_available() -> bool:
    """Check if nmap is available in the system PATH or standard locations."""
    _ensure_nmap_on_path()
    if shutil.which("nmap") is not None:
        return True
    try:
        # Run nmap with --version, stdout/stderr to devnull, timeout to keep it quick
        subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _detect_nmap_version() -> Optional[str]:
    """Detect and return Nmap version string, or None if detection fails."""
    try:
        res = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5.0)
        out = getattr(res, 'stdout', None)
        if isinstance(out, (str, bytes)) and getattr(res, 'returncode', None) == 0:
            if isinstance(out, bytes):
                out = out.decode('utf-8', errors='replace')
            first_line = out.strip().splitlines()[0].strip() if out.strip() else ""
            if "nmap" in first_line.lower() and not first_line.startswith("<"):
                return first_line[:50]
    except Exception:
        pass
    return None


_cached_nmap_version: Optional[str] = None


def get_nmap_version() -> Optional[str]:
    """Retrieve Nmap version lazily on first use, after _ensure_nmap_on_path().
    Caches only a successful result (retries if it was None).
    """
    global _cached_nmap_version
    if _cached_nmap_version is not None:
        return _cached_nmap_version

    _ensure_nmap_on_path()
    detected = _detect_nmap_version()
    if detected is not None:
        _cached_nmap_version = detected
    return detected


def reset_cached_nmap_version() -> None:
    """Reset cached Nmap version (used in tests)."""
    global _cached_nmap_version
    _cached_nmap_version = None


class NetworkScannerServiceInterface(ABC):
    """Abstract interface for running network audits and extracting port parameters."""

    @abstractmethod
    def execute_scan(self, user_id: int, ip_address: str, scan_profile: str, scanner_mode: str = 'MOCK') -> NetworkScan:
        """Trigger a network scanner execution run and save results to repositories."""
        pass


class MockNetworkScannerService(NetworkScannerServiceInterface):
    """Placeholder service implementation that returns simulated network telemetry."""

    def __init__(self, repository: NetworkScanRepositoryInterface, risk_calculator: RiskCalculatorInterface):
        self.repository = repository
        self.risk_calculator = risk_calculator

    def execute_scan(self, user_id: int, ip_address: str, scan_profile: str, scanner_mode: str = 'MOCK') -> NetworkScan:
        from flask import current_app
        is_testing = False
        try:
            is_testing = current_app.config.get('TESTING', False)
        except Exception:
            pass

        try:
            ip = ipaddress.ip_address(ip_address.strip())
            if not is_testing and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast):
                # Log threat event log entry
                try:
                    from app.models.threat import ThreatLog
                    from flask import request
                    from app.extensions import db
                    threat = ThreatLog(
                        source_ip=request.remote_addr if request else "127.0.0.1",
                        threat_type="SSRF Scan Attempt",
                        severity="High",
                        description=f"Blocked network scanner SSRF target request: User ID {user_id} attempted to scan private/loopback destination: {ip_address}"
                    )
                    db.session.add(threat)
                    db.session.commit()
                except Exception:
                    pass
                raise ValueError("Scanning internal or private IP addresses is blocked for security reasons.")
        except ValueError as e:
            if "blocked" in str(e):
                raise ValueError(str(e))
            raise ValueError("Invalid IP address format.")

        # 1. Instantiate NetworkScan metadata model
        scan = NetworkScan(
            ip_address=ip_address,
            status='completed',
            scan_profile=scan_profile,
            scanner_mode='MOCK',
            risk_level='Low', # Set initially, calculated below
            user_id=user_id,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )

        # 2. Add dynamic, mock port findings depending on target profile selections
        findings = []
        if scan_profile == 'Quick Scan':
            findings.extend([
                NetworkScanResult(
                    port=80,
                    protocol='tcp',
                    service_name='http',
                    service_version='nginx 1.18.0',
                    state='open',
                    severity='Low',
                    remediation='Ensure HTTP traffic redirects automatically to secure HTTPS configurations.'
                ),
                NetworkScanResult(
                    port=443,
                    protocol='tcp',
                    service_name='https',
                    service_version='nginx 1.18.0',
                    state='open',
                    severity='Low',
                    remediation='Monitor SSL configurations and TLS handshake setups periodically.'
                )
            ])
        else: # Service Detection Profile
            findings.extend([
                NetworkScanResult(
                    port=22,
                    protocol='tcp',
                    service_name='ssh',
                    service_version='OpenSSH 8.2p1 Ubuntu 4ubuntu0.5',
                    state='open',
                    severity='Medium',
                    remediation='Restrict SSH source IP addresses using firewalls and disable password logins.'
                ),
                NetworkScanResult(
                    port=80,
                    protocol='tcp',
                    service_name='http',
                    service_version='Apache httpd 2.4.41',
                    state='open',
                    severity='Low',
                    remediation='Configure redirects and hide version banners.'
                ),
                NetworkScanResult(
                    port=3389,
                    protocol='tcp',
                    service_name='ms-wbt-server',
                    service_version='Windows Remote Desktop (RDP)',
                    state='open',
                    severity='High',
                    remediation='Disable public facing RDP listeners. Force VPN usage to access Remote Desktop.'
                )
            ])

        # Link findings to scan parent
        scan.results = findings
        
        # 3. Calculate Overall Risk Index using calculator interface
        scan.risk_level = self.risk_calculator.calculate_risk(findings)

        # 4. Commit scan details via repository interface
        scan = self.repository.save(scan)

        # 5. Trigger AI Analysis Service automatically
        try:
            import json
            from app.services.ai_service import AIAnalysisService
            from app.models.ai import AIResponse
            from app.extensions import db

            # Format findings for AIAnalysisService
            findings_data = []
            for result in findings:
                findings_data.append({
                    "name": f"Open Port {result.port}/{result.protocol} ({result.service_name})",
                    "severity": result.severity,
                    "description": f"Port {result.port}/{result.protocol} is open and running service {result.service_name} (version: {result.service_version or 'Unknown'}). An open port/service increases the target's attack surface but does not automatically mean a vulnerability exists unless explicitly exploited or misconfigured.",
                    "remediation": result.remediation or "Restrict access to trusted hosts using local firewall configurations."
                })

            # Calculate deterministic score corresponding to risk level
            score_map = {'Low': 90, 'Medium': 70, 'High': 40, 'Critical': 20}
            net_score = 100 if not findings else score_map.get(scan.risk_level, 70)

            scan_results_payload = {
                "target": scan.ip_address,
                "scan_type": "network",
                "overall_risk": scan.risk_level,
                "security_score": net_score,
                "findings": findings_data
            }

            # Call AI Service (falls back safely on quota exhaustion)
            ai_data = AIAnalysisService.analyze_scan(scan_results_payload, fallback_on_quota=True, user_id=user_id)
            model_used = ai_data.get("_model_used", AIAnalysisService.DEFAULT_MODEL)

            # Persist AI response
            db_response = AIResponse(
                prompt="Automatically generated report from network scanner results.",
                response_text=json.dumps(ai_data),
                model_used=model_used,
                network_scan_id=scan.id
            )
            db.session.add(db_response)
            db.session.commit()
        except Exception as e:
            # AI analysis must fail gracefully and not prevent the scan itself from succeeding
            logger.warning(f"AI analysis failed gracefully for network scan {scan.uuid}: {e}")

        return scan


class NmapNetworkScannerService(NetworkScannerServiceInterface):
    """Service implementation that performs real Nmap audits."""

    get_nmap_version = staticmethod(get_nmap_version)

    def __init__(self, repository: NetworkScanRepositoryInterface, risk_calculator: RiskCalculatorInterface):
        self.repository = repository
        self.risk_calculator = risk_calculator

    def _record_evidence(
        self,
        scan_id: int,
        phase: str,
        command: any,
        exit_code: Optional[int],
        duration_seconds: Optional[float],
        raw_xml: Optional[str],
        stderr: Optional[str],
        nmap_version: Optional[str]
    ) -> None:
        """Persist a single network scan evidence row with 1 MB text truncation."""
        try:
            from app.models.network_scan import NetworkScanEvidence
            from app.extensions import db

            # Sanitize command
            if isinstance(command, (list, tuple)):
                cmd_str = " ".join(str(c) for c in command)
            elif isinstance(command, str):
                cmd_str = command
            else:
                cmd_str = "nmap"

            # Sanitize exit_code
            clean_exit = None
            if isinstance(exit_code, int):
                clean_exit = exit_code
            elif exit_code is not None and not hasattr(exit_code, '_mock_name'):
                try:
                    clean_exit = int(exit_code)
                except (ValueError, TypeError):
                    clean_exit = None

            # Sanitize duration
            clean_dur = None
            if isinstance(duration_seconds, (int, float)):
                clean_dur = round(float(duration_seconds), 4)
            elif duration_seconds is not None and not hasattr(duration_seconds, '_mock_name'):
                try:
                    clean_dur = round(float(duration_seconds), 4)
                except (ValueError, TypeError):
                    clean_dur = None

            # Sanitize raw_xml
            clean_xml = None
            if isinstance(raw_xml, bytes):
                clean_xml = raw_xml.decode('utf-8', errors='replace')
            elif isinstance(raw_xml, str):
                clean_xml = raw_xml
            elif raw_xml is not None and not hasattr(raw_xml, '_mock_name'):
                clean_xml = str(raw_xml)

            # Sanitize stderr
            clean_stderr = None
            if isinstance(stderr, bytes):
                clean_stderr = stderr.decode('utf-8', errors='replace')
            elif isinstance(stderr, str):
                clean_stderr = stderr
            elif stderr is not None and not hasattr(stderr, '_mock_name'):
                clean_stderr = str(stderr)

            # Sanitize nmap_version
            clean_ver = "unknown"
            if isinstance(nmap_version, str) and nmap_version.strip() and nmap_version.strip().lower() != "none":
                clean_ver = nmap_version.strip()[:50]
            elif nmap_version is not None and not hasattr(nmap_version, '_mock_name'):
                v_str = str(nmap_version).strip()
                if v_str and v_str.lower() != "none":
                    clean_ver = v_str[:50]

            evidence = NetworkScanEvidence(
                network_scan_id=scan_id,
                phase=str(phase),
                command=cmd_str,
                exit_code=clean_exit,
                duration_seconds=clean_dur,
                raw_xml=truncate_evidence_text(clean_xml),
                stderr=truncate_evidence_text(clean_stderr),
                nmap_version=clean_ver,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(evidence)
            db.session.commit()
        except Exception as e:
            try:
                from app.extensions import db
                db.session.rollback()
            except Exception:
                pass
            logger.warning(f"Failed to persist network scan evidence for scan {scan_id}: {e}")

    def _run_ai_analysis(self, scan: NetworkScan, findings: list) -> None:
        """Run AI analysis service for completed scans, gracefully failing if needed."""
        if scan.status == 'inconclusive':
            return
        try:
            import json
            from app.services.ai_service import AIAnalysisService
            from app.models.ai import AIResponse
            from app.extensions import db

            findings_data = []
            for result in findings:
                findings_data.append({
                    "name": f"Open Port {result.port}/{result.protocol} ({result.service_name})",
                    "severity": result.severity,
                    "description": f"Port {result.port}/{result.protocol} is open and running service {result.service_name} (version: {result.service_version or 'Unknown'}). An open port/service increases the target's attack surface but does not automatically mean a vulnerability exists unless explicitly exploited or misconfigured.",
                    "remediation": result.remediation or "Restrict access to trusted hosts using local firewall configurations."
                })

            score_map = {'Low': 90, 'Medium': 70, 'High': 40, 'Critical': 20}
            net_score = 100 if not findings else score_map.get(scan.risk_level, 70)

            scan_results_payload = {
                "target": scan.ip_address,
                "scan_type": "network",
                "overall_risk": scan.risk_level,
                "security_score": net_score,
                "findings": findings_data
            }

            ai_data = AIAnalysisService.analyze_scan(scan_results_payload, fallback_on_quota=True, user_id=scan.user_id)
            model_used = ai_data.get("_model_used", AIAnalysisService.DEFAULT_MODEL)

            db_response = AIResponse(
                prompt="Automatically generated report from network scanner results.",
                response_text=json.dumps(ai_data),
                model_used=model_used,
                network_scan_id=scan.id
            )
            db.session.add(db_response)
            db.session.commit()
        except Exception as e:
            logger.warning(f"AI analysis failed gracefully for network scan {scan.uuid}: {e}")

    def execute_scan(self, user_id: int, ip_address: str, scan_profile: str, scanner_mode: str = 'REAL_NMAP') -> NetworkScan:
        from flask import current_app

        is_testing = False
        try:
            is_testing = current_app.config.get('TESTING', False)
        except Exception:
            pass

        # Target IP and Hostname Validation & SSRF Prevention
        target = ip_address.strip()
        resolved_ip = None
        
        # 1. First check if it is a valid IP address
        try:
            ip = ipaddress.ip_address(target)
            resolved_ip = str(ip)
        except ValueError:
            # 2. It is not a direct IP, check if it is a valid hostname/localhost
            if target.lower() == 'localhost':
                resolved_ip = '127.0.0.1'
                ip = ipaddress.ip_address(resolved_ip)
            else:
                try:
                    addr_info = socket.getaddrinfo(target, None)
                    resolved_ip = addr_info[0][4][0]
                    ip = ipaddress.ip_address(resolved_ip)
                except Exception:
                    raise ValueError("Invalid IP address format.")

        # 3. SSRF Target Validation
        if not is_testing and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast):
            # Log threat event log entry
            try:
                from app.models.threat import ThreatLog
                from flask import request
                from app.extensions import db
                threat = ThreatLog(
                    source_ip=request.remote_addr if request else "127.0.0.1",
                    threat_type="SSRF Scan Attempt",
                    severity="High",
                    description=f"Blocked network scanner SSRF target request: User ID {user_id} attempted to scan private/loopback destination: {ip_address}"
                )
                db.session.add(threat)
                db.session.commit()
            except Exception:
                pass
            raise ValueError("Scanning internal or private IP addresses is blocked for security reasons.")

        # 4. Check if Nmap is installed (Do this AFTER target validation!)
        if not is_nmap_available():
            raise NmapUnavailableError("Nmap is not installed or available on this system. Please use Simulated Mode.")

        # Instantiate NetworkScan metadata model
        started_at = datetime.now(timezone.utc)
        scan = NetworkScan(
            ip_address=ip_address,
            status='running',
            scan_profile=scan_profile,
            risk_level='Low',
            scanner_mode='REAL_NMAP',
            user_id=user_id,
            started_at=started_at
        )
        scan = self.repository.save(scan)

        # Ensure Nmap directory is in PATH before executing subprocess
        _ensure_nmap_on_path()
        nmap_ver = get_nmap_version() or "unknown"

        # ==========================================
        # PHASE 1 (discovery, authoritative)
        # ==========================================
        # Command: nmap -Pn -sT -p <ports> --max-retries 1 --host-timeout 20s -oX - <target> (NO -sV). Subprocess timeout 35s.
        if scan_profile == 'Quick Scan':
            phase1_ports = "80,443"
        else:
            phase1_ports = "22,80,443,3389,8080"

        cmd_phase1 = [
            "nmap", "-Pn", "-sT", "-p", phase1_ports,
            "--max-retries", "1", "--host-timeout", "20s",
            "-oX", "-", resolved_ip
        ]

        # Execute Phase 1 Nmap
        t0_p1 = time.monotonic()
        try:
            res_phase1 = subprocess.run(cmd_phase1, capture_output=True, text=True, timeout=35.0)
            dur_p1 = time.monotonic() - t0_p1
        except subprocess.TimeoutExpired as exc:
            dur_p1 = time.monotonic() - t0_p1
            scan.status = 'failed'
            scan.completed_at = datetime.now(timezone.utc)
            self.repository.save(scan)
            raw_out = getattr(exc, 'stdout', None)
            if isinstance(raw_out, bytes):
                raw_out = raw_out.decode('utf-8', errors='replace')
            raw_err = getattr(exc, 'stderr', None)
            if isinstance(raw_err, bytes):
                raw_err = raw_err.decode('utf-8', errors='replace')
            self._record_evidence(
                scan_id=scan.id,
                phase='discovery',
                command=cmd_phase1,
                exit_code=None,
                duration_seconds=dur_p1,
                raw_xml=raw_out,
                stderr=raw_err or "Network scan timed out after 35 seconds.",
                nmap_version=nmap_ver
            )
            raise ValueError("Network scan timed out after 30 seconds.")
        except (OSError, subprocess.SubprocessError) as e:
            dur_p1 = time.monotonic() - t0_p1
            scan.status = 'failed'
            scan.completed_at = datetime.now(timezone.utc)
            self.repository.save(scan)
            self._record_evidence(
                scan_id=scan.id,
                phase='discovery',
                command=cmd_phase1,
                exit_code=None,
                duration_seconds=dur_p1,
                raw_xml=None,
                stderr=str(e),
                nmap_version=nmap_ver
            )
            raise ValueError(f"Nmap execution failed: {str(e)}")

        # Handle non-zero exit codes
        if res_phase1.returncode != 0:
            scan.status = 'failed'
            scan.completed_at = datetime.now(timezone.utc)
            self.repository.save(scan)
            self._record_evidence(
                scan_id=scan.id,
                phase='discovery',
                command=cmd_phase1,
                exit_code=res_phase1.returncode,
                duration_seconds=dur_p1,
                raw_xml=res_phase1.stdout,
                stderr=res_phase1.stderr,
                nmap_version=nmap_ver
            )
            raise ValueError(f"Nmap command exited with non-zero status code: {res_phase1.returncode}")

        # Record Phase 1 evidence row for successful subprocess execution
        self._record_evidence(
            scan_id=scan.id,
            phase='discovery',
            command=cmd_phase1,
            exit_code=res_phase1.returncode,
            duration_seconds=dur_p1,
            raw_xml=res_phase1.stdout,
            stderr=res_phase1.stderr,
            nmap_version=nmap_ver
        )

        # Parse Phase 1 XML
        try:
            parsed_phase1 = parse_nmap_xml(res_phase1.stdout)
        except ET.ParseError:
            scan.status = 'failed'
            scan.completed_at = datetime.now(timezone.utc)
            self.repository.save(scan)
            raise ValueError("Failed to parse network scanner output results.")

        # Run integrity check (phase 1 only decides this):
        # host_timedout == true OR host has no <ports> element OR host not up -> scan.status = 'inconclusive'
        if parsed_phase1.host_timedout or not parsed_phase1.has_ports_element or not parsed_phase1.host_up:
            scan.status = 'inconclusive'
            scan.risk_level = 'Inconclusive'
            scan.results = []
            scan.completed_at = datetime.now(timezone.utc)
            scan = self.repository.save(scan)
            return scan

        # Open/closed/filtered state from phase 1 is the ground truth
        open_ports = [p for p in parsed_phase1.ports if p.state == 'open']

        # If zero open ports: legitimate completed result
        if not open_ports:
            scan.status = 'completed'
            scan.risk_level = self.risk_calculator.calculate_risk([])
            scan.results = []
            scan.completed_at = datetime.now(timezone.utc)
            scan = self.repository.save(scan)
            self._run_ai_analysis(scan, [])
            return scan

        # ==========================================
        # PHASE 2 (version detection, best effort)
        # Only for ports OPEN in phase 1, ONLY for 'Service Detection' profile.
        # Guard: Skip Phase 2 entirely when there are no open ports (max_workers must never be 0).
        # ==========================================
        port_version_info = {}

        if scan_profile == 'Service Detection' and open_ports:
            def _probe_port(p_port: ParsedPort) -> Tuple[int, str, str, dict]:
                port_num = p_port.port
                cmd_p2 = [
                    "nmap", "-Pn", "-sT", "-p", str(port_num),
                    "-sV", "--version-light", "--host-timeout", "75s",
                    "-oX", "-", resolved_ip
                ]
                t0_p2 = time.monotonic()
                try:
                    res_p2 = subprocess.run(cmd_p2, capture_output=True, text=True, timeout=90.0)
                    dur_p2 = time.monotonic() - t0_p2
                    ev_dict = {
                        "phase": f"version:{port_num}",
                        "command": cmd_p2,
                        "exit_code": res_p2.returncode,
                        "duration_seconds": dur_p2,
                        "raw_xml": res_p2.stdout,
                        "stderr": res_p2.stderr,
                        "nmap_version": nmap_ver
                    }
                    if res_p2.returncode == 0 and res_p2.stdout:
                        p2_parsed = parse_nmap_xml(res_p2.stdout)
                        matching = [pt for pt in p2_parsed.ports if pt.port == port_num]
                        if matching:
                            matched = matching[0]
                            s_name = matched.display_service_name
                            v_text = format_version_text(
                                product=matched.service_product,
                                version=matched.service_version,
                                extrainfo=matched.service_extrainfo,
                                method=matched.service_method,
                                conf=matched.service_conf
                            )
                            return (port_num, s_name, v_text, ev_dict)
                    return (port_num, p_port.display_service_name, VERSION_TEXT_TIMED_OUT, ev_dict)
                except subprocess.TimeoutExpired as texc:
                    dur_p2 = time.monotonic() - t0_p2
                    logger.warning(f"Phase 2 version probe timed out for port {port_num}")
                    raw_out = getattr(texc, 'stdout', None)
                    if isinstance(raw_out, bytes):
                        raw_out = raw_out.decode('utf-8', errors='replace')
                    raw_err = getattr(texc, 'stderr', None)
                    if isinstance(raw_err, bytes):
                        raw_err = raw_err.decode('utf-8', errors='replace')
                    ev_dict = {
                        "phase": f"version:{port_num}",
                        "command": cmd_p2,
                        "exit_code": None,
                        "duration_seconds": dur_p2,
                        "raw_xml": raw_out,
                        "stderr": raw_err or f"Phase 2 probe timed out for port {port_num}",
                        "nmap_version": nmap_ver
                    }
                    return (port_num, p_port.display_service_name, VERSION_TEXT_TIMED_OUT, ev_dict)
                except Exception as ex:
                    dur_p2 = time.monotonic() - t0_p2
                    logger.warning(f"Phase 2 version probe failed for port {port_num}: {ex}")
                    ev_dict = {
                        "phase": f"version:{port_num}",
                        "command": cmd_p2,
                        "exit_code": None,
                        "duration_seconds": dur_p2,
                        "raw_xml": None,
                        "stderr": str(ex),
                        "nmap_version": nmap_ver
                    }
                    return (port_num, p_port.display_service_name, VERSION_TEXT_TIMED_OUT, ev_dict)

            max_workers = max(1, min(4, len(open_ports)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_probe_port, p): p.port for p in open_ports}
                for future in concurrent.futures.as_completed(futures):
                    p_num = futures[future]
                    try:
                        p_id, s_name, v_text, ev_dict = future.result()
                        port_version_info[p_id] = (s_name, v_text)
                        self._record_evidence(
                            scan_id=scan.id,
                            phase=ev_dict["phase"],
                            command=ev_dict["command"],
                            exit_code=ev_dict["exit_code"],
                            duration_seconds=ev_dict["duration_seconds"],
                            raw_xml=ev_dict["raw_xml"],
                            stderr=ev_dict["stderr"],
                            nmap_version=ev_dict["nmap_version"]
                        )
                    except Exception as exc:
                        p_obj = next((pt for pt in open_ports if pt.port == p_num), None)
                        fallback_label = p_obj.display_service_name if p_obj else "unknown"
                        port_version_info[p_num] = (fallback_label, VERSION_TEXT_TIMED_OUT)
                        self._record_evidence(
                            scan_id=scan.id,
                            phase=f"version:{p_num}",
                            command=f"nmap -Pn -sT -p {p_num} -sV --version-light --host-timeout 75s -oX - {resolved_ip}",
                            exit_code=None,
                            duration_seconds=0.0,
                            raw_xml=None,
                            stderr=str(exc),
                            nmap_version=nmap_ver
                        )

        # Compile findings from ground-truth open ports
        findings = []
        for p in open_ports:
            port_id = p.port
            protocol = p.protocol
            state = p.state

            if scan_profile == 'Service Detection':
                s_name, v_text = port_version_info.get(
                    port_id, (p.display_service_name, VERSION_TEXT_TIMED_OUT)
                )
                service_name = s_name
                service_version = v_text
            else:  # Quick Scan
                service_name = p.display_service_name
                service_version = p.full_version_text

            # Severity and remediation mapping based on port configuration
            severity = 'Low'
            remediation = 'Restrict access to trusted hosts using local firewall configurations.'

            if port_id == 22:
                severity = 'Medium'
                remediation = 'Restrict SSH source IP addresses using firewalls and disable password logins.'
            elif port_id == 80:
                severity = 'Low'
                remediation = 'Ensure HTTP traffic redirects automatically to secure HTTPS configurations.'
            elif port_id == 443:
                severity = 'Low'
                remediation = 'Monitor SSL configurations and TLS handshake setups periodically.'
            elif port_id == 3389:
                severity = 'High'
                remediation = 'Disable public facing RDP listeners. Force VPN usage to access Remote Desktop.'
            elif port_id == 8080:
                severity = 'Medium'
                remediation = 'Disable public access to admin ports and use SSL/TLS.'

            findings.append(NetworkScanResult(
                port=port_id,
                protocol=protocol,
                service_name=service_name,
                service_version=service_version,
                state=state,
                severity=severity,
                remediation=remediation
            ))

        scan.status = 'completed'
        scan.results = findings
        scan.risk_level = self.risk_calculator.calculate_risk(findings)
        scan.completed_at = datetime.now(timezone.utc)

        # Commit scan details via repository interface
        scan = self.repository.save(scan)

        # Trigger AI Analysis Service
        self._run_ai_analysis(scan, findings)

        return scan


class NetworkScannerService(NetworkScannerServiceInterface):
    """Dispatcher service directing requests to Nmap or Mock scanning implementations."""

    def __init__(self, repository: NetworkScanRepositoryInterface, risk_calculator: RiskCalculatorInterface):
        self.repository = repository
        self.risk_calculator = risk_calculator
        self.mock_scanner = MockNetworkScannerService(repository, risk_calculator)
        self.nmap_scanner = NmapNetworkScannerService(repository, risk_calculator)

    def execute_scan(self, user_id: int, ip_address: str, scan_profile: str, scanner_mode: str = 'REAL_NMAP') -> NetworkScan:
        if scanner_mode == 'REAL_NMAP':
            return self.nmap_scanner.execute_scan(user_id, ip_address, scan_profile, scanner_mode)
        else:
            return self.mock_scanner.execute_scan(user_id, ip_address, scan_profile, scanner_mode)
