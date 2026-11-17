"""Network Exposure Rules Engine and Risk Evaluation.

This module defines deterministic, evidence-based network exposure rules and the overall
network risk evaluation formula for network scan assessments.

### RISK FORMULA
Overall risk = highest exposure level among triggered rules:
  - 'Critical' if any triggered rule specifies Critical exposure (none initially).
  - 'High' if any triggered rule specifies High exposure.
  - 'Medium' if any triggered rule specifies Medium exposure.
  - 'Low' if any triggered rule specifies Low exposure.
  - Informational exposure counts as 'Low'.
  - A completed scan with zero open ports counts as 'Low'.
  - If the scan did not complete or was interrupted, risk is 'Inconclusive'.

Allowed output risk level strings:
  'Low', 'Medium', 'High', 'Critical', 'Inconclusive'

### EVIDENCE-BASED BASIS
Rules evaluate only evidence produced by the scanner:
  - Port state and number from Phase 1 discovery.
  - Service banner / product version only when confirmed by an active probe (method == 'probed').
  - When service identity is assumed from port number alone (or probe did not run/verify),
    the basis is explicitly recorded as:
    "Basis: port number only (service not verified)"
  - When service identity was confirmed by an active probe, the basis is recorded as:
    "probed service banner"

### RULE RATIONALE & REASONING (Plain-Language, No Invented Citations)
High Exposure Rules:
  - Port 23 (Telnet): Remote terminal protocol that transmits credentials and all session
    commands in unencrypted cleartext over the network.
  - Port 21 (FTP): File transfer protocol that transmits user authentication credentials and data
    in unencrypted cleartext across the network.
  - Port 3389 (RDP): Graphical remote desktop service. Public network exposure presents an active
    surface for automated credential brute-forcing and session hijacking.
  - Port 445 (SMB): Server Message Block / Microsoft-DS file sharing protocol intended for trusted
    local networks; public exposure enables remote host enumeration and unauthorized access attempts.
  - Port 139 (NetBIOS): Legacy NetBIOS Session Service susceptible to unauthenticated network
    enumeration and spoofing.
  - Port 135 (MSRPC): Microsoft RPC endpoint mapper exposes registered RPC services and interfaces
    to unauthenticated network query.
  - Port 3306 (MySQL): Relational database network listener; direct network exposure presents risk of
    unauthorized data access attempts and credential brute-force attacks.
  - Port 5432 (PostgreSQL): Relational database network listener; direct network exposure presents risk
    of unauthorized connection attempts and data exfiltration.
  - Port 1433 (MSSQL): Microsoft SQL Server listener; direct exposure to untrusted networks invites
    automated credential attacks and access to sensitive enterprise data.
  - Port 27017 (MongoDB): NoSQL database listener; direct exposure presents risk of unauthorized data
    access if database access control or network binding is permissive.
  - Port 6379 (Redis): In-memory data store designed for protected internal architectures; often lacks
    robust default network access controls or command restrictions.
  - Port 9200 (Elasticsearch): REST API for search cluster; exposure allows remote cluster enumeration
    and unauthenticated data manipulation if access controls are not enforced.
  - Port 11211 (Memcached): Distributed memory caching system without default authentication; can be
    leveraged for unauthorized data reads or network traffic amplification.
  - Port 5900 (VNC): Remote graphical desktop sharing protocol; commonly operates with weak password
    schemes or unencrypted network sessions.

Medium Exposure Rules:
  - Port 25 (SMTP): Simple Mail Transfer Protocol listener; unmanaged listeners risk abuse as open
    relays for spam transmission or email spoofing.
  - Port 110 (POP3): Post Office Protocol v3 transmits user credentials and mail content in cleartext
    over the network unless wrapped in TLS.
  - Port 143 (IMAP): Internet Message Access Protocol transmits authentication credentials and mail
    messages in plaintext unless encrypted transport is enforced.
  - Port 161 (SNMP): Simple Network Management Protocol; v1/v2c versions transmit community strings in
    cleartext and allow unauthorized network state enumeration.

Low Exposure Rules:
  - Port 22 (SSH): Secure Shell provides encrypted remote administration; an open port represents an
    administrative surface subject to automated credential scanning.
  - Port 8080 (HTTP-Alt): Alternative HTTP port commonly used for application development, proxies, or
    internal consoles that may bypass standard edge protections.
  - Port 8000 (HTTP-Alt): Alternative HTTP port commonly used for development web frameworks, APIs, or
    debugging interfaces that may lack production hardening.
  - Port 8443 (HTTPS-Alt): Alternative HTTPS port frequently hosting secondary administrative panels
    or management consoles.
  - Port 53 (DNS): Domain Name System server responding to resolution requests; open recursive resolvers
    risk abuse in denial of service amplification or cache poisoning.

Informational Exposure Rules:
  - Port 80 (HTTP): Standard cleartext web server listener, routinely used for public web serving and
    HTTP-to-HTTPS redirect endpoints.
  - Port 443 (HTTPS): Standard TLS-encrypted web server listener providing encrypted communication for
    web applications.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

# Basis string constants
BASIS_PORT_ONLY = "port number only (service not verified)"
BASIS_PROBED_BANNER = "probed service banner"

# Exposure level ranking hierarchy
EXPOSURE_RANKS: Dict[str, int] = {
    'CRITICAL': 5,
    'HIGH': 4,
    'MEDIUM': 3,
    'LOW': 2,
    'INFORMATIONAL': 1,
}


@dataclass(frozen=True)
class NetworkExposureRule:
    """Definition of an evidence-based network exposure rule."""
    rule_id: str
    port: int
    protocol: str
    exposure_level: str
    service_name: str
    rationale: str
    remediation: str


@dataclass
class NetworkRuleMatch:
    """Result of matching an observed port against exposure rules."""
    rule_id: str
    exposure_level: str
    observation: str
    rationale: str
    remediation: str
    basis: str


# Initial 25 deterministic network exposure rules
INITIAL_RULES: List[NetworkExposureRule] = [
    # High Exposure Rules (14 rules)
    NetworkExposureRule(
        rule_id="RULE-TELNET-23",
        port=23,
        protocol="tcp",
        exposure_level="High",
        service_name="telnet",
        rationale="Telnet transmits all authentication credentials and session commands in cleartext without cryptographic protection.",
        remediation="If remote terminal access is required, replace Telnet with an encrypted protocol such as SSH and disable the Telnet service."
    ),
    NetworkExposureRule(
        rule_id="RULE-FTP-21",
        port=21,
        protocol="tcp",
        exposure_level="High",
        service_name="ftp",
        rationale="Standard FTP authenticates and transmits files in cleartext without transport layer encryption.",
        remediation="If file transfer capability is required, use SFTP or FTPS with modern TLS ciphers and disable unencrypted FTP."
    ),
    NetworkExposureRule(
        rule_id="RULE-RDP-3389",
        port=3389,
        protocol="tcp",
        exposure_level="High",
        service_name="ms-wbt-server",
        rationale="RDP listeners exposed to network access present high exposure to credential brute-forcing and session hijacking.",
        remediation="If remote desktop management is required, restrict access behind a VPN or bastion host and enforce multi-factor authentication."
    ),
    NetworkExposureRule(
        rule_id="RULE-SMB-445",
        port=445,
        protocol="tcp",
        exposure_level="High",
        service_name="microsoft-ds",
        rationale="SMB is intended for local network file and printer sharing; exposure allows unauthorized host reconnaissance and lateral movement.",
        remediation="If file sharing is not intended across this network boundary, block port 445 at the perimeter or host firewall."
    ),
    NetworkExposureRule(
        rule_id="RULE-NETBIOS-139",
        port=139,
        protocol="tcp",
        exposure_level="High",
        service_name="netbios-ssn",
        rationale="NetBIOS provides legacy Windows file and printer sharing services susceptible to enumeration and spoofing.",
        remediation="If legacy Windows domain sharing is not required, disable NetBIOS over TCP/IP and block port 139."
    ),
    NetworkExposureRule(
        rule_id="RULE-MSRPC-135",
        port=135,
        protocol="tcp",
        exposure_level="High",
        service_name="msrpc",
        rationale="MSRPC endpoint mapper exposes information about registered RPC services and interfaces on the host.",
        remediation="If external RPC management is not required, restrict port 135 to trusted administrative network segments."
    ),
    NetworkExposureRule(
        rule_id="RULE-MYSQL-3306",
        port=3306,
        protocol="tcp",
        exposure_level="High",
        service_name="mysql",
        rationale="Direct exposure of database network listeners risks unauthorized access attempts and data exfiltration.",
        remediation="If external database access is not required, bind MySQL to localhost (127.0.0.1) or restrict connections via firewall."
    ),
    NetworkExposureRule(
        rule_id="RULE-POSTGRES-5432",
        port=5432,
        protocol="tcp",
        exposure_level="High",
        service_name="postgresql",
        rationale="Direct exposure of relational database listeners presents significant unauthorized access risk.",
        remediation="If direct external access is not necessary, bind PostgreSQL to local interfaces or allow only authorized application IPs."
    ),
    NetworkExposureRule(
        rule_id="RULE-MSSQL-1433",
        port=1433,
        protocol="tcp",
        exposure_level="High",
        service_name="ms-sql-s",
        rationale="Exposing enterprise database services directly to untrusted networks invites credential attacks and exposure of sensitive records.",
        remediation="If remote SQL Server access is not required, restrict listener binding to internal interfaces and trusted hosts."
    ),
    NetworkExposureRule(
        rule_id="RULE-MONGODB-27017",
        port=27017,
        protocol="tcp",
        exposure_level="High",
        service_name="mongodb",
        rationale="MongoDB instances exposed to network traffic risk unauthorized data access if authentication or binding is permissive.",
        remediation="If remote access is not needed, bind MongoDB to localhost and restrict inbound connections using firewall access rules."
    ),
    NetworkExposureRule(
        rule_id="RULE-REDIS-6379",
        port=6379,
        protocol="tcp",
        exposure_level="High",
        service_name="redis",
        rationale="Redis was designed for trusted internal networks and often lacks strong default access controls or command restrictions.",
        remediation="If Redis is used only by local applications, bind it to localhost or a protected private subnet and require authentication."
    ),
    NetworkExposureRule(
        rule_id="RULE-ELASTIC-9200",
        port=9200,
        protocol="tcp",
        exposure_level="High",
        service_name="wap-wsp",
        rationale="Elasticsearch clusters exposed without strict access controls allow cluster enumeration and unauthenticated data manipulation.",
        remediation="If external search API access is not intended, place Elasticsearch behind a reverse proxy with authentication and restrict port 9200."
    ),
    NetworkExposureRule(
        rule_id="RULE-MEMCACHED-11211",
        port=11211,
        protocol="tcp",
        exposure_level="High",
        service_name="memcache",
        rationale="Memcached has no native authentication by default and can be leveraged for unauthorized data reads or UDP amplification.",
        remediation="If caching is needed only for local services, bind Memcached to 127.0.0.1 and block external access to port 11211."
    ),
    NetworkExposureRule(
        rule_id="RULE-VNC-5900",
        port=5900,
        protocol="tcp",
        exposure_level="High",
        service_name="vnc",
        rationale="VNC exposes graphical desktop sessions over the network, frequently with weak password authentication or unencrypted transport.",
        remediation="If remote desktop access is required, tunnel VNC connections through SSH or a VPN rather than exposing port 5900 directly."
    ),

    # Medium Exposure Rules (4 rules)
    NetworkExposureRule(
        rule_id="RULE-SMTP-25",
        port=25,
        protocol="tcp",
        exposure_level="Medium",
        service_name="smtp",
        rationale="Mail transfer agents accept inbound email connections; unmanaged relays can be exploited for spam distribution or mail spoofing.",
        remediation="If this host does not operate as an internet mail relay, restrict port 25 to internal mail servers and verify relay controls."
    ),
    NetworkExposureRule(
        rule_id="RULE-POP3-110",
        port=110,
        protocol="tcp",
        exposure_level="Medium",
        service_name="pop3",
        rationale="Standard POP3 transmits user credentials and downloaded email messages in plaintext across the network.",
        remediation="If POP3 retrieval is required, transition clients to POP3S with TLS (port 995) and disable cleartext port 110."
    ),
    NetworkExposureRule(
        rule_id="RULE-IMAP-143",
        port=143,
        protocol="tcp",
        exposure_level="Medium",
        service_name="imap",
        rationale="Standard IMAP transmits authentication credentials and email content unencrypted unless STARTTLS is explicitly negotiated.",
        remediation="If IMAP is required, enforce IMAPS over TLS (port 993) or mandatory STARTTLS and restrict unencrypted access."
    ),
    NetworkExposureRule(
        rule_id="RULE-SNMP-161",
        port=161,
        protocol="udp",
        exposure_level="Medium",
        service_name="snmp",
        rationale="SNMP v1 and v2c send community strings in cleartext and allow unauthorized device status and network configuration discovery.",
        remediation="If network monitoring is required, upgrade to SNMPv3 with cryptographic authentication and restrict access by IP."
    ),

    # Low Exposure Rules (5 rules)
    NetworkExposureRule(
        rule_id="RULE-SSH-22",
        port=22,
        protocol="tcp",
        exposure_level="Low",
        service_name="ssh",
        rationale="SSH provides encrypted remote administration; an open listener is exposed to credential brute-force and automated scanning.",
        remediation="If remote administration is required, restrict source IP addresses with firewall rules and prefer SSH keys over passwords."
    ),
    NetworkExposureRule(
        rule_id="RULE-HTTP-ALT-8080",
        port=8080,
        protocol="tcp",
        exposure_level="Low",
        service_name="http-proxy",
        rationale="Port 8080 is commonly used for development servers, management consoles, or application proxies that may bypass standard controls.",
        remediation="If this service is for development or internal administrative use, restrict access to authorized networks or configure TLS."
    ),
    NetworkExposureRule(
        rule_id="RULE-HTTP-ALT-8000",
        port=8000,
        protocol="tcp",
        exposure_level="Low",
        service_name="http-alt",
        rationale="Port 8000 often hosts internal web services, REST APIs, or debugging endpoints that may lack production hardening.",
        remediation="If this service is not intended for public access, restrict network exposure or configure an encrypted reverse proxy."
    ),
    NetworkExposureRule(
        rule_id="RULE-HTTPS-ALT-8443",
        port=8443,
        protocol="tcp",
        exposure_level="Low",
        service_name="https-alt",
        rationale="Port 8443 typically hosts web management interfaces or secondary TLS applications requiring periodic security review.",
        remediation="If this service hosts administrative interfaces, restrict source IPs to management networks and maintain strong cipher suites."
    ),
    NetworkExposureRule(
        rule_id="RULE-DNS-53",
        port=53,
        protocol="tcp",
        exposure_level="Low",
        service_name="domain",
        rationale="DNS services respond to name resolution queries; unconstrained resolvers can be abused for cache poisoning or amplification.",
        remediation="If this host is an authoritative or recursive DNS resolver, restrict recursion to trusted local clients."
    ),

    # Informational Exposure Rules (2 rules)
    NetworkExposureRule(
        rule_id="RULE-HTTP-80",
        port=80,
        protocol="tcp",
        exposure_level="Informational",
        service_name="http",
        rationale="Standard web service port used for public web hosting and HTTP-to-HTTPS redirect listeners.",
        remediation="If this host should serve only HTTPS, redirect HTTP to HTTPS."
    ),
    NetworkExposureRule(
        rule_id="RULE-HTTPS-443",
        port=443,
        protocol="tcp",
        exposure_level="Informational",
        service_name="https",
        rationale="Standard encrypted web server listener providing TLS communications for web clients.",
        remediation="If this service hosts web traffic, maintain modern TLS cipher configurations and verify certificates periodically."
    ),
]

# Lookup dictionary by port for fast matching (TCP primary, with protocol fallback)
_RULES_BY_PORT: Dict[int, NetworkExposureRule] = {r.port: r for r in INITIAL_RULES}

# Additional well-known ports for the "Common Ports" profile (Phase 1 only)
COMMON_PORTS_ADDITIONAL: List[int] = [
    20, 69, 111, 389, 993, 995, 1723, 3000, 5000, 5060, 8888
]

# All ports for "Common Ports" profile: rules ports + additional ports, sorted ascending
COMMON_PORTS_LIST: List[int] = sorted(list(set(list(_RULES_BY_PORT.keys()) + COMMON_PORTS_ADDITIONAL)))
COMMON_PORTS_STR: str = ",".join(str(p) for p in COMMON_PORTS_LIST)


def match_port_rule(
    port: int,
    protocol: str = "tcp",
    service_name: Optional[str] = None,
    service_version: Optional[str] = None,
    method: Optional[str] = None
) -> NetworkRuleMatch:
    """
    Match an observed open port against evidence-based exposure rules.

    Parameters:
      port: Network port number (e.g. 80, 22).
      protocol: Transport protocol ('tcp' or 'udp').
      service_name: Service name reported by scanner or port mapping.
      service_version: Formatted version string or product details.
      method: Nmap detection method ('probed', 'table', etc.).

    Returns:
      NetworkRuleMatch with rule_id, exposure_level, observation, rationale,
      remediation, and basis.
    """
    clean_proto = (protocol or "tcp").lower()
    clean_srv = service_name or "unknown"
    is_probed = (method == "probed")

    # Determine basis
    basis = BASIS_PROBED_BANNER if is_probed else BASIS_PORT_ONLY

    # Build observation text based on evidence
    if is_probed:
        ver_info = f" ({service_version})" if (service_version and "not identified" not in service_version.lower() and "timed out" not in service_version.lower()) else ""
        observation = f"Port {port}/{clean_proto} observed open; service banner probed as {clean_srv}{ver_info}."
    else:
        observation = f"Port {port}/{clean_proto} observed open ({clean_srv} assumed from port number)."

    # Look up matching rule
    rule = _RULES_BY_PORT.get(port)
    if rule is not None:
        return NetworkRuleMatch(
            rule_id=rule.rule_id,
            exposure_level=rule.exposure_level,
            observation=observation,
            rationale=rule.rationale,
            remediation=rule.remediation,
            basis=basis
        )

    # Generic open port fallback rule
    return NetworkRuleMatch(
        rule_id="RULE-GENERIC-OPEN",
        exposure_level="Low",
        observation=observation,
        rationale="Unclassified network service port observed open; exposed network services increase attack surface.",
        remediation="If this service is not needed externally, restrict port access to trusted IP addresses using firewall rules.",
        basis=basis
    )


def calculate_network_risk(findings_or_levels: Any, is_inconclusive: bool = False) -> str:
    """
    Calculate overall network risk rating from triggered exposure rules or findings.

    Formula:
    Overall risk = highest exposure level among triggered rules:
      - Any rule with exposure level 'Critical' -> 'Critical'
      - Any rule with exposure level 'High' -> 'High'
      - Any rule with exposure level 'Medium' -> 'Medium'
      - Any rule with exposure level 'Low' or 'Informational' -> 'Low'
      - No open ports / no triggered rules -> 'Low'
      - If scan did not complete / is inconclusive -> 'Inconclusive'

    'Critical' is produced only if a rule explicitly sets it (none initially).
    Informational counts as 'Low'.
    """
    if is_inconclusive:
        return 'Inconclusive'

    if not findings_or_levels:
        return 'Low'

    # Extract exposure level strings
    highest_rank = 0
    highest_level = 'Low'

    for item in findings_or_levels:
        # Determine the exposure level string
        if isinstance(item, str):
            lvl_str = item
        elif hasattr(item, 'severity'):
            lvl_str = item.severity
        elif hasattr(item, 'exposure_level'):
            lvl_str = item.exposure_level
        elif isinstance(item, dict):
            lvl_str = item.get('exposure_level') or item.get('severity') or 'Low'
        else:
            lvl_str = 'Low'

        # Filter out closed/filtered states if present on object
        state = getattr(item, 'state', None)
        if isinstance(item, dict):
            state = item.get('state')
        if state and str(state).lower() not in ('open', 'unknown'):
            continue

        normalized = (lvl_str or 'Low').upper()
        rank = EXPOSURE_RANKS.get(normalized, 2)
        if rank > highest_rank:
            highest_rank = rank
            highest_level = lvl_str.capitalize()

    if highest_rank == 0:
        return 'Low'

    # Informational counts as Low in overall risk rating
    if highest_level.lower() == 'informational':
        return 'Low'

    # Return standard capitalized risk string: Low, Medium, High, Critical
    return highest_level
