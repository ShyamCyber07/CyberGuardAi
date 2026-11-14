import uuid
from datetime import datetime, timezone
from app.extensions import db

class NetworkScan(db.Model):
    """Database model representing network scanner execution history."""
    __tablename__ = 'network_scans'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)  # IPv4, IPv6 or authorized hostname
    status = db.Column(db.String(20), default='completed', index=True, nullable=False)  # pending, running, completed, failed
    risk_level = db.Column(db.String(20), nullable=False)  # Low, Medium, High
    scan_profile = db.Column(db.String(50), nullable=False)  # Quick Scan, Service Detection
    scanner_mode = db.Column(db.String(20), default='MOCK', nullable=False)  # MOCK, REAL_NMAP
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False)

    # Relationships
    results = db.relationship('NetworkScanResult', backref='network_scan', lazy=True, cascade='all, delete-orphan')
    ai_response = db.relationship('AIResponse', backref='network_scan', uselist=False, lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='network_scan', lazy=True, cascade='all, delete-orphan')
    evidence = db.relationship('NetworkScanEvidence', backref='network_scan', lazy=True, cascade='all, delete-orphan', order_by='NetworkScanEvidence.id')

    def __repr__(self):
        return f"<NetworkScan {self.ip_address} - Risk: {self.risk_level}>"


class NetworkScanEvidence(db.Model):
    """Database model for storing command telemetry and raw output evidence for network scans."""
    __tablename__ = 'network_scan_evidence'

    id = db.Column(db.Integer, primary_key=True)
    network_scan_id = db.Column(db.Integer, db.ForeignKey('network_scans.id', ondelete='CASCADE'), index=True, nullable=False)
    phase = db.Column(db.String(50), nullable=False)  # 'discovery' | 'version:<port>'
    command = db.Column(db.Text, nullable=True)
    exit_code = db.Column(db.Integer, nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)
    raw_xml = db.Column(db.Text, nullable=True)  # Truncated to 1 MB
    stderr = db.Column(db.Text, nullable=True)   # Truncated to 1 MB
    nmap_version = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f"<NetworkScanEvidence scan_id={self.network_scan_id} phase={self.phase} exit={self.exit_code}>"


class NetworkScanResult(db.Model):
    """Database model for storing identified ports and running services on audited network nodes."""
    __tablename__ = 'network_scan_results'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    network_scan_id = db.Column(db.Integer, db.ForeignKey('network_scans.id', ondelete='CASCADE'), index=True, nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # tcp, udp
    service_name = db.Column(db.String(50), nullable=False)  # e.g., ssh, http, domain
    service_version = db.Column(db.String(100), nullable=True)  # e.g., OpenSSH 8.2p1
    state = db.Column(db.String(20), nullable=False)  # open, closed, filtered
    severity = db.Column(db.String(20), nullable=False)  # Low, Medium, High
    remediation = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<NetworkScanResult Port {self.port}/{self.protocol} - Service: {self.service_name}>"
