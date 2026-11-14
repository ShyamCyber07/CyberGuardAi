import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.hybrid import hybrid_property
from app.extensions import db

class RiskRating(str):
    """
    Subclass of str that preserves full string compatibility while providing
    the .rule attribute to indicate which rule produced the risk result.
    """
    def __new__(cls, value, rule=None):
        obj = super().__new__(cls, value)
        obj.rule = rule
        return obj

    def __repr__(self):
        return f"RiskRating('{super().__str__()}', rule='{self.rule}')"


def derive_risk(score, findings=None, return_rule=False):
    """
    Derives authoritative risk level from security score and findings.

    Exact Score Bands:
      - Score 85 - 100: 'None' (if 0 findings of severity low or higher) or 'Low' (if >=1 finding of severity low or higher)
      - Score 70 - 84:  'Medium'
      - Score 40 - 69:  'High'
      - Score 0  - 39:  'Critical'

    Severity Floor Rules:
      - 'None' vs 'Low' counts only findings of severity low or higher (findings with severity 'info'
        do not elevate 'None' to 'Low'). A scan with only 'info' findings and score >= 85 is 'None'.
      - Any finding with severity 'critical' (case-insensitive) elevates the risk rating
        to at least 'High'.
        ('None', 'Low', 'Medium' -> 'High'; 'High' and 'Critical' remain unchanged).

    Args:
        score (int or float or None): The numeric compliance score (0-100).
        findings (list, optional): List of ScanResult objects or dicts with 'severity'.
        return_rule (bool, optional): If True, returns a tuple of (RiskRating, rule_name).

    Returns:
        RiskRating (str): The derived risk rating with a `.rule` attribute showing which rule fired.
        If return_rule=True, returns (RiskRating, rule_name).
    """
    if score is None:
        rating = RiskRating("Unknown", rule="score_none")
        return (rating, rating.rule) if return_rule else rating

    try:
        numeric_score = int(score)
    except (ValueError, TypeError):
        rating = RiskRating("Unknown", rule="invalid_score")
        return (rating, rating.rule) if return_rule else rating

    findings_list = findings or []

    def _get_severity(f):
        if isinstance(f, dict):
            return str(f.get("severity", "")).lower()
        return str(getattr(f, "severity", "")).lower()

    # 'None' vs 'Low' counts only findings of severity low or higher.
    # A scan with only 'info' findings and score >= 85 is 'None'.
    actionable_severities = {'low', 'medium', 'high', 'critical'}
    has_actionable_findings = any(_get_severity(f) in actionable_severities for f in findings_list)
    has_critical = any(_get_severity(f) == "critical" for f in findings_list)

    if numeric_score >= 85:
        base_risk = 'Low' if has_actionable_findings else 'None'
        base_rule = 'score_band_low' if has_actionable_findings else 'score_band_none'
    elif numeric_score >= 70:
        base_risk = 'Medium'
        base_rule = 'score_band_medium'
    elif numeric_score >= 40:
        base_risk = 'High'
        base_rule = 'score_band_high'
    else:
        base_risk = 'Critical'
        base_rule = 'score_band_critical'

    # Apply critical finding floor: any critical finding -> at least 'High'
    if has_critical and base_risk in ('None', 'Low', 'Medium'):
        final_risk = 'High'
        final_rule = 'critical_finding_floor'
    else:
        final_risk = base_risk
        final_rule = base_rule

    rating = RiskRating(final_risk, rule=final_rule)
    return (rating, final_rule) if return_rule else rating


class Scan(db.Model):
    """Database model representing security scan executions."""
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    target_type = db.Column(db.String(50), nullable=False)  # e.g., 'network', 'dependency', 'container', 'sast'
    target_destination = db.Column(db.String(255), nullable=False)  # IP address, domain, or repository URL
    status = db.Column(db.String(20), default='pending', index=True, nullable=False)  # pending, running, completed, failed
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False)
    risk_score = db.Column(db.Integer, nullable=True)
    risk_level = db.Column(db.String(20), nullable=True)  # e.g., 'Critical', 'High', 'Medium', 'Low', 'None'
    evidence_json = db.Column(db.Text, nullable=True)  # JSON-encoded raw scan evidence telemetry

    @hybrid_property
    def security_score(self):
        """Semantic alias for risk_score representing the Security Compliance Score (0-100)."""
        return self.risk_score

    @security_score.setter
    def security_score(self, value):
        self.risk_score = value

    @hybrid_property
    def authoritative_risk(self):
        """Authoritative risk rating derived from security_score if not explicitly stored."""
        if self.risk_level:
            return RiskRating(self.risk_level, rule="stored_risk_level")
        if self.security_score is None:
            return RiskRating("Unknown", rule="score_none")
        return derive_risk(self.security_score, self.results)

    # Relationships
    results = db.relationship('ScanResult', backref='scan', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='scan', lazy=True, cascade='all, delete-orphan')
    ai_response = db.relationship('AIResponse', backref='scan', uselist=False, lazy=True, cascade='all, delete-orphan')

    def mark_completed(self):
        """Update scan status to completed and record completion timestamp."""
        self.status = 'completed'
        self.completed_at = datetime.now(timezone.utc)

    def mark_failed(self):
        """Update scan status to failed and record completion timestamp."""
        self.status = 'failed'
        self.completed_at = datetime.now(timezone.utc)

    def __repr__(self):
        return f"<Scan {self.target_type} on {self.target_destination} - Status: {self.status}>"


class ScanResult(db.Model):
    """Database model for storing vulnerability findings for a security scan."""
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), index=True, nullable=False)
    vulnerability_name = db.Column(db.String(150), index=True, nullable=False)
    severity = db.Column(db.String(20), index=True, nullable=False)  # critical, high, medium, low, info
    description = db.Column(db.Text, nullable=False)
    remediation = db.Column(db.Text, nullable=True)
    raw_payload = db.Column(db.JSON, nullable=True)  # Store original scanner telemetry/findings payload
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f"<ScanResult {self.vulnerability_name} ({self.severity})>"
