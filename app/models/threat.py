from datetime import datetime, timezone
from app.extensions import db

class ThreatLog(db.Model):
    """Database model for storing recorded security threat logs and events."""
    __tablename__ = 'threat_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    threat_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=True)
    resolved = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f"<ThreatLog {self.threat_type} - {self.severity} (IP: {self.source_ip})>"
