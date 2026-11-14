from datetime import datetime, timezone
from app.extensions import db

class AuditLog(db.Model):
    """Database model for security-sensitive system and user actions."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), index=True, nullable=False)  # e.g., 'login_success', 'scan_triggered', 'report_deleted'
    ip_address = db.Column(db.String(45), nullable=True)  # Supports both IPv4 and IPv6
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    
    # Foreign Key (Nullable for unauthenticated events such as failed logins)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), index=True, nullable=True)

    def __repr__(self):
        return f"<AuditLog {self.action} at {self.timestamp}>"
