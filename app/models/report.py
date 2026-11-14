import uuid
from datetime import datetime, timezone
from app.extensions import db

class Report(db.Model):
    """Database model for cybersecurity status reporting."""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    title = db.Column(db.String(150), nullable=False)
    summary = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='draft', index=True, nullable=False)  # draft, finalized, archived
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Foreign Keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), index=True, nullable=True)
    network_scan_id = db.Column(db.Integer, db.ForeignKey('network_scans.id', ondelete='CASCADE'), index=True, nullable=True)

    # Relationships
    ai_responses = db.relationship('AIResponse', backref='report', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Report {self.title} - Status: {self.status}>"
