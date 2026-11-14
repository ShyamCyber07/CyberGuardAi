import uuid
from datetime import datetime, timezone
from app.extensions import db

class SavedPassword(db.Model):
    """Database model representing user encrypted credentials stored in the security vault."""
    __tablename__ = 'saved_passwords'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)  # User description (e.g. "Work Email", "API Key")
    encrypted_password = db.Column(db.Text, nullable=False)
    encryption_version = db.Column(db.Integer, default=2, server_default='1', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False)

    def __repr__(self):
        return f"<SavedPassword {self.label} for User ID {self.user_id}>"
