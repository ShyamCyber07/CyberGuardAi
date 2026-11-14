import uuid
from datetime import datetime, timezone
from flask_login import UserMixin
from app.extensions import db, bcrypt

class User(UserMixin, db.Model):
    """Database model for user authentication, roles, and profiles."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='analyst', nullable=False)  # Options: 'admin', 'analyst', 'auditor'
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scans = db.relationship('Scan', backref='creator', lazy=True, cascade='all, delete-orphan')
    network_scans = db.relationship('NetworkScan', backref='network_creator', lazy=True, cascade='all, delete-orphan')
    saved_passwords = db.relationship('SavedPassword', backref='owner', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='creator', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='actor', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        """Hash and set the user's password."""
        if not password:
            raise ValueError("Password must not be empty.")
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Verify the user's password."""
        if not password or not self.password_hash:
            return False
        return bcrypt.check_password_hash(self.password_hash, password)

    def has_role(self, role_name):
        """Check if the user has a specific security clearance/role."""
        return self.role == role_name

    def __repr__(self):
        return f"<User {self.email} - Role: {self.role}>"
