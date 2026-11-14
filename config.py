import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env
load_dotenv(BASE_DIR / '.env')

class Config:
    """Base configuration settings."""
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("No SECRET_KEY set in the environment variables.")
        
    GEMINI_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configure security headers and settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Remember Cookies flags
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    
    # File upload protection (Max request size limit: 5MB)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    
    # Session Timeout (15 minutes inactivity)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    
    # Flask-WTF CSRF protection
    WTF_CSRF_ENABLED = True
    
    # Demonstration / Simulated Scanner Mode gating (default False)
    DEMO_MODE = os.environ.get('DEMO_MODE', 'false').lower() in ('true', '1')

class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    ENV = 'development'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{BASE_DIR / 'instance' / 'cyberguard.db'}"
    # In development, session cookie secure can be False for non-https local dev
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'true').lower() in ('true', '1')

class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    DEBUG = True
    LOGIN_DISABLED = False
    RATELIMIT_ENABLED = False
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'test_temp.db'}"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    DEMO_MODE = True

class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    ENV = 'production'
    
    # Retrieve and sanitize DATABASE_URL dynamically (handling postgres:// to postgresql:// transitions)
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
        
    SQLALCHEMY_DATABASE_URI = db_url or f"sqlite:///{BASE_DIR / 'instance' / 'cyberguard_prod.db'}"
    
    # Ensure strict security in production
    @classmethod
    def init_app(cls, app):
        # Ensure the instance directory exists in case we default to SQLite
        os.makedirs(BASE_DIR / 'instance', exist_ok=True)

# Mapping configurations
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
