import os
import sys
import ipaddress
import socket
import pytest

# Ensure project root is in system path for test discovery
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def pytest_configure(config):
    config.addinivalue_line("markers", "network: mark test as requiring external internet access (e.g. live SSL handshake to example.com:443)")

from app import create_app
from app.extensions import db as _db
from app.models.user import User
from app.services.ai_service import reset_quota_cooldown, clear_analysis_cache
from app.services.ai_assistant_service import clear_assistant_cache


def _is_loopback_address(address):
    """Check if socket address connects to a local loopback destination."""
    if isinstance(address, tuple) and len(address) > 0:
        host = address[0]
    elif isinstance(address, str):
        host = address
    else:
        return True

    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def block_external_network_and_keys(monkeypatch):
    """
    Autouse fixture that deletes GEMINI_API_KEY from os.environ and
    blocks non-loopback socket.connect to ensure deterministic offline tests.
    """
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex

    def guarded_connect(self, address):
        if not _is_loopback_address(address):
            raise RuntimeError(f"Non-loopback socket.connect blocked in tests: {address}")
        return orig_connect(self, address)

    def guarded_connect_ex(self, address):
        if not _is_loopback_address(address):
            raise RuntimeError(f"Non-loopback socket.connect_ex blocked in tests: {address}")
        return orig_connect_ex(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)


@pytest.fixture(autouse=True)
def clean_ai_service_state():
    """Ensure in-memory quota cooldown and caches are clean for every test."""
    reset_quota_cooldown()
    clear_analysis_cache()
    clear_assistant_cache()
    yield
    reset_quota_cooldown()
    clear_analysis_cache()
    clear_assistant_cache()

@pytest.fixture(scope='function')
def app():
    """Function-scoped test application factory."""
    app = create_app('testing')
    
    # Establish application context before running tests
    with app.app_context():
        yield app
        
    # Clean up file after session completes
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    db_path = db_uri.replace('sqlite:///', '')
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass

@pytest.fixture(scope='function')
def db(app):
    """Function-scoped test database setup and teardown."""
    _db.create_all()
    
    yield _db
    
    _db.session.remove()
    _db.drop_all()
    _db.engine.dispose()

@pytest.fixture(scope='function')
def client(app, db):
    """Test HTTP client fixture."""
    return app.test_client()

@pytest.fixture(scope='function')
def test_users(db):
    """Seed test users database table with multiple roles."""
    admin = User(email="admin@test.com", role="admin")
    admin.set_password("AdminPass123!")
    
    analyst = User(email="analyst@test.com", role="analyst")
    analyst.set_password("AnalystPass123!")
    
    standard = User(email="user@test.com", role="analyst") # Use analyst/admin choices valid in registration forms
    standard.set_password("UserPass123!")
    
    db.session.add_all([admin, analyst, standard])
    db.session.commit()
    
    return {
        'admin': admin,
        'analyst': analyst,
        'user': standard
    }
