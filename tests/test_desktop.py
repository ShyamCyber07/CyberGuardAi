"""
tests/test_desktop.py
---------------------
Unit tests for the desktop launcher modules.

These tests do NOT open a real window or start a real Flask server.
They verify that all desktop modules import correctly, that config
values are sane, and that the port-finding utility works.
"""

import importlib
import os
import socket
import sys
import threading
import time
import pytest


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _bind_port(port: int) -> socket.socket:
    """Bind and listen on localhost:port and return it (caller must close).

    We call listen() so the OS marks the port as truly in use.
    Using SO_REUSEADDR=0 ensures our own bind in find_free_port() fails.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Do NOT set SO_REUSEADDR – we want subsequent bind() calls to fail
    s.bind(("127.0.0.1", port))
    s.listen(1)
    return s


# ─── desktop.config ───────────────────────────────────────────────────────────

class TestDesktopConfig:
    def test_import(self):
        from desktop.config import (
            WINDOW_TITLE,
            WINDOW_MIN_WIDTH,
            WINDOW_MIN_HEIGHT,
            WINDOW_START_WIDTH,
            WINDOW_START_HEIGHT,
            FLASK_HOST,
            FLASK_DEFAULT_PORT,
            FLASK_STARTUP_TIMEOUT,
            BASE_DIR,
            find_free_port,
            find_env_file,
            get_meipass_dir,
        )
        assert WINDOW_TITLE == "CyberGuard AI"
        assert WINDOW_MIN_WIDTH >= 1200
        assert WINDOW_MIN_HEIGHT >= 700
        assert FLASK_HOST == "127.0.0.1"
        assert FLASK_DEFAULT_PORT > 0
        assert FLASK_STARTUP_TIMEOUT > 0
        assert BASE_DIR.exists()

    def test_find_env_file_finds_project_env(self):
        """find_env_file() must locate the project .env when running in dev mode."""
        from desktop.config import find_env_file, BASE_DIR
        # In dev mode (not frozen), BASE_DIR is the project root which has .env
        env_path = find_env_file()
        assert env_path is not None, "find_env_file() returned None – .env not found"
        assert env_path.exists(), f".env path does not exist: {env_path}"
        assert env_path.name == ".env"

    def test_get_meipass_dir_none_in_dev(self):
        """get_meipass_dir() must return None when not running as a frozen exe."""
        from desktop.config import get_meipass_dir
        # In normal Python mode there is no _MEIPASS
        result = get_meipass_dir()
        assert result is None, f"Expected None outside PyInstaller, got {result}"

    def test_base_dir_is_project_root(self):
        from desktop.config import BASE_DIR
        # Project root should contain run.py and config.py
        assert (BASE_DIR / "run.py").exists(), "run.py should be in BASE_DIR"
        assert (BASE_DIR / "config.py").exists(), "config.py should be in BASE_DIR"

    def test_find_free_port_returns_integer(self):
        from desktop.config import find_free_port
        port = find_free_port(start=19000)
        assert isinstance(port, int)
        assert 19000 <= port < 19020

    def test_find_free_port_skips_busy_port(self):
        from desktop.config import find_free_port
        # Bind+listen on port 19100 so it is truly busy
        s = _bind_port(19100)
        try:
            port = find_free_port(start=19100)
            # Should skip 19100 and return 19101+
            assert port != 19100
            assert port >= 19101
        finally:
            s.close()


# ─── desktop.server ───────────────────────────────────────────────────────────

class TestDesktopServer:
    def test_import(self):
        """Server module must import without side effects."""
        from desktop.server import start_flask_server, stop_flask_server
        assert callable(start_flask_server)
        assert callable(stop_flask_server)

    def test_stop_before_start_is_safe(self):
        """Calling stop without having started should not raise."""
        from desktop import server as srv
        # Reset internal state
        srv._flask_thread = None
        srv._shutdown_event.clear()
        # Should not raise
        srv.stop_flask_server()


# ─── desktop.window ───────────────────────────────────────────────────────────

class TestDesktopWindow:
    def test_import(self):
        """Window module must import without opening a real window."""
        from desktop.window import (
            create_window,
            run_window,
            show_flask_error,
            show_db_error,
            _show_error_dialog,
        )
        assert callable(create_window)
        assert callable(run_window)
        assert callable(show_flask_error)
        assert callable(show_db_error)
        assert callable(_show_error_dialog)


# ─── desktop.launcher ─────────────────────────────────────────────────────────

class TestDesktopLauncher:
    def test_import(self):
        from desktop.launcher import (
            _configure_desktop_logging,
            _load_env,
            _validate_env,
            launch,
        )
        assert callable(launch)

    def test_configure_logging_idempotent(self):
        """Calling _configure_desktop_logging twice must not add duplicate handlers."""
        import logging
        from desktop import launcher
        # Reset guard
        launcher._logging_configured = False
        root = logging.getLogger()
        before = len(root.handlers)

        launcher._configure_desktop_logging()
        after_first = len(root.handlers)

        launcher._configure_desktop_logging()  # Second call – should be no-op
        after_second = len(root.handlers)

        assert after_first == after_second, (
            "Second call to _configure_desktop_logging added duplicate handlers"
        )
        # Clean up: reset flag so other tests are not affected
        launcher._logging_configured = False

    def test_validate_env_catches_missing_secret_key(self, monkeypatch):
        """_validate_env must report an error when SECRET_KEY is absent."""
        from desktop.launcher import _validate_env
        monkeypatch.delenv("SECRET_KEY", raising=False)
        errors = _validate_env()
        assert len(errors) >= 1
        assert any("SECRET_KEY" in e for e in errors)

    def test_validate_env_passes_when_secret_key_set(self, monkeypatch):
        """_validate_env must return empty list when SECRET_KEY is present."""
        from desktop.launcher import _validate_env
        monkeypatch.setenv("SECRET_KEY", "a" * 32)
        errors = _validate_env()
        assert errors == []
