"""
desktop/config.py
-----------------
Configuration constants and helpers for the CyberGuard AI desktop launcher.
Does NOT contain any secrets – those are loaded from .env / environment.
"""

import os
import sys
import socket
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────

def get_base_dir() -> Path:
    """
    Return the project root / distribution root directory.

    When frozen by PyInstaller the executable is at dist/CyberGuardAI/CyberGuardAI.exe,
    so the 'root' for user data (database, logs, user-placed .env) is the exe's directory.
    When running as plain Python, __file__ is inside desktop/, so go up one level.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller one-folder: exe lives in dist/CyberGuardAI/
        return Path(sys.executable).parent
    # Normal Python run: desktop/config.py -> project root
    return Path(__file__).resolve().parent.parent


def get_meipass_dir() -> Path | None:
    """
    Return the PyInstaller _MEIPASS extraction directory, or None when not frozen.

    _MEIPASS is the temp folder where PyInstaller extracts bundled Python files,
    templates, static assets, and any data files added via the spec's 'datas' list.
    It is NOT the same as the exe directory (BASE_DIR).
    """
    meipass = getattr(sys, "_MEIPASS", None)
    return Path(meipass) if meipass else None


def find_env_file() -> Path | None:
    """
    Locate the .env file by searching candidate directories in priority order:

    1. Next to the executable / project root  (user-placed, takes precedence)
    2. Inside PyInstaller's _MEIPASS bundle   (the .env copied by the spec file)
    3. Fallback: BASE_DIR again               (covers the normal Python case)

    Returns the first existing path, or None if .env is not found anywhere.
    """
    candidates: list[Path] = []

    # 1. User-placed .env next to the exe (or project root in dev mode)
    candidates.append(BASE_DIR / ".env")

    # 2. Bundled .env inside _MEIPASS (PyInstaller frozen builds)
    meipass = get_meipass_dir()
    if meipass:
        candidates.append(meipass / ".env")

    for path in candidates:
        if path.exists():
            return path

    return None


BASE_DIR: Path = get_base_dir()

# ─── Window settings ──────────────────────────────────────────────────────────

WINDOW_TITLE = "CyberGuard AI"
WINDOW_MIN_WIDTH = 1200
WINDOW_MIN_HEIGHT = 700
WINDOW_START_WIDTH = 1400
WINDOW_START_HEIGHT = 800

# ─── Flask server settings ────────────────────────────────────────────────────

FLASK_HOST = "127.0.0.1"           # Never bind to 0.0.0.0 - desktop-only
FLASK_DEFAULT_PORT = 5000
FLASK_STARTUP_TIMEOUT = 30         # seconds to wait for Flask to be ready
FLASK_STARTUP_POLL_INTERVAL = 0.2  # seconds between readiness checks

# ─── Desktop logging ──────────────────────────────────────────────────────────

DESKTOP_LOG_FILE = BASE_DIR / "logs" / "desktop.log"
DESKTOP_LOG_MAX_BYTES = 1 * 1024 * 1024   # 1 MB
DESKTOP_LOG_BACKUP_COUNT = 5

# ─── Flask environment for the desktop build ─────────────────────────────────

FLASK_ENV = "development"          # uses DevelopmentConfig (no HTTPS requirement)


def find_free_port(start: int = FLASK_DEFAULT_PORT) -> int:
    """
    Find a free TCP port starting from *start*.
    Tries up to 20 consecutive ports before giving up.
    """
    for port in range(start, start + 20):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((FLASK_HOST, port))
                return port
        except OSError:
            continue
    raise RuntimeError(
        f"Could not find a free port in range {start}-{start + 19}. "
        "Please close other applications and try again."
    )
