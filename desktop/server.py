"""
desktop/server.py
-----------------
Manages the Flask server lifecycle for the desktop application.

Responsibilities:
- Start Flask in a background daemon thread.
- Poll until Flask is ready (avoid blank-screen race condition).
- Shut down cleanly when the desktop window closes.
- Never bind to anything other than 127.0.0.1.
"""

import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Internal state
# ──────────────────────────────────────────────────────────────────────────────

_flask_thread: Optional[threading.Thread] = None
_shutdown_event = threading.Event()


def _ensure_env(base_dir: Path) -> None:
    """
    Load .env into os.environ (idempotent).

    Searches in priority order:
      1. Next to the executable / project root  (user-placed)
      2. Inside PyInstaller _MEIPASS bundle     (bundled by spec)

    Uses override=True so blank system env vars do not shadow .env values.
    """
    try:
        from dotenv import load_dotenv
        from desktop.config import find_env_file

        env_path = find_env_file()
        if env_path:
            load_dotenv(env_path, override=True)
            logger.debug("Loaded environment from %s", env_path)
        else:
            logger.debug("No .env file found; relying on system environment.")
    except ImportError:
        logger.warning("python-dotenv not available; skipping .env loading")


def _patch_sys_path(base_dir: Path) -> None:
    """
    Ensure the project root is on sys.path so that 'from app import ...' works
    both in normal Python mode and when running from a PyInstaller bundle.
    """
    root_str = str(base_dir)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

    # In a frozen bundle PyInstaller puts the extracted app code in _MEIPASS.
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass and meipass not in sys.path:
        sys.path.insert(0, meipass)


def _run_flask(host: str, port: int, base_dir: Path) -> None:
    """
    Target function for the Flask background thread.
    Creates a fresh app instance (DevelopmentConfig) and runs the Werkzeug
    dev server with threading enabled so concurrent requests don't deadlock.
    """
    try:
        _patch_sys_path(base_dir)
        _ensure_env(base_dir)

        # Change working directory so Flask can find templates/static in the
        # right place when frozen.
        os.chdir(base_dir)

        from app import create_app  # noqa: PLC0415

        flask_env = os.environ.get("FLASK_ENV", "development")
        app = create_app(flask_env)

        logger.info("Starting Flask on %s:%d (env=%s)", host, port, flask_env)

        app.run(
            host=host,
            port=port,
            debug=False,           # No reloader – we manage the process
            use_reloader=False,    # Critical: reloader would fork a child process
            threaded=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Flask server crashed: %s", exc)
        _shutdown_event.set()   # Signal the window to close / show error


def start_flask_server(
    host: str,
    port: int,
    base_dir: Path,
    timeout: float = 30.0,
    poll_interval: float = 0.2,
) -> bool:
    """
    Start Flask in a daemon thread and block until it is accepting connections
    or *timeout* seconds elapse.

    Returns True if Flask started successfully, False otherwise.
    """
    global _flask_thread

    _flask_thread = threading.Thread(
        target=_run_flask,
        args=(host, port, base_dir),
        daemon=True,   # Dies automatically when the main process exits
        name="CyberGuardAI-Flask",
    )
    _flask_thread.start()
    logger.info("Flask thread started; waiting for server to be ready …")

    deadline = time.monotonic() + timeout
    health_url = f"http://{host}:{port}/"

    while time.monotonic() < deadline:
        # If the thread died early, bail out immediately.
        if not _flask_thread.is_alive():
            logger.error("Flask thread terminated before becoming ready.")
            return False

        try:
            resp = requests.get(health_url, timeout=1)
            # Any response (including 302 redirect to login) means Flask is up.
            logger.info("Flask ready – HTTP %d from %s", resp.status_code, health_url)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(poll_interval)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Waiting for Flask (%s) …", exc)
            time.sleep(poll_interval)

    logger.error("Flask did not become ready within %.0f seconds.", timeout)
    return False


def stop_flask_server() -> None:
    """
    Signal the Flask thread to stop.
    Because we use Werkzeug's dev server with use_reloader=False and the
    thread is a daemon, the process will exit and clean up automatically.
    This function just logs the intent.
    """
    logger.info("Desktop window closed – shutting down Flask server.")
    _shutdown_event.set()
    # The daemon thread will be killed when the main process exits.
