"""
desktop/launcher.py
-------------------
Orchestrates the full desktop startup sequence:

  1. Configure desktop logging (single handler, no duplicates).
  2. Load environment / secrets from .env.
  3. Validate critical configuration.
  4. Find a free localhost port.
  5. Start the Flask server in a background thread.
  6. Wait until Flask is ready.
  7. Open the PyWebView window.
  8. Block until the window is closed.
  9. Shut everything down cleanly.

This module is imported by desktop_app.py (project root entry point).
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path

from desktop.config import (
    BASE_DIR,
    DESKTOP_LOG_BACKUP_COUNT,
    DESKTOP_LOG_FILE,
    DESKTOP_LOG_MAX_BYTES,
    FLASK_HOST,
    FLASK_STARTUP_POLL_INTERVAL,
    FLASK_STARTUP_TIMEOUT,
    find_env_file,
    find_free_port,
)
from desktop.server import start_flask_server, stop_flask_server
from desktop.window import (
    create_window,
    run_window,
    show_flask_error,
)

logger = logging.getLogger(__name__)

_logging_configured = False  # Guard against duplicate handler setup


def _configure_desktop_logging() -> None:
    """
    Set up a file + console logger for the desktop launcher.
    Uses a module-level guard so re-imports never add duplicate handlers.
    """
    global _logging_configured
    if _logging_configured:
        return
    _logging_configured = True

    # Ensure logs directory exists
    DESKTOP_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        DESKTOP_LOG_FILE,
        maxBytes=DESKTOP_LOG_MAX_BYTES,
        backupCount=DESKTOP_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    # Console handler (visible in terminal / PyInstaller console window)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Only add handlers that are not already present
    existing_types = {type(h) for h in root_logger.handlers}
    if logging.handlers.RotatingFileHandler not in existing_types:
        root_logger.addHandler(file_handler)
    if logging.StreamHandler not in existing_types:
        root_logger.addHandler(console_handler)


def _load_env() -> None:
    """
    Load .env secrets into os.environ.

    Search order (first match wins):
      1. <exe_dir>/.env       – user-placed file next to the executable
      2. <_MEIPASS>/.env      – bundled file extracted by PyInstaller

    Uses override=True so that a blank/empty system-level env var does not
    silently shadow a value defined in the .env file.
    """
    try:
        from dotenv import load_dotenv

        env_path = find_env_file()
        if env_path:
            # override=True: .env values win over blank/unset system env vars
            loaded = load_dotenv(env_path, override=True)
            if loaded:
                logger.debug("Environment loaded from %s", env_path)
            else:
                logger.warning("load_dotenv() returned False for %s", env_path)
        else:
            logger.warning(
                ".env not found in any expected location "
                "(checked next to exe and inside bundle). "
                "Relying on system environment variables."
            )
    except ImportError:
        logger.warning("python-dotenv is not installed; skipping .env loading.")


def _validate_env() -> list[str]:
    """
    Check for required environment variables.
    Returns a list of human-readable error messages (empty = all good).
    """
    errors: list[str] = []

    if not os.environ.get("SECRET_KEY"):
        errors.append(
            "SECRET_KEY is not set.\n"
            "Add SECRET_KEY=<random 64-char hex string> to your .env file."
        )

    return errors


def launch() -> None:
    """
    Main entry point called by desktop_app.py.
    Runs the full startup + window lifecycle.
    """
    _configure_desktop_logging()
    logger.info("=" * 60)
    logger.info("CyberGuard AI Desktop – starting up")
    logger.info("Base directory: %s", BASE_DIR)
    logger.info("=" * 60)

    # ── 1. Load environment ────────────────────────────────────────────────
    _load_env()

    # ── 2. Validate critical config ────────────────────────────────────────
    env_errors = _validate_env()
    if env_errors:
        from desktop.window import _show_error_dialog

        error_text = "\n\n".join(env_errors)
        logger.error("Configuration validation failed:\n%s", error_text)
        _show_error_dialog(
            "CyberGuard AI – Configuration Error",
            f"The application cannot start due to missing configuration:\n\n{error_text}",
        )
        sys.exit(1)

    # ── 3. Find a free port ────────────────────────────────────────────────
    try:
        port = find_free_port()
        logger.info("Using port %d for Flask server.", port)
    except RuntimeError as exc:
        from desktop.window import _show_error_dialog

        logger.error("Port selection failed: %s", exc)
        _show_error_dialog("CyberGuard AI – Port Error", str(exc))
        sys.exit(1)

    url = f"http://{FLASK_HOST}:{port}/"

    # ── 4. Start Flask ─────────────────────────────────────────────────────
    flask_ok = start_flask_server(
        host=FLASK_HOST,
        port=port,
        base_dir=BASE_DIR,
        timeout=FLASK_STARTUP_TIMEOUT,
        poll_interval=FLASK_STARTUP_POLL_INTERVAL,
    )

    if not flask_ok:
        logger.error("Flask failed to start. See logs for details.")
        show_flask_error(port)
        sys.exit(1)

    logger.info("Flask is ready at %s", url)

    # ── 5. Create the PyWebView window ─────────────────────────────────────
    window = create_window(url)
    if window is None:
        logger.error("Could not create the desktop window.")
        stop_flask_server()
        sys.exit(1)

    # ── 6. Enter the event loop ────────────────────────────────────────────
    logger.info("Entering PyWebView event loop …")
    run_window(on_closed=stop_flask_server)

    logger.info("CyberGuard AI Desktop – shutdown complete.")
