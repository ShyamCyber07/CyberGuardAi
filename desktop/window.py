"""
desktop/window.py
-----------------
Creates and manages the PyWebView desktop window for CyberGuard AI.

The window simply wraps the already-running Flask HTTP server at
http://127.0.0.1:<port>.  All Flask security controls remain intact –
PyWebView acts purely as a thin rendering shell.
"""

import logging
import sys
import tkinter as tk
from tkinter import messagebox
from typing import Optional

import webview

# Enable file downloads in PyWebView (WebView2 defaults to False, which blocks PDF exports)
webview.settings['ALLOW_DOWNLOADS'] = True

from desktop.config import (
    WINDOW_TITLE,
    WINDOW_START_WIDTH,
    WINDOW_START_HEIGHT,
    WINDOW_MIN_WIDTH,
    WINDOW_MIN_HEIGHT,
)

logger = logging.getLogger(__name__)


def _show_error_dialog(title: str, message: str) -> None:
    """
    Display a native Windows error dialog using tkinter (no Qt/wxPython needed).
    Falls back to printing on import failure.
    """
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the empty Tk window
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:  # noqa: BLE001
        print(f"ERROR [{title}]: {message}", file=sys.stderr)


def create_window(url: str) -> Optional[webview.Window]:
    """
    Create and return a PyWebView window pointed at *url*.
    Returns None on failure.
    """
    try:
        window = webview.create_window(
            title=WINDOW_TITLE,
            url=url,
            width=WINDOW_START_WIDTH,
            height=WINDOW_START_HEIGHT,
            min_size=(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT),
            resizable=True,
            # frameless=False means native OS window chrome (title bar, borders)
            frameless=False,
            # text_select allows selecting text in the UI (useful for copy/paste)
            text_select=True,
            # confirm_close prompts before closing (disable for seamless UX)
            confirm_close=False,
        )
        logger.info(
            "PyWebView window created: '%s' -> %s (%dx%d)",
            WINDOW_TITLE,
            url,
            WINDOW_START_WIDTH,
            WINDOW_START_HEIGHT,
        )
        return window
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to create PyWebView window: %s", exc)
        _show_error_dialog(
            "Window Error",
            f"CyberGuard AI could not create the desktop window.\n\nDetail: {exc}",
        )
        return None


def run_window(on_closed=None) -> None:
    """
    Enter the PyWebView event loop (blocks until window is closed).

    *on_closed* is an optional callback invoked when the window is destroyed –
    use it to trigger Flask shutdown.
    """
    try:
        webview.start(
            debug=False,      # Set True for DevTools console during development
            # http_server is handled by our own Flask thread, not PyWebView's built-in
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("PyWebView event loop error: %s", exc)
    finally:
        if on_closed:
            try:
                on_closed()
            except Exception:  # noqa: BLE001
                pass


def show_flask_error(port: int) -> None:
    """Show an error dialog when Flask fails to start."""
    _show_error_dialog(
        "CyberGuard AI – Startup Error",
        f"The application server failed to start on port {port}.\n\n"
        "Possible causes:\n"
        "  • Port is already in use by another process\n"
        "  • Missing required environment variables (SECRET_KEY)\n"
        "  • Database could not be opened\n\n"
        "Check logs\\desktop.log for details.",
    )


def show_db_error(db_path: str) -> None:
    """Show an error dialog when the database cannot be opened."""
    _show_error_dialog(
        "CyberGuard AI – Database Error",
        f"The application database could not be opened:\n  {db_path}\n\n"
        "Please check file permissions and disk space.",
    )
