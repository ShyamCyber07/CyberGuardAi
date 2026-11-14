"""
desktop_app.py
--------------
Root-level entry point for the CyberGuard AI desktop application.

Usage (development):
    python desktop_app.py

Usage (compiled .exe):
    CyberGuardAI.exe

The existing web-mode entry point (python run.py) is unaffected.
"""

import sys
import os

# ---------------------------------------------------------------------------
# When frozen by PyInstaller, ensure the bundle root is on sys.path so that
# 'import app', 'import config', 'import desktop' all resolve correctly.
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    # _MEIPASS is the temp directory where PyInstaller extracts files.
    bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    exe_dir = os.path.dirname(sys.executable)

    for p in (bundle_dir, exe_dir):
        if p not in sys.path:
            sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from desktop.launcher import launch
    launch()
