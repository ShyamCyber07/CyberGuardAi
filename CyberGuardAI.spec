# -*- mode: python ; coding: utf-8 -*-
# CyberGuardAI.spec
# -----------------
# PyInstaller spec file for CyberGuard AI desktop application.
#
# Build command:
#   .venv\Scripts\pyinstaller.exe CyberGuardAI.spec
#
# Output: dist\CyberGuardAI\CyberGuardAI.exe  (one-folder distribution)

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

# ─── Project root (same directory as this spec file) ─────────────────────────
ROOT = Path(SPECPATH)

# ─── Collect all data files ───────────────────────────────────────────────────
# templates, static assets, migrations, and the desktop sub-package
added_files = [
    # Flask templates
    (str(ROOT / "app" / "templates"), "app/templates"),
    # Static assets (CSS, JS, vendor, reports placeholder)
    (str(ROOT / "app" / "static"),    "app/static"),
    # Alembic migration scripts (needed for flask db upgrade)
    (str(ROOT / "migrations"),        "migrations"),
    # Desktop package
    (str(ROOT / "desktop"),           "desktop"),
    # Config file
    (str(ROOT / "config.py"),         "."),
]

# Include .env if present (production builds should NOT include secrets;
# users should place .env next to the .exe instead).
# We include it here for development convenience ONLY.
env_file = ROOT / ".env"
if env_file.exists():
    added_files.append((str(env_file), "."))

# ─── Hidden imports ───────────────────────────────────────────────────────────
# PyInstaller cannot always detect dynamic imports (blueprints, plugins, etc.)
hidden_imports = [
    # Flask ecosystem
    "flask",
    "flask_sqlalchemy",
    "flask_migrate",
    "flask_login",
    "flask_wtf",
    "flask_bcrypt",
    "flask_limiter",
    "flask_limiter.util",
    "limits",
    "limits.storage.memory",
    "limits.strategies",
    "wtforms",
    "wtforms.validators",
    "email_validator",
    "alembic",
    "alembic.runtime.migration",
    "alembic.operations.ops",
    "sqlalchemy",
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.orm",
    # Cryptography / password vault
    "cryptography",
    "cryptography.fernet",
    "bcrypt",
    # HTTP / networking
    "requests",
    "urllib3",
    "certifi",
    "charset_normalizer",
    "chardet",
    "idna",
    # Reporting
    "reportlab",
    "reportlab.pdfgen",
    "reportlab.lib",
    "reportlab.lib.pagesizes",
    "reportlab.lib.styles",
    "reportlab.platypus",
    # App modules (blueprints load dynamically)
    "app",
    "app.extensions",
    "app.models",
    "app.models.user",
    "app.models.scan",
    "app.models.network_scan",
    "app.models.saved_password",
    "app.models.report",
    "app.models.threat",
    "app.models.audit",
    "app.models.ai",
    "app.routes",
    "app.routes.main.routes",
    "app.routes.auth.routes",
    "app.routes.scanner.routes",
    "app.routes.network_scanner.routes",
    "app.routes.password_security.routes",
    "app.routes.admin",
    "app.routes.assistant",
    "app.services.scanner_service",
    "app.services.network_scan_service",
    "app.services.gemini_service",
    "app.services.ai_service",
    "app.services.ai_assistant_service",
    "app.services.password_service",
    "app.services.pdf_service",
    "app.services.risk_calculator",
    "app.repositories",
    "app.repositories.network_scan_repository",
    # Desktop
    "desktop",
    "desktop.launcher",
    "desktop.server",
    "desktop.window",
    "desktop.config",
    # PyWebView dependencies
    "webview",
    "webview.platforms",
    "clr",
    "pythonnet",
    # dotenv
    "dotenv",
    # Standard library extras sometimes missed
    "logging.handlers",
    "xml.etree.ElementTree",
    "ipaddress",
    "socket",
    "shutil",
    "subprocess",
    "threading",
    "tkinter",
    "tkinter.messagebox",
]

# ─── Analysis ─────────────────────────────────────────────────────────────────
a = Analysis(
    ["desktop_app.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=added_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pytest",
        "pytest_cov",
        "coverage",
        "selenium",
        "webdriver_manager",
        "gunicorn",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ─── Executable ───────────────────────────────────────────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CyberGuardAI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # Disable UPX – can trigger AV false positives
    console=False,      # No console window (windowed app)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon="app/static/favicon.ico",  # Uncomment if you have an .ico file
)

# ─── One-folder collection ────────────────────────────────────────────────────
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CyberGuardAI",
)
