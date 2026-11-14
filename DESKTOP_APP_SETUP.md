# CyberGuard AI – Desktop Application Setup Guide

## Overview

CyberGuard AI can run in two modes:

| Mode | Command | Description |
|------|---------|-------------|
| **Web mode** | `python run.py` | Classic browser-based Flask app |
| **Desktop mode** | `python desktop_app.py` | Native Windows desktop window (PyWebView shell) |

Both modes share **the same Flask backend, database, templates, and security controls**.

---

## Requirements

### Python
- Python 3.11+ (tested on 3.14)
- Virtual environment recommended

### System Dependencies

| Dependency | Required For | Notes |
|------------|-------------|-------|
| **Nmap** | Real network scanning | Optional – mock mode works without it |
| **Microsoft WebView2 Runtime** | Desktop window rendering | Usually pre-installed on Windows 10/11 |

---

## Installation

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Configure environment

Copy `.env.example` to `.env` and fill in the values:

```powershell
copy .env.example .env
```

Edit `.env`:

```env
# Flask – REQUIRED
FLASK_ENV=development
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">

# Database (optional – defaults to cyberguard.db in project root)
DATABASE_URL=sqlite:///cyberguard.db

# Gemini AI – optional (AI features disabled if missing)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

# Logging
LOG_LEVEL=INFO
```

### 4. Initialize the database

```powershell
flask db upgrade
```

---

## Running the Application

### Web mode (browser)

```powershell
python run.py
```

Then open http://127.0.0.1:5000 in your browser.

### Desktop mode (native window)

```powershell
python desktop_app.py
```

The application will:
1. Find a free port (starting at 5000)
2. Start Flask on `127.0.0.1:<port>`
3. Open the CyberGuard AI window via PyWebView (using the system WebView2 runtime)
4. Close the Flask server cleanly when you close the window

---

## Building the Windows Executable (.exe)

### Prerequisites

```powershell
pip install "pyinstaller>=6.0,<7.0"
```

### Build command

```powershell
.venv\Scripts\pyinstaller.exe CyberGuardAI.spec
```

### Output location

```
dist\
  CyberGuardAI\
    CyberGuardAI.exe        ← Main executable
    ...                      ← Supporting DLLs and Python runtime
```

### Running the built executable

```powershell
.\dist\CyberGuardAI\CyberGuardAI.exe
```

> **Important:** The `.env` file is **not embedded** in production builds for security reasons.
> Place your `.env` file in the same directory as `CyberGuardAI.exe` before running.

---

## Nmap Integration

### Real Nmap mode

For real network scanning, Nmap must be installed and available on `PATH`.

**Windows installation:**
1. Download from https://nmap.org/download.html
2. Install with default settings (adds Nmap to `PATH` automatically)
3. Verify: `nmap --version`

### Mock mode

If Nmap is not installed, the application will:
- Display a warning on the network scanner page
- Allow mock scans (simulated results) to work normally
- **Not crash** – all other features continue working

### Configuring a custom Nmap path

Set `NMAP_PATH` in your `.env` if Nmap is in a non-standard location:

```env
NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
```

---

## Gemini AI Configuration

The Gemini AI features use the `GEMINI_API_KEY` environment variable.

```env
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-2.5-flash   # optional, this is the default
```

**Security:** Never hardcode the API key in source code. The key is read from the `.env`
file or system environment at runtime and is never embedded in the executable.

If `GEMINI_API_KEY` is not set:
- AI analysis features will show a graceful error message
- All other features (scanner, vault, reports) continue to work normally

---

## Database Behavior

| Mode | Default Database Location |
|------|--------------------------|
| Web (`python run.py`) | `cyberguard.db` (project root) |
| Desktop (`python desktop_app.py`) | `cyberguard.db` (project root) |
| Compiled `.exe` | `cyberguard.db` (same folder as `.exe`) |

Both modes use the **same SQLite database file** – no data is lost when switching modes.

### Running migrations

```powershell
# Web / development mode
flask db upgrade

# After building the .exe (run from dist\CyberGuardAI\)
.\CyberGuardAI.exe  # First launch auto-initializes tables via create_all fallback
```

---

## Logging

| Log File | Contents |
|----------|----------|
| `logs\cyberguard.log` | Flask application logs (all modes) |
| `logs\desktop.log` | Desktop launcher logs (desktop mode only) |

Logs rotate at 1 MB, keeping 5-10 backups.

---

## Security Notes

- Flask is **always** bound to `127.0.0.1` only in desktop mode – never to `0.0.0.0`
- CSRF protection, authentication, RBAC, SSRF filtering, and security headers are **preserved**
- `SECRET_KEY`, `GEMINI_API_KEY`, and passwords are **never** embedded in the executable
- PyWebView renders the existing Flask UI – no new attack surface is introduced

---

## Troubleshooting

### "SECRET_KEY is not set" error on startup

Add `SECRET_KEY` to your `.env` file:
```powershell
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```
Paste the output into `.env`.

### Desktop window doesn't open / blank screen

1. Check `logs\desktop.log` for errors
2. Ensure Microsoft WebView2 Runtime is installed
   - Download: https://developer.microsoft.com/en-us/microsoft-edge/webview2/
3. Verify Flask started successfully by checking `logs\cyberguard.log`

### "Port already in use" error

The launcher automatically tries ports 5000–5019. If all are busy:
```powershell
# Find and kill the process using port 5000
netstat -ano | findstr :5000
taskkill /PID <pid> /F
```

### PyInstaller build fails

- Ensure the virtual environment is activated
- Run: `pip install -r requirements.txt`
- Check that `pyinstaller --version` works
- If missing hidden imports, add them to the `hidden_imports` list in `CyberGuardAI.spec`

### Nmap not found

- Install Nmap from https://nmap.org
- Restart the terminal/application after installation
- Use **Mock mode** for testing without Nmap

### AI assistant not responding

- Verify `GEMINI_API_KEY` is set in `.env`
- Check `logs\cyberguard.log` for API error details
- Ensure outbound HTTPS (port 443) to `generativelanguage.googleapis.com` is not blocked

---

## File Structure (New Files Added)

```
CyberGuardAi/
├── desktop_app.py          ← NEW: Desktop entry point
├── CyberGuardAI.spec       ← NEW: PyInstaller build configuration
├── DESKTOP_APP_SETUP.md    ← NEW: This file
├── requirements.txt        ← MODIFIED: Added pywebview, pyinstaller
├── desktop/                ← NEW: Desktop package
│   ├── __init__.py
│   ├── config.py           ← Window/server settings
│   ├── launcher.py         ← Startup orchestration
│   ├── server.py           ← Flask lifecycle manager
│   └── window.py           ← PyWebView window management
├── run.py                  ← UNCHANGED: Web mode entry point
├── app/                    ← UNCHANGED: Existing Flask application
└── ...
```
