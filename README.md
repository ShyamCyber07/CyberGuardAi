# CyberGuard AI

CyberGuard AI is a professional, modular, secure cybersecurity monitoring web application built with Python, Flask, SQLite, and Bootstrap 5.

## Technology Stack

- **Frontend:** HTML5, CSS3, Bootstrap 5, JavaScript
- **Backend:** Python, Flask
- **Database:** SQLite (SQLAlchemy ORM)
- **Migrations:** Flask-Migrate (Alembic)
- **Security & Forms:** Flask-WTF, Flask-Login, Secure Configuration

## Directory Structure

```text
CyberGuardAi/
├── app/
│   ├── __init__.py          # Application Factory
│   ├── extensions.py        # Extensions initialization (SQLAlchemy, LoginManager, etc.)
│   ├── models/              # SQLAlchemy Database Models
│   │   └── __init__.py
│   ├── routes/              # Flask Blueprints
│   │   ├── __init__.py
│   │   └── main/
│   │       ├── __init__.py
│   │       └── routes.py
│   ├── static/              # Static assets (CSS, JS, Images)
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       └── main.js
│   └── templates/           # Jinja2 HTML Templates
│       ├── base.html
│       └── main/
│           └── index.html
├── .env                     # Local environment secrets (ignored by Git)
├── .env.example             # Example environment template
├── .gitignore               # Git ignored patterns
├── config.py                # Configuration classes (Dev, Prod, Test)
├── README.md                # Project documentation
├── requirements.txt         # Dependency declarations
└── run.py                   # App entrypoint script
```

## Getting Started

### Prerequisites

- **Python:** Python 3.10, 3.11, or 3.12 is recommended. (Verified with Python 3.12/3.14).
- **Nmap (Optional but Recommended):**
  - To perform local ports audits using the Network Security Scanner, **Nmap** must be installed on the host system.
  - **Windows:** Download the installer from [nmap.org](https://nmap.org/download.html) and add the Nmap installation directory (usually `C:\Program Files (x86)\Nmap`) to the system PATH.
  - **Linux (Debian/Ubuntu):** Install via package manager:
    ```bash
    sudo apt-get update && sudo apt-get install -y nmap
    ```

### Installation

1. **Clone or download the project** to your local workspace.
2. **Initialize virtual environment:**
   ```bash
   python -m venv .venv
   ```
3. **Activate the virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     .venv\Scripts\Activate.ps1
     ```
   - **Linux/macOS:**
     ```bash
     source .venv/bin/activate
     ```
4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
5. **Set up environment variables:**
   Copy `.env.example` to `.env` and fill in your custom values.
   ```bash
   copy .env.example .env
   ```
   *Note: In order to run AI-assisted vulnerability analysis or the AI Chat Assistant, you must procure a Gemini API Key from Google AI Studio and configure `GEMINI_API_KEY` in the `.env` file.*

6. **Initialize the database migrations:**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

### Running the Application

To start the Flask development server:
```bash
python run.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your web browser.

### Running the Test Suite

To execute the automated unit and integration tests (including coverage calculation):
```bash
python -m pytest -v
```

