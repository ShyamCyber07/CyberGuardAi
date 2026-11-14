import os
import multiprocessing

# Bind socket address
bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:8000")

# Worker settings
# Recommended formula: 2 * cores + 1
workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
threads = int(os.environ.get("GUNICORN_THREADS", 2))

# Timeout to allow slightly longer tasks (e.g. PDF generation, AI processing) to complete
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 120))

# Logging configuration
# Ensure the logs directory exists
os.makedirs("logs", exist_ok=True)
accesslog = os.environ.get("GUNICORN_ACCESSLOG", "logs/gunicorn-access.log")
errorlog = os.environ.get("GUNICORN_ERRORLOG", "logs/gunicorn-error.log")
loglevel = os.environ.get("GUNICORN_LOGLEVEL", "info")

# Redirect stdout/stderr to error log
capture_output = True

# Process name
proc_name = "cyberguard-ai"

# Trust X-Forwarded-* headers from Nginx proxy
forwarded_allow_ips = os.environ.get("GUNICORN_FORWARDED_ALLOW_IPS", "*")
secure_scheme_headers = {
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SCHEME': 'https',
}
