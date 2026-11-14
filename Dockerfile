# Multi-stage build for smaller production image size
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies for C-extensions (if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install dependencies into a wheels directory to avoid installing dev-tools in final container
RUN pip install --no-cache-dir --user -r requirements.txt


# Final deployment image stage
FROM python:3.12-slim

# Install system dependencies
# CRITICAL: nmap is required by the Python-nmap library to perform network scanner queries.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy python packages from the builder stage
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application files
COPY . .

# Create directory structures and set up permissions
# Ensuring logs, static uploads, and SQLite instances are persistent and writeable
RUN mkdir -p logs instance app/static/reports \
    && useradd -m cyberguard \
    && chown -R cyberguard:cyberguard /app

# Switch to the non-root application execution context
USER cyberguard

# Declare standard environment variables
ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Expose Gunicorn application socket port
EXPOSE 8000

# Run database migrations and boot application server via Gunicorn
CMD ["gunicorn", "-c", "gunicorn.conf.py", "run:app"]
