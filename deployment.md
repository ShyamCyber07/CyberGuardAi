# Production Deployment Guide: CyberGuard AI

This document details the step-by-step guide to provisioning, configuring, securing, and deploying **CyberGuard AI** in a production environment using Docker and Nginx.

---

## 1. Server Prerequisites & Recommendations

*   **Operating System**: Linux (Ubuntu 22.04 LTS or Debian 12 recommended).
*   **System Specifications**: Minimum 2 Cores, 2GB RAM (due to PDF compiler and python-nmap sub-process overhead).
*   **Installed Dependencies**: 
    *   Docker Engine (v24.0.0+)
    *   Docker Compose (v2.0.0+)
    *   Certbot (for Let's Encrypt SSL/TLS certificates)

---

## 2. Server Provisioning & Setup

### Step 1: Clone the Application
```bash
git clone https://github.com/your-org/CyberGuardAi.git /var/www/cyberguard
cd /var/www/cyberguard
```

### Step 2: Configure Environment Variables
Copy the template and generate a unique cryptography key:
```bash
cp .env.example .env
```
Generate a secure random key using python:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
Update the `.env` file with:
*   `SECRET_KEY`: Set to the generated token.
*   `DATABASE_URL`: Add your PostgreSQL URI or leave blank to use the SQLite instance.
*   `GEMINI_API_KEY`: Enter a valid Gemini API key from AI Studio to enable AI report diagnostics.

---

## 3. Deployment with Docker Compose

Deploy the container cluster in daemon mode:
```bash
docker compose up --build -d
```
Verify that all containers are active:
```bash
docker compose ps
```
Monitor the boot logs for errors:
```bash
docker compose logs -f
```

---

## 4. Database Setup & Schema Migrations

Run database migrations inside the active application container to establish the tables structure:
```bash
docker compose exec web flask db upgrade
```
*Note: If no migration folder exists or the schema needs to be initialized from scratch:*
```bash
docker compose exec web flask db init
docker compose exec web flask db migrate -m "Initial schema setup"
docker compose exec web flask db upgrade
```

To initialize default users (e.g. seeding the first Admin user):
```bash
docker compose exec web flask shell -c "from app import db; from app.models.user import User; u=User(email='admin@domain.com', role='admin'); u.set_password('ChangeMeSecure123!'); db.session.add(u); db.session.commit(); print('Admin seeded.')"
```

---

## 5. Reverse Proxy & SSL Setup (Nginx + Certbot)

### Step 1: Install Certbot
Install Certbot Nginx plugin:
```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx -y
```

### Step 2: Generate Let's Encrypt SSL Certificates
Obtain a certificate (replace `yourdomain.com` with your public DNS record):
```bash
sudo certbot certonly --nginx -d yourdomain.com -d www.yourdomain.com
```

### Step 3: Configure HTTPS on Nginx
Modify the host's `/var/www/cyberguard/nginx.conf` to enable the SSL block (uncomment lines 39-75) and reference the generated cert paths:
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$host$request_uri; # Redirect HTTP to HTTPS
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Strong SSL parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    
    # ... Rest of proxy configuration (copied from nginx.conf template)
}
```

Reload Nginx mapping:
```bash
docker compose restart nginx
```

---

## 6. Performance & Security Optimizations

### 1. Static Assets Caching
Nginx is configured to serve static assets (`/static/` folder) directly from a shared volume, bypassing Gunicorn's Python interpreter entirely. This reduces memory footprint and optimizes latency:
*   `expires 30d`: Static styles, scripts, and media are cached by client browsers for 30 days.

### 2. Gunicorn Worker Calculations
Gunicorn automatically calculates the optimal number of worker processes:
*   `Workers = 2 * Cores + 1`
*   `Threads = 2`
This allows concurrent IO processing of scanning tasks and PDF report compilation requests without blocking other users.

### 3. Log Rotation (Host OS)
Prevent the system disk from filling up by configuring logrotate for Gunicorn log outputs. Create `/etc/logrotate.d/cyberguard`:
```text
/var/lib/docker/volumes/cyberguard_log_data/_data/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 cyberguard cyberguard
}
```

---

## 7. Post-Deployment Audit Checklist

1.  **SSL Validation**: Scan your URL at [SSL Labs](https://www.ssllabs.com/ssltest/) to verify a grade of **A** or **A+**.
2.  **Security Headers**: Inspect response headers using `curl -I https://yourdomain.com` to confirm HSTS, CSP, X-Frame-Options, and X-Content-Type-Options are present.
3.  **Scanner Diagnostics**: Confirm the system Nmap package works inside the container:
    ```bash
    docker compose exec web nmap --version
    ```
4.  **Ownership Check**: Ensure Gunicorn processes run under the non-root `cyberguard` user, not `root`:
    ```bash
    docker compose exec web ps aux
    ```
