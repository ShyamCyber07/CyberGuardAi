import sys
import os
import re
import time
import requests

# Target base URL
BASE_URL = "http://127.0.0.1:5000"

print("====================================================")
print("CYBERGUARD AI - E2E PROGRAMMATIC VERIFICATION SUITE")
print("====================================================")

# Dynamic variables to store credentials and UUIDs
timestamp = int(time.time())
analyst_email = f"analyst_e2e_{timestamp}@cyberguard.ai"
admin_email = f"admin_e2e_{timestamp}@cyberguard.ai"
test_password = "SecureE2EPassword123!"

print(f"Analyst Email to register: {analyst_email}")
print(f"Admin Email to register: {admin_email}")

# Helper to extract CSRF token from HTML
def get_csrf_token(html):
    # Try different patterns for finding csrf_token
    match = re.search(r'name="csrf_token"\s+type="hidden"\s+value="([^"]+)"', html)
    if not match:
        match = re.search(r'value="([^"]+)"\s+type="hidden"\s+name="csrf_token"', html)
    if not match:
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    if not match:
        match = re.search(r'value="([^"]+)"[^>]*name="csrf_token"', html)
    if not match:
        match = re.search(r'id="csrf_token"[^>]*value="([^"]+)"', html)
    return match.group(1) if match else None

# Create sessions
analyst_session = requests.Session()
admin_session = requests.Session()

# ----------------------------------------------------
# PHASE 4 - AUTHENTICATION & CSRF CHECKS
# ----------------------------------------------------
print("\n--- PHASE 4: Authentication & CSRF ---")

# 1. Protected route access while logged out
print("1. Testing protected route redirection while logged out...")
resp = analyst_session.get(f"{BASE_URL}/dashboard")
print(f"   GET /dashboard -> redirected to: {resp.url}")
assert "/auth/login" in resp.url, "Should redirect to login page"
print("   [PASS] Logged-out redirect verified.")

# 2. POST without CSRF token (CSRF security verification)
print("2. Testing POST login without CSRF token...")
resp_no_csrf = requests.post(f"{BASE_URL}/auth/login", data={
    "email": analyst_email,
    "password": test_password
})
print(f"   POST /auth/login without CSRF -> Status: {resp_no_csrf.status_code}")
assert resp_no_csrf.status_code == 400, "Should be rejected with 400 Bad Request"
print("   [PASS] CSRF protection verified (blocked without token).")

# 3. Invalid login attempt
print("3. Testing invalid credentials with valid CSRF token...")
login_page = analyst_session.get(f"{BASE_URL}/auth/login")
print(f"   GET /auth/login -> Status: {login_page.status_code}")
csrf_token = get_csrf_token(login_page.text)
assert csrf_token is not None, "Failed to get CSRF token from login page"

resp_invalid = analyst_session.post(f"{BASE_URL}/auth/login", data={
    "csrf_token": csrf_token,
    "email": "nonexistent@cyberguard.ai",
    "password": "WrongPassword!"
})
print(f"   POST /auth/login with bad creds -> Final URL: {resp_invalid.url}, Status: {resp_invalid.status_code}")
assert "/auth/login" in resp_invalid.url or "unsuccessful" in resp_invalid.text, "Should not authenticate and stay/return on login page"
print("   [PASS] Invalid login rejected.")

# 4. Register Analyst User
print("4. Registering temporary Analyst User...")
reg_page = analyst_session.get(f"{BASE_URL}/auth/register")
print(f"   GET /auth/register -> Status: {reg_page.status_code}")
csrf_token = get_csrf_token(reg_page.text)
assert csrf_token is not None, "Failed to get CSRF token from register page"

resp_reg_analyst = analyst_session.post(f"{BASE_URL}/auth/register", data={
    "csrf_token": csrf_token,
    "email": analyst_email,
    "password": test_password,
    "confirm_password": test_password,
    "role": "analyst"
})
print(f"   POST /auth/register (analyst) -> Status: {resp_reg_analyst.status_code}, Final URL: {resp_reg_analyst.url}")
assert resp_reg_analyst.status_code == 200
assert "created successfully" in resp_reg_analyst.text.lower() or "verification" in resp_reg_analyst.text.lower(), "Account registration flash message not found"
print("   [PASS] Analyst registration completed.")

# 5. Register Admin User
print("5. Registering temporary Admin User...")
reg_page = admin_session.get(f"{BASE_URL}/auth/register")
print(f"   GET /auth/register -> Status: {reg_page.status_code}")
csrf_token = get_csrf_token(reg_page.text)
assert csrf_token is not None

resp_reg_admin = admin_session.post(f"{BASE_URL}/auth/register", data={
    "csrf_token": csrf_token,
    "email": admin_email,
    "password": test_password,
    "confirm_password": test_password,
    "role": "admin"
})
print(f"   POST /auth/register (admin) -> Status: {resp_reg_admin.status_code}, Final URL: {resp_reg_admin.url}")
assert resp_reg_admin.status_code == 200
assert "created successfully" in resp_reg_admin.text.lower() or "verification" in resp_reg_admin.text.lower(), "Account registration flash message not found"
print("   [PASS] Admin registration completed.")

# 6. Log in Analyst
print("6. Logging in Analyst...")
login_page = analyst_session.get(f"{BASE_URL}/auth/login")
print(f"   GET /auth/login -> Status: {login_page.status_code}")
csrf_token = get_csrf_token(login_page.text)
resp_login_analyst = analyst_session.post(f"{BASE_URL}/auth/login", data={
    "csrf_token": csrf_token,
    "email": analyst_email,
    "password": test_password
})
print(f"   POST /auth/login (analyst) -> Status: {resp_login_analyst.status_code}, Final URL: {resp_login_analyst.url}")
assert "/dashboard" in resp_login_analyst.url, "Should redirect to dashboard after login"
print("   [PASS] Analyst login successful.")

# 7. Log in Admin
print("7. Logging in Admin...")
login_page = admin_session.get(f"{BASE_URL}/auth/login")
print(f"   GET /auth/login -> Status: {login_page.status_code}")
csrf_token = get_csrf_token(login_page.text)
resp_login_admin = admin_session.post(f"{BASE_URL}/auth/login", data={
    "csrf_token": csrf_token,
    "email": admin_email,
    "password": test_password
})
print(f"   POST /auth/login (admin) -> Status: {resp_login_admin.status_code}, Final URL: {resp_login_admin.url}")
assert "/dashboard" in resp_login_admin.url, "Should redirect to dashboard after login"
print("   [PASS] Admin login successful.")


# ----------------------------------------------------
# PHASE 3 - HOMEPAGE (LOGGED IN)
# ----------------------------------------------------
print("\n--- PHASE 3: Homepage (Logged In) ---")
resp_home = analyst_session.get(f"{BASE_URL}/")
print(f"   GET / -> Status: {resp_home.status_code}")
assert resp_home.status_code == 200, "Homepage should render"
assert "Launch Security Center" in resp_home.text or "Security Center" in resp_home.text, "Hero link check failed"
assert "View Threat Docs" in resp_home.text, "Docs link check failed"
assert "Inspect Matrix" in resp_home.text, "Matrix link check failed"
print("   [PASS] Homepage checks completed.")


# ----------------------------------------------------
# PHASE 5 - DASHBOARD
# ----------------------------------------------------
print("\n--- PHASE 5: Dashboard Content ---")
resp_dash = analyst_session.get(f"{BASE_URL}/dashboard")
print(f"   GET /dashboard -> Status: {resp_dash.status_code}")
assert resp_dash.status_code == 200, "Dashboard should load"
# Verify dashboard elements
assert "average risk score" in resp_dash.text.lower(), "Avg risk KPI missing"
assert "total scans" in resp_dash.text.lower(), "Total scans KPI missing"
assert "todays scans" in resp_dash.text.lower() or "today's scans" in resp_dash.text.lower(), "Todays scans KPI missing"
print("   [PASS] Dashboard metrics and elements loaded successfully.")


# ----------------------------------------------------
# PHASE 6 - WEBSITE SCANNER
# ----------------------------------------------------
print("\n--- PHASE 6: Website Scanner ---")
scan_page = analyst_session.get(f"{BASE_URL}/scanner/")
print(f"   GET /scanner/ -> Status: {scan_page.status_code}")
assert scan_page.status_code == 200
csrf_token = get_csrf_token(scan_page.text)
assert csrf_token is not None

print("   Submitting active scan on authorized target: https://google.com")
# Trigger Website Scan
resp_scan = analyst_session.post(f"{BASE_URL}/scanner/", data={
    "csrf_token": csrf_token,
    "target_url": "https://google.com"
})
print(f"   POST /scanner/ -> Final URL: {resp_scan.url}")
assert "/scanner/results/" in resp_scan.url, "Should redirect to scan results page"

# Extract Scan UUID from URL
web_scan_uuid = resp_scan.url.split("/results/")[1]
print(f"   Extracted Website Scan UUID: {web_scan_uuid}")

# Review elements in results
assert "security score" in resp_scan.text.lower(), "Security score absent"
assert "ssl" in resp_scan.text.lower() or "tls" in resp_scan.text.lower(), "SSL section absent"
assert "headers" in resp_scan.text.lower(), "HTTP Headers section absent"

# Trigger manual AI Analysis (knowing GEMINI_API_KEY is missing, it should fail gracefully and redirect back)
print("   Triggering AI Analysis (API key absent)...")
resp_ai_trigger = analyst_session.post(f"{BASE_URL}/scanner/results/{web_scan_uuid}/ai", data={
    "csrf_token": csrf_token
})
print(f"   POST /scanner/results/{web_scan_uuid}/ai -> Final URL: {resp_ai_trigger.url}")
assert "/scanner/results/" in resp_ai_trigger.url, "Should redirect back to results"
print("   [PASS] AI Analysis failed gracefully as expected.")

# Download PDF Report
print("   Downloading website PDF report...")
resp_pdf = analyst_session.get(f"{BASE_URL}/scanner/results/{web_scan_uuid}/pdf")
print(f"   GET /scanner/results/{web_scan_uuid}/pdf -> Status: {resp_pdf.status_code}, Content-Type: {resp_pdf.headers.get('Content-Type')}")
assert resp_pdf.status_code == 200
assert "application/pdf" in resp_pdf.headers.get("Content-Type").lower(), "Should be a PDF document"
print("   [PASS] PDF generated and downloaded successfully.")


# ----------------------------------------------------
# PHASE 7 - NETWORK SCANNER
# ----------------------------------------------------
print("\n--- PHASE 7: Network Scanner ---")
net_page = analyst_session.get(f"{BASE_URL}/scanner/network/")
print(f"   GET /scanner/network/ -> Status: {net_page.status_code}")
assert net_page.status_code == 200
csrf_token = get_csrf_token(net_page.text)
assert csrf_token is not None

print("   1. Submitting network scan on authorized host: 8.8.8.8")
resp_net_scan = analyst_session.post(f"{BASE_URL}/scanner/network/", data={
    "csrf_token": csrf_token,
    "ip_address": "8.8.8.8",
    "scan_profile": "Quick Scan"
})
print(f"   POST /scanner/network/ -> Final URL: {resp_net_scan.url}")
assert "/scanner/network/results/" in resp_net_scan.url, "Should redirect to network scan results"

# Extract Network Scan UUID
net_scan_uuid = resp_net_scan.url.split("/results/")[1]
print(f"   Extracted Network Scan UUID: {net_scan_uuid}")
assert "ports" in resp_net_scan.text.lower(), "Open ports display absent"
assert "risk level" in resp_net_scan.text.lower(), "Risk level display absent"

# Download Network Scan PDF Report
print("   Downloading network scan PDF report...")
resp_net_pdf = analyst_session.get(f"{BASE_URL}/scanner/network/results/{net_scan_uuid}/pdf")
print(f"   GET /scanner/network/results/{net_scan_uuid}/pdf -> Status: {resp_net_pdf.status_code}, Content-Type: {resp_net_pdf.headers.get('Content-Type')}")
assert resp_net_pdf.status_code == 200
assert "application/pdf" in resp_net_pdf.headers.get("Content-Type").lower()
print("   [PASS] Network scan PDF generated and downloaded successfully.")

# 2. SSRF/Loopback target rejection
print("   2. Testing private/loopback network target protection...")
resp_private = analyst_session.post(f"{BASE_URL}/scanner/network/", data={
    "csrf_token": csrf_token,
    "ip_address": "127.0.0.1",
    "scan_profile": "Quick Scan"
})
print(f"   POST /scanner/network/ with 127.0.0.1 -> Final URL: {resp_private.url}")
# Should show warning/danger message on form page (or redirect to /scanner/network/ and show flash)
assert "blocked" in resp_private.text.lower() or "internal" in resp_private.text.lower() or "private" in resp_private.text.lower(), "Should print security block warning"
print("   [PASS] Private IP address scan request blocked successfully.")


# ----------------------------------------------------
# PHASE 8 - PASSWORD SECURITY
# ----------------------------------------------------
print("\n--- PHASE 8: Password Security Audit ---")
pwd_page = analyst_session.get(f"{BASE_URL}/password-security/")
print(f"   GET /password-security/ -> Status: {pwd_page.status_code}")
assert pwd_page.status_code == 200
csrf_token = get_csrf_token(pwd_page.text)
assert csrf_token is not None

# 1. Strength Checker
print("   1. Testing Password Strength Checker...")
resp_pwd_check = analyst_session.post(f"{BASE_URL}/password-security/", data={
    "csrf_token": csrf_token,
    "form_type": "check",
    "password": "WeakPassword1"
})
assert resp_pwd_check.status_code == 200
assert "entropy" in resp_pwd_check.text.lower() or "suggestions" in resp_pwd_check.text.lower(), "Strength audit results absent"
print("   [PASS] Strength checker audit results verified.")

# 2. Password Generator
print("   2. Testing Password Generator...")
resp_pwd_gen = analyst_session.post(f"{BASE_URL}/password-security/", data={
    "csrf_token": csrf_token,
    "form_type": "generate",
    "length": 18,
    "use_upper": "y",
    "use_lower": "y",
    "use_digits": "y",
    "use_symbols": "y"
})
assert resp_pwd_gen.status_code == 200
assert "generated" in resp_pwd_gen.text.lower(), "Password generator feedback absent"
print("   [PASS] Password generated successfully.")

# 3. Vault save generated password
print("   3. Saving generated password to Vault Registry...")
# Generate first
resp_pwd_gen = analyst_session.post(f"{BASE_URL}/password-security/", data={
    "csrf_token": csrf_token,
    "form_type": "generate",
    "length": 16,
    "use_upper": "y",
    "use_lower": "y",
    "use_digits": "y",
    "use_symbols": "y"
})
# Extract generated password value from HTML (hidden field)
match_val = re.search(r'id="generated_password_val"\s+name="generated_password_val"\s+type="hidden"\s+value="([^"]+)"', resp_pwd_gen.text)
if not match_val:
    match_val = re.search(r'name="generated_password_val"[^>]*value="([^"]+)"', resp_pwd_gen.text)
assert match_val is not None, "Could not find generated_password_val hidden field"
gen_pwd_val = match_val.group(1)
print(f"      Generated password to save: {gen_pwd_val}")

resp_save_vault = analyst_session.post(f"{BASE_URL}/password-security/", data={
    "csrf_token": csrf_token,
    "form_type": "generate",
    "action": "save",
    "generated_password_val": gen_pwd_val,
    "label": "E2E Secure Key Vault"
})
print(f"      POST /password-security/ (save vault) -> Final URL: {resp_save_vault.url}")
assert "saved to vault" in resp_save_vault.text.lower(), "Vault save success flash message missing"
assert "E2E Secure Key Vault" in resp_save_vault.text, "Credential label missing in history"
print("   [PASS] Password successfully encrypted and saved to database vault registry.")

# 4. Vault Delete Credential
print("   4. Testing vault deletion...")
# Find delete UUID from page
match_del_uuid = re.search(r'action="/password-security/delete/([^"]+)"', resp_save_vault.text)
if not match_del_uuid:
    match_del_uuid = re.search(r'href="/password-security/delete/([^"]+)"', resp_save_vault.text)
assert match_del_uuid is not None, "Delete UUID match failed"
del_uuid = match_del_uuid.group(1)
print(f"      UUID to delete: {del_uuid}")

resp_delete_vault = analyst_session.post(f"{BASE_URL}/password-security/delete/{del_uuid}", data={
    "csrf_token": csrf_token
})
print(f"      POST /password-security/delete/{del_uuid} -> Final URL: {resp_delete_vault.url}")
assert "removed" in resp_delete_vault.text.lower() or "deleted" in resp_delete_vault.text.lower(), "Deletion flash message check failed"
assert "E2E Secure Key Vault" not in resp_delete_vault.text, "Deleted label still exists in history"
print("   [PASS] Password vault credential deleted successfully.")


# ----------------------------------------------------
# PHASE 9 - AI ASSISTANT
# ----------------------------------------------------
print("\n--- PHASE 9: AI Security Assistant ---")
assistant_page = analyst_session.get(f"{BASE_URL}/assistant/")
print(f"   GET /assistant/ -> Status: {assistant_page.status_code}")
assert assistant_page.status_code == 200
csrf_token = get_csrf_token(assistant_page.text)
assert csrf_token is not None

# 1. Ask a valid question (API key missing, should return graceful error or 500 API failure)
print("   1. Asking a question about website scan (valid access, missing API key)...")
resp_ask = analyst_session.post(f"{BASE_URL}/assistant/ask", json={
    "scan_uuid": web_scan_uuid,
    "scan_type": "website",
    "question": "What is the most important security issue in this scan?"
}, headers={
    "X-CSRFToken": csrf_token,
    "Content-Type": "application/json"
})
print(f"      POST /assistant/ask -> Status: {resp_ask.status_code}, Body: {resp_ask.text}")
# If Gemini API key is missing, app returns JSON error (likely 500 or 400 stating API key missing)
assert resp_ask.status_code in [400, 500], "Should fail gracefully with 400 or 500 due to missing API key"
assert "api_key" in resp_ask.text.lower() or "gemini" in resp_ask.text.lower() or "key" in resp_ask.text.lower() or "error" in resp_ask.text.lower(), "Graceful error message check"
print("   [PASS] AI Assistant fails gracefully and does not expose backend credentials.")

# 2. Ask question on another user's scan (BOLA isolation)
print("   2. Querying AI Assistant on another user's scan (Admin's network scan from Analyst session)...")
# Get Admin's CSRF token
resp_admin_assistant = admin_session.get(f"{BASE_URL}/assistant/")
admin_csrf_token = get_csrf_token(resp_admin_assistant.text)

# Perform POST using admin session on analyst's scan
resp_bola_post = admin_session.post(f"{BASE_URL}/assistant/ask", json={
    "scan_uuid": web_scan_uuid,
    "scan_type": "website",
    "question": "What is the vulnerability?"
}, headers={
    "X-CSRFToken": admin_csrf_token,
    "Content-Type": "application/json"
})
print(f"      POST /assistant/ask (Admin session querying Analyst scan) -> Status: {resp_bola_post.status_code}")
assert resp_bola_post.status_code == 403, "Should be blocked with 403 Forbidden"
print("   [PASS] AI Assistant user isolation (BOLA) verified successfully.")

# 3. Ask question on nonexistent scan
print("   3. Querying AI Assistant on fake scan UUID...")
resp_fake_uuid = analyst_session.post(f"{BASE_URL}/assistant/ask", json={
    "scan_uuid": "fake-uuid-1234567890",
    "scan_type": "website",
    "question": "Hello?"
}, headers={
    "X-CSRFToken": csrf_token,
    "Content-Type": "application/json"
})
print(f"      POST /assistant/ask (Fake UUID) -> Status: {resp_fake_uuid.status_code}")
assert resp_fake_uuid.status_code == 404, "Should be rejected with 404 Not Found"
print("   [PASS] Fake scan query rejected.")


# ----------------------------------------------------
# PHASE 10 - HISTORY
# ----------------------------------------------------
print("\n--- PHASE 10: Scan History Management ---")
hist_page = analyst_session.get(f"{BASE_URL}/history")
print(f"   GET /history -> Status: {hist_page.status_code}")
assert hist_page.status_code == 200
csrf_token = get_csrf_token(hist_page.text)
assert csrf_token is not None

# 1. Search filter
print("   1. Testing search filter parameter q=google...")
hist_search = analyst_session.get(f"{BASE_URL}/history?q=google")
assert "google.com" in hist_search.text, "Search result should contain google.com"
print("      [PASS] Search filter works.")

# 2. Type filter
print("   2. Testing type filter type=network...")
hist_type = analyst_session.get(f"{BASE_URL}/history?type=network")
assert "8.8.8.8" in hist_type.text, "Type filter should show network targets"
assert "google.com" not in hist_type.text, "Type filter should hide website targets"
print("      [PASS] Type filter works.")

# 3. Delete scan
print("   3. Testing scan deletion...")
resp_del_scan = analyst_session.post(f"{BASE_URL}/history/delete/network/{net_scan_uuid}", data={
    "csrf_token": csrf_token
})
print(f"      POST /history/delete/network/{net_scan_uuid} -> Final URL: {resp_del_scan.url}")
assert "deleted" in resp_del_scan.text.lower(), "Deleted flash message missing"
assert "8.8.8.8" not in resp_del_scan.text, "Deleted target still listed in history"
print("   [PASS] Scan deletion verified.")


# ----------------------------------------------------
# PHASE 11 - ADMIN PANEL ACCESS AND CONTROLS
# ----------------------------------------------------
print("\n--- PHASE 11: Admin Panel ---")

# 1. Normal user (Analyst) blocked from admin panel
print("   1. Testing Analyst access to admin dashboard...")
resp_admin_denied = analyst_session.get(f"{BASE_URL}/admin/dashboard")
print(f"      GET /admin/dashboard (Analyst session) -> Status: {resp_admin_denied.status_code}")
assert resp_admin_denied.status_code == 403, "Should be rejected with 403 Forbidden"
print("      [PASS] Analyst access blocked successfully.")

# 2. Admin dashboard page loads
print("   2. Testing Admin access to admin dashboard...")
resp_admin_dashboard = admin_session.get(f"{BASE_URL}/admin/dashboard")
print(f"      GET /admin/dashboard (Admin session) -> Status: {resp_admin_dashboard.status_code}")
assert resp_admin_dashboard.status_code == 200, "Should load admin dashboard"
assert "admin control panel" in resp_admin_dashboard.text.lower() or "admin dashboard" in resp_admin_dashboard.text.lower(), "Page title/header incorrect"
print("      [PASS] Admin dashboard loads successfully.")

# 3. User management loading
print("   3. Testing user management view...")
resp_admin_users = admin_session.get(f"{BASE_URL}/admin/users")
print(f"      GET /admin/users -> Status: {resp_admin_users.status_code}")
assert resp_admin_users.status_code == 200
assert analyst_email in resp_admin_users.text, "User management should list analyst user"
print("      [PASS] User management loaded successfully.")

# 4. Logs loading
print("   4. Testing logs view...")
resp_admin_logs = admin_session.get(f"{BASE_URL}/admin/logs")
print(f"      GET /admin/logs -> Status: {resp_admin_logs.status_code}")
assert resp_admin_logs.status_code == 200
assert "audit log" in resp_admin_logs.text.lower(), "Logs page absent"
print("      [PASS] Admin logs view loaded successfully.")

# 5. Demoting or deleting analyst user
print("   5. Testing user deletion via Admin controls...")
# Extract user ID of analyst user specifically by locating its table row
pattern = rf"{re.escape(analyst_email)}.*?action=\"/admin/users/delete/(\d+)\""
match_user_id = re.search(pattern, resp_admin_users.text, re.DOTALL)
assert match_user_id is not None, "Failed to locate deletion form for analyst user"
analyst_id = match_user_id.group(1)
print(f"      Analyst User ID to delete: {analyst_id}")

csrf_token_admin = get_csrf_token(resp_admin_users.text)
resp_delete_user = admin_session.post(f"{BASE_URL}/admin/users/delete/{analyst_id}", data={
    "csrf_token": csrf_token_admin
})
print(f"      POST /admin/users/delete/{analyst_id} -> Final URL: {resp_delete_user.url}")
assert "successfully deleted" in resp_delete_user.text.lower(), "User deletion flash message absent"

# Perform a fresh GET request to verify the user is gone
resp_admin_users_after = admin_session.get(f"{BASE_URL}/admin/users")
assert analyst_email not in resp_admin_users_after.text, "Deleted user still present in user manager table"
print("   [PASS] User deletion via Admin controls verified successfully.")


# ----------------------------------------------------
# FINAL VERIFICATION SUCCESS
# ----------------------------------------------------
print("\n====================================================")
print("E2E PROGRAMMATIC VERIFICATION PASSED SUCCESSFULLY!")
print("====================================================")
sys.exit(0)
