import requests
import re

BASE_URL = "http://127.0.0.1:5000"

s = requests.Session()
r = s.get(f"{BASE_URL}/auth/login")

# Find CSRF token
match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.text)
token = match.group(1) if match else None
print("CSRF Token found:", token)

# Let's try registering a user first to be absolutely sure they exist
timestamp = 999999
email = f"test_debug_{timestamp}@cyberguard.ai"
password = "SecurePassword123!"

r_reg_page = s.get(f"{BASE_URL}/auth/register")
match_reg = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r_reg_page.text)
reg_token = match_reg.group(1) if match_reg else None

r_reg = s.post(f"{BASE_URL}/auth/register", data={
    "csrf_token": reg_token,
    "email": email,
    "password": password,
    "confirm_password": password,
    "role": "analyst"
})

print("Registration status/url:", r_reg.status_code, r_reg.url)
print("Registration contains 'created successfully':", "created successfully" in r_reg.text.lower())

# Now login
r_login_page = s.get(f"{BASE_URL}/auth/login")
match_login = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r_login_page.text)
login_token = match_login.group(1) if match_login else None

r_login = s.post(f"{BASE_URL}/auth/login", data={
    "csrf_token": login_token,
    "email": email,
    "password": password
})

print("Login status/url:", r_login.status_code, r_login.url)
print("Login page text length:", len(r_login.text))

# Print any flash message or warning or alert on the login page if we didn't redirect
if "dashboard" not in r_login.url:
    print("\n--- HTML Page snippet ---")
    # find alert classes or messages
    alerts = re.findall(r'<div class="alert[^>]*>(.*?)</div>', r_login.text, re.DOTALL)
    for alert in alerts:
        print("ALERT:", alert.strip())
    # print input fields to check form validation errors
    print("\n--- Form Validation Errors ---")
    errors = re.findall(r'<div class="invalid-feedback[^>]*>(.*?)</div>', r_login.text, re.DOTALL)
    for err in errors:
        print("ERROR:", err.strip())
