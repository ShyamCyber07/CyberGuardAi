import re
import sys
import time
import requests

BASE_URL = "http://127.0.0.1:5000"

def get_csrf_token(html_text):
    match = re.search(r'id=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html_text)
    if not match:
        match = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html_text)
    if not match:
        match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']', html_text)
    if not match:
        match = re.search(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html_text)
    return match.group(1) if match else None

def test_login(session):
    print("\n--- 1. Testing Login on Packaged Application ---")
    resp = session.get(f"{BASE_URL}/auth/login")
    assert resp.status_code == 200, f"Expected 200 on /auth/login, got {resp.status_code}"
    csrf = get_csrf_token(resp.text)
    print(f"Extracted CSRF Token: {csrf[:15]}...")

    login_data = {
        "email": "desktop_verify@cyberguard.ai",
        "password": "Verify1234!",
        "csrf_token": csrf
    }
    post_resp = session.post(f"{BASE_URL}/auth/login", data=login_data, allow_redirects=True)
    assert post_resp.status_code == 200, f"Expected 200 after login redirect, got {post_resp.status_code}"
    assert "dashboard" in post_resp.url or "Logout" in post_resp.text or "desktop_verify" in post_resp.text
    print("Login SUCCESSFUL! Redirected to:", post_resp.url)

def test_rate_limiting():
    print("\n--- 2. Testing Rate Limiting on Packaged Application ---")
    spam_session = requests.Session()
    got_429 = False
    status_codes = []
    
    r = spam_session.get(f"{BASE_URL}/auth/login")
    token = get_csrf_token(r.text)

    for i in range(1, 10):
        res = spam_session.post(
            f"{BASE_URL}/auth/login",
            data={"email": f"bad_{i}@cyberguard.ai", "password": "wrong", "csrf_token": token}
        )
        status_codes.append(res.status_code)
        if res.status_code == 429:
            got_429 = True
            print(f"Request {i}: Got HTTP 429 (Too Many Requests)! Rate limiting active.")
            break
        else:
            print(f"Request {i}: Status {res.status_code}")
        time.sleep(0.1)

    print(f"Status codes seen: {status_codes}")
    assert got_429, "Rate limiting did not trigger HTTP 429"
    print("Rate Limiting Test: PASSED (HTTP 429 received and verified)")

def test_website_scan_and_pdf(session):
    print("\n--- 3. Testing Website Scan and PDF Download on Packaged Application ---")
    page = session.get(f"{BASE_URL}/scanner/")
    csrf = get_csrf_token(page.text)
    print(f"Scanner page loaded (HTTP {page.status_code}), CSRF: {csrf[:15]}...")

    scan_resp = session.post(
        f"{BASE_URL}/scanner/api/scan",
        json={"target_url": "https://example.com"},
        headers={"X-CSRFToken": csrf}
    )
    print(f"Website scan response: HTTP {scan_resp.status_code}")
    assert scan_resp.status_code == 200, f"Scan request failed: {scan_resp.text}"
    scan_json = scan_resp.json()
    assert scan_json.get("success") is True, f"Scan not successful: {scan_json}"
    scan_uuid = scan_json["scan"]["uuid"]
    print(f"Website scan completed synchronously with UUID: {scan_uuid}")
    print(f"Security score: {scan_json['scan']['security_score']}")
    print(f"Findings count: {len(scan_json['scan']['findings'])}")

    # Download Website Scan PDF
    pdf_url = f"{BASE_URL}/scanner/results/{scan_uuid}/pdf"
    print(f"Downloading PDF report from {pdf_url}...")
    pdf_resp = session.get(pdf_url)
    assert pdf_resp.status_code == 200, f"Expected 200 for PDF download, got {pdf_resp.status_code}"
    assert "application/pdf" in pdf_resp.headers.get("Content-Type", ""), f"Unexpected content type: {pdf_resp.headers.get('Content-Type')}"
    assert pdf_resp.content.startswith(b"%PDF"), "Response content does not start with %PDF header"
    print(f"Website Scan PDF download SUCCESS! Verified valid PDF (%PDF header, {len(pdf_resp.content)} bytes).")

def test_network_scan_and_pdf(session):
    print("\n--- 4. Testing Network Scan and PDF Download on Packaged Application ---")
    page = session.get(f"{BASE_URL}/scanner/network")
    csrf = get_csrf_token(page.text)
    print(f"Network scanner page loaded (HTTP {page.status_code}), CSRF: {csrf[:15]}...")

    scan_resp = session.post(
        f"{BASE_URL}/scanner/network/api/scan",
        json={"ip_address": "8.8.8.8", "scan_profile": "Quick Scan"},
        headers={"X-CSRFToken": csrf}
    )
    print(f"Network scan response: HTTP {scan_resp.status_code}")
    assert scan_resp.status_code == 200, f"Network scan request failed: {scan_resp.text}"
    scan_json = scan_resp.json()
    assert scan_json.get("success") is True, f"Network scan not successful: {scan_json}"
    scan_uuid = scan_json["scan"]["uuid"]
    print(f"Network scan completed synchronously with UUID: {scan_uuid}")
    print(f"Risk level: {scan_json['scan']['risk_level']}")
    print(f"Findings count: {len(scan_json['scan']['findings'])}")

    # Download Network Scan PDF
    pdf_url = f"{BASE_URL}/scanner/network/results/{scan_uuid}/pdf"
    print(f"Downloading Network PDF report from {pdf_url}...")
    pdf_resp = session.get(pdf_url)
    assert pdf_resp.status_code == 200, f"Expected 200 for Network PDF download, got {pdf_resp.status_code}"
    assert "application/pdf" in pdf_resp.headers.get("Content-Type", ""), f"Unexpected content type: {pdf_resp.headers.get('Content-Type')}"
    assert pdf_resp.content.startswith(b"%PDF"), "Response content does not start with %PDF header"
    print(f"Network Scan PDF download SUCCESS! Verified valid PDF (%PDF header, {len(pdf_resp.content)} bytes).")

if __name__ == "__main__":
    session = requests.Session()
    test_login(session)
    test_rate_limiting()
    test_website_scan_and_pdf(session)
    test_network_scan_and_pdf(session)
    print("\n==============================================")
    print("ALL RUNTIME VERIFICATIONS ON PACKAGED EXE PASSED!")
    print("==============================================")
