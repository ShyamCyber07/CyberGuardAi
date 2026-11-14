import os
import sys

# Ensure current working directory is in system path for imports
sys.path.append(os.getcwd())

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.network_scan import NetworkScan
from app.services.network_scan_service import NetworkScannerServiceInterface

# 1. Verify Pluggability Architecture: Compile check for custom scanner injection
class CustomProductionScanner(NetworkScannerServiceInterface):
    def execute_scan(self, user_id: int, ip_address: str, scan_profile: str) -> NetworkScan:
        # A real production implementation would replace this, returning a NetworkScan object
        print(f"[Architecture Test] CustomProductionScanner executing on: {ip_address}")
        return NetworkScan(ip_address=ip_address, risk_level='Low', scan_profile=scan_profile, user_id=user_id)

print("Checking Service Interface compliance...")
prod_scanner = CustomProductionScanner()
assert isinstance(prod_scanner, NetworkScannerServiceInterface)
print("Interface complies with NetworkScannerServiceInterface successfully!\n")

# 2. Flask app verification run
app = create_app('development')
app.config['WTF_CSRF_ENABLED'] = False
app.config['TESTING'] = True

with app.app_context():
    # Retrieve mock analyst
    user = User.query.filter_by(email="analyst@cyberguard.ai").first()
    if not user:
        user = User(email="analyst@cyberguard.ai", role="analyst")
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()

    with app.test_client() as client:
        # Authenticate user session
        client.post('/auth/login', data={
            'email': 'analyst@cyberguard.ai',
            'password': 'SecurePassword123!'
        })

        # Test index view
        res = client.get('/scanner/network/')
        print(f"GET /scanner/network/ -> Status: {res.status_code}")
        assert res.status_code == 200
        assert "Network Audit Engine" in res.get_data(as_text=True)

        # Test invalid target host inputs
        bad_res = client.post('/scanner/network/', data={
            'ip_address': '@invalid_host!',
            'scan_profile': 'Quick Scan'
        }, follow_redirects=True)
        print(f"POST /scanner/network/ (Bad Input) -> Status: {bad_res.status_code}")
        assert "Invalid target format" in bad_res.get_data(as_text=True)

        # Test valid IP input
        good_res = client.post('/scanner/network/', data={
            'ip_address': '192.168.1.10',
            'scan_profile': 'Quick Scan'
        }, follow_redirects=False)
        print(f"POST /scanner/network/ (Valid IP) -> Status: {good_res.status_code}, Redirects to: {good_res.location}")
        assert good_res.status_code == 302
        
        # Follow to results
        results_url = good_res.location
        results_res = client.get(results_url)
        print(f"GET {results_url} -> Status: {results_res.status_code}")
        assert results_res.status_code == 200
        results_html = results_res.get_data(as_text=True)
        assert "Port Diagnostics Matrix" in results_html
        assert "nginx 1.18.0" in results_html
        assert "Overall Risk Level:" in results_html

        # Test JSON API endpoint
        print("\nTriggering Network Scan API...")
        api_res = client.post(
            '/scanner/network/api/scan',
            json={
                'ip_address': 'scanme.nmap.org',
                'scan_profile': 'Service Detection'
            },
            headers={'Content-Type': 'application/json'}
        )
        print(f"API POST -> Status: {api_res.status_code}")
        print("API Response Body:", api_res.get_json())
        assert api_res.status_code == 200
        
        api_json = api_res.get_json()
        print("API JSON Response payload:")
        print(api_json)
        
        assert api_json['success'] is True
        assert api_json['scan']['ip_address'] == 'scanme.nmap.org'
        assert api_json['scan']['risk_level'] == 'High'  # Service Detection has RDP port 3389 (High)
        assert len(api_json['scan']['findings']) == 3
        
        print("\nChecking History Registries...")
        history_res = client.get('/scanner/network/history')
        print(f"GET /scanner/network/history -> Status: {history_res.status_code}")
        assert history_res.status_code == 200
        assert "scanme.nmap.org" in history_res.get_data(as_text=True)

    print("\nPluggable Network Assessment Module Verification Passed Successfully!")
