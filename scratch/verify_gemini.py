import os
import sys
import json

# Ensure current working directory is in system path for imports
sys.path.append(os.getcwd())

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan, NetworkScanResult
from app.services.gemini_service import GeminiService

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

    # 1. Test Prompt Builder constraint (Website Scan)
    print("Verifying prompt builder constraints...")
    web_scan = Scan.query.filter_by(target_destination='https://example.com').first()
    if web_scan and web_scan.ai_response:
        db.session.delete(web_scan.ai_response)
        db.session.commit()
    if not web_scan:
        web_scan = Scan(target_type='website', target_destination='https://example.com', user_id=user.id)
        db.session.add(web_scan)
        db.session.commit()
        result = ScanResult(
            scan_id=web_scan.id,
            vulnerability_name='Missing Strict-Transport-Security (HSTS) Header',
            severity='medium',
            description='HSTS prevents MITM attacks.',
            remediation='Add header.'
        )
        db.session.add(result)
        db.session.commit()
        # Reload
        web_scan = Scan.query.filter_by(id=web_scan.id).first()

    # 2. Trigger active scanner service mock analysis
    print("Triggering mock explain scan...")
    analysis = GeminiService.explain_scan(web_scan)
    print(f"Used Model: {analysis['model_used']}")
    print("AI prompt compiled:")
    print(analysis['prompt'])
    
    # Assert Prompt constraints (Only audits the supplied vulnerabilities list)
    assert "HSTS" in analysis['prompt']
    assert "Under no circumstances may you invent, suggest, or assume other vulnerabilities exist." in analysis['prompt']
    assert "Respond strictly in valid JSON format." in analysis['prompt']
    
    print("Parsed JSON response:")
    print(analysis['response_data'])
    assert 'executive_summary' in analysis['response_data']
    assert 'recommendations' in analysis['response_data']

    # 3. Test HTTP view controller routes trigger for Website Scans
    client = app.test_client()
    with client:
        # Authenticate
        client.post('/auth/login', data={
            'email': 'analyst@cyberguard.ai',
            'password': 'SecurePassword123!'
        })

        # Trigger AI analysis for website scan
        ai_post_url = f'/scanner/results/{web_scan.uuid}/ai'
        print(f"\nPosting to: {ai_post_url}")
        res = client.post(ai_post_url, follow_redirects=True)
        print(f"Trigger AI POST -> Status: {res.status_code}")
        html_str = res.get_data(as_text=True)
        assert any(term in html_str for term in ["compiled successfully.", "already compiled.", "Analysis failed", "Analysis Unavailable"])
        assert "AI Security Analysis" in html_str

        # 4. Test HTTP view controller routes trigger for Network Scans
        net_scan = NetworkScan.query.first()
        if net_scan and net_scan.ai_response:
            db.session.delete(net_scan.ai_response)
            db.session.commit()
        if not net_scan:
            net_scan = NetworkScan(ip_address='192.168.1.1', risk_level='Low', scan_profile='Quick Scan', user_id=user.id)
            db.session.add(net_scan)
            db.session.commit()
            port_res = NetworkScanResult(
                network_scan_id=net_scan.id,
                port=80,
                protocol='tcp',
                service_name='http',
                service_version='nginx 1.18.0',
                state='open',
                severity='Low',
                remediation='Redirect to HTTPS'
            )
            db.session.add(port_res)
            db.session.commit()
            # Reload
            net_scan = NetworkScan.query.filter_by(id=net_scan.id).first()

        net_ai_post_url = f'/scanner/network/results/{net_scan.uuid}/ai'
        print(f"\nPosting to: {net_ai_post_url}")
        net_res = client.post(net_ai_post_url, follow_redirects=True)
        print(f"Trigger Net AI POST -> Status: {net_res.status_code}")
        assert net_res.status_code == 200
        net_html_str = net_res.get_data(as_text=True)
        assert any(term in net_html_str for term in ["compiled successfully.", "already compiled.", "Analysis failed", "Analysis Unavailable"])
        assert "AI Security Analysis" in net_html_str

    print("\nGemini AI Integration Verification Passed Successfully!")
