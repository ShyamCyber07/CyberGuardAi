import os
import sys

# Ensure current working directory is in system path for imports
sys.path.append(os.getcwd())

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan, NetworkScanResult
from app.models.report import Report

app = create_app('development')
app.config['WTF_CSRF_ENABLED'] = False
app.config['TESTING'] = True

with app.app_context():
    # Retrieve test analyst user
    user = User.query.filter_by(email="analyst@cyberguard.ai").first()
    if not user:
        user = User(email="analyst@cyberguard.ai", role="analyst")
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()

    # 1. Select / Create Website Scan
    web_scan = Scan.query.filter_by(target_destination='https://example.com').first()
    if not web_scan:
        web_scan = Scan(target_type='website', target_destination='https://example.com', user_id=user.id, risk_score=82)
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

    # 2. Select / Create Network Scan
    net_scan = NetworkScan.query.first()
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

    # Test HTTP Client PDF generation triggers
    client = app.test_client()
    with client:
        # Authenticate
        client.post('/auth/login', data={
            'email': 'analyst@cyberguard.ai',
            'password': 'SecurePassword123!'
        })

        # Generate Website PDF
        print("Exporting Website Audit Compliance Report...")
        web_pdf_url = f'/scanner/results/{web_scan.uuid}/pdf'
        res_web = client.get(web_pdf_url)
        print(f"Website PDF Response -> Status: {res_web.status_code}, Content-Type: {res_web.headers.get('Content-Type')}")
        assert res_web.status_code == 200
        assert res_web.headers.get('Content-Type') == 'application/pdf'
        
        # Verify Report model database registration
        web_report = Report.query.filter_by(scan_id=web_scan.id).order_by(Report.created_at.desc()).first()
        assert web_report is not None
        assert web_report.status == 'finalized'
        
        # Verify filesystem storage
        web_path = os.path.join(app.root_path, 'static', 'reports', f"{web_report.uuid}.pdf")
        print(f"Checking file exists at: {web_path}")
        assert os.path.exists(web_path)
        assert os.path.getsize(web_path) > 0

        # Generate Network PDF
        print("\nExporting Network Audit Compliance Report...")
        net_pdf_url = f'/scanner/network/results/{net_scan.uuid}/pdf'
        res_net = client.get(net_pdf_url)
        print(f"Network PDF Response -> Status: {res_net.status_code}, Content-Type: {res_net.headers.get('Content-Type')}")
        assert res_net.status_code == 200
        assert res_net.headers.get('Content-Type') == 'application/pdf'
        
        # Verify Report model database registration
        net_report = Report.query.filter_by(network_scan_id=net_scan.id).order_by(Report.created_at.desc()).first()
        assert net_report is not None
        assert net_report.status == 'finalized'
        
        # Verify filesystem storage
        net_path = os.path.join(app.root_path, 'static', 'reports', f"{net_report.uuid}.pdf")
        print(f"Checking file exists at: {net_path}")
        assert os.path.exists(net_path)
        assert os.path.getsize(net_path) > 0

    print("\nPDF Report Generator Verification Passed Successfully!")
