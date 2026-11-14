import os
import sys

# Ensure current working directory is in system path for imports
sys.path.append(os.getcwd())

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.network_scan import NetworkScan
from app.models.report import Report

app = create_app('development')
app.config['WTF_CSRF_ENABLED'] = False
app.config['TESTING'] = True

with app.app_context():
    # 1. Retrieve test user
    user = User.query.filter_by(email="analyst@cyberguard.ai").first()
    if not user:
        user = User(email="analyst@cyberguard.ai", role="analyst")
        user.set_password("SecurePassword123!")
        db.session.add(user)
        db.session.commit()

    # 2. Add sample scan to test deleting
    temp_scan = Scan(
        target_type='website',
        target_destination='https://delete-me.com',
        user_id=user.id,
        risk_score=99
    )
    db.session.add(temp_scan)
    db.session.commit()
    temp_scan_uuid = temp_scan.uuid

    # Create a dummy report file to verify PDF deletion
    temp_report = Report(
        uuid='temp-report-uuid-to-delete',
        title='Temp Delete Report',
        status='finalized',
        user_id=user.id,
        scan_id=temp_scan.id
    )
    db.session.add(temp_report)
    db.session.commit()
    
    reports_dir = os.path.join(app.root_path, 'static', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    temp_pdf_path = os.path.join(reports_dir, 'temp-report-uuid-to-delete.pdf')
    with open(temp_pdf_path, 'w') as f:
        f.write('dummy pdf content')

    print(f"Created temporary PDF report file at: {temp_pdf_path}")
    assert os.path.exists(temp_pdf_path)

    # 3. Test HTTP Client actions
    client = app.test_client()
    with client:
        # Authenticate
        client.post('/auth/login', data={
            'email': 'analyst@cyberguard.ai',
            'password': 'SecurePassword123!'
        })

        # Fetch history page (default)
        print("Fetching unified scan history page...")
        res = client.get('/history')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert "Assessment Scan History" in html
        assert "Compliance History" in html
        
        # Test Search filtering
        print("Testing search filter...")
        res_search = client.get('/history?q=delete-me')
        assert res_search.status_code == 200
        assert "https://delete-me.com" in res_search.get_data(as_text=True)

        # Test Type filtering
        print("Testing type filter...")
        res_type = client.get('/history?type=website')
        assert res_type.status_code == 200
        
        # Test Delete scan action
        delete_url = f'/history/delete/website/{temp_scan_uuid}'
        print(f"Triggering DELETE POST: {delete_url}")
        res_delete = client.post(delete_url, follow_redirects=True)
        assert res_delete.status_code == 200
        assert "Scan record successfully deleted." in res_delete.get_data(as_text=True)

        # Verify database removal
        deleted_scan = Scan.query.filter_by(uuid=temp_scan_uuid).first()
        assert deleted_scan is None
        deleted_report = Report.query.filter_by(uuid='temp-report-uuid-to-delete').first()
        assert deleted_report is None

        # Verify physical file deletion
        print(f"Checking if temp PDF file was removed: {temp_pdf_path}")
        assert not os.path.exists(temp_pdf_path)

    print("\nScan History & Deletion Verification Passed Successfully!")
