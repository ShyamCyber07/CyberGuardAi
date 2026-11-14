import os
import sys

# Ensure current working directory is in system path for imports
sys.path.append(os.getcwd())

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.report import Report
from app.models.scan import Scan
from app.models.audit import AuditLog

app = create_app('development')
app.config['WTF_CSRF_ENABLED'] = False
app.config['TESTING'] = True

with app.app_context():
    # 1. Setup admin and normal user
    admin_user = User.query.filter_by(email="admin@cyberguard.ai").first()
    if not admin_user:
        admin_user = User(email="admin@cyberguard.ai", role="admin")
        admin_user.set_password("AdminSecurePassword123!")
        db.session.add(admin_user)
        db.session.commit()
    else:
        admin_user.role = 'admin'
        db.session.commit()

    normal_user = User.query.filter_by(email="user@cyberguard.ai").first()
    if not normal_user:
        normal_user = User(email="user@cyberguard.ai", role="user")
        normal_user.set_password("UserSecurePassword123!")
        db.session.add(normal_user)
        db.session.commit()
    else:
        normal_user.role = 'user'
        db.session.commit()

    # 2. Test Access Controls (RBAC) via test client
    client = app.test_client()
    
    # CASE A: Standard User access attempt
    print("Testing standard user RBAC rejection...")
    with client:
        # Authenticate as standard user
        client.post('/auth/login', data={
            'email': 'user@cyberguard.ai',
            'password': 'UserSecurePassword123!'
        })
        res = client.get('/admin/dashboard')
        print(f"Standard user fetch -> Status: {res.status_code}")
        assert res.status_code == 403

        # Logout
        client.get('/auth/logout')

    # CASE B: Administrator access attempt
    print("\nTesting administrator RBAC approval...")
    with client:
        # Authenticate as admin user
        client.post('/auth/login', data={
            'email': 'admin@cyberguard.ai',
            'password': 'AdminSecurePassword123!'
        })
        res = client.get('/admin/dashboard')
        print(f"Administrator fetch -> Status: {res.status_code}")
        assert res.status_code == 200
        assert "Admin Control Panel" in res.get_data(as_text=True)

        # 3. Test changing user role
        print("\nTesting user role modification via Admin routes...")
        change_role_url = f'/admin/users/role/{normal_user.id}'
        res_role = client.post(change_role_url, data={'role': 'analyst'}, follow_redirects=True)
        print(f"Role change post -> Status: {res_role.status_code}")
        assert res_role.status_code == 200
        
        # Verify database update
        db.session.refresh(normal_user)
        print(f"Updated user role in DB: {normal_user.role}")
        assert normal_user.role == 'analyst'

        # Verify Audit Log entry
        audit_entry = AuditLog.query.order_by(AuditLog.timestamp.desc()).first()
        print(f"Latest Audit log: {audit_entry.action}")
        assert "User role changed" in audit_entry.action

        # 4. Test deleting report
        print("\nTesting report purging...")
        # Create temporary dummy scan and report
        temp_scan = Scan(target_type='website', target_destination='https://admin-test.com', user_id=normal_user.id)
        db.session.add(temp_scan)
        db.session.commit()
        
        temp_report = Report(
            uuid='admin-temp-report-uuid',
            title='Admin Temp Report',
            status='finalized',
            user_id=normal_user.id,
            scan_id=temp_scan.id
        )
        db.session.add(temp_report)
        db.session.commit()
        
        reports_dir = os.path.join(app.root_path, 'static', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, 'admin-temp-report-uuid.pdf')
        with open(pdf_path, 'w') as f:
            f.write('dummy pdf')

        print(f"Created temporary PDF file at: {pdf_path}")
        assert os.path.exists(pdf_path)

        # Purge report
        purge_url = f'/admin/reports/delete/{temp_report.id}'
        res_purge = client.post(purge_url, follow_redirects=True)
        print(f"Report purge POST -> Status: {res_purge.status_code}")
        assert res_purge.status_code == 200
        
        # Verify db delete
        deleted_rep = Report.query.filter_by(uuid='admin-temp-report-uuid').first()
        assert deleted_rep is None
        # Verify physical file deletion
        print(f"Checking if report PDF file was removed: {pdf_path}")
        assert not os.path.exists(pdf_path)

        # 5. Test viewing logs
        print("\nTesting logs and platform viewer...")
        res_logs = client.get('/admin/logs')
        print(f"Logs page fetch -> Status: {res_logs.status_code}")
        assert res_logs.status_code == 200
        assert "Database Security Audit Logs" in res_logs.get_data(as_text=True)
        assert "Rotating Application Logs" in res_logs.get_data(as_text=True)

    print("\nAdmin Panel & RBAC controls Verification Passed Successfully!")
