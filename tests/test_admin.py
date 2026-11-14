import os
from app.models.user import User
from app.models.report import Report
from app.models.scan import Scan
from app.models.audit import AuditLog

def test_admin_dashboard_metrics(app, db, test_users):
    """Test dashboard metrics are rendered successfully for admins."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['admin'].id)
        sess['_fresh'] = True
    
    res = client.get('/admin/dashboard')
    assert res.status_code == 200
    assert b"Admin Control Panel" in res.data
    # Assert counts in rendering context
    assert b"3" in res.data # Total Users seeded


def test_admin_user_role_change(app, db, test_users):
    """Test modifying user authorization roles."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['admin'].id)
        sess['_fresh'] = True
    
    target_user = test_users['user']
    
    # Change user to analyst
    res = client.post(f'/admin/users/role/{target_user.id}', data={'role': 'analyst'}, follow_redirects=True)
    assert res.status_code == 200
    
    # Assert role changed
    db.session.refresh(target_user)
    assert target_user.role == 'analyst'
    
    # Verify Audit log generated
    audit_entry = AuditLog.query.order_by(AuditLog.timestamp.desc()).first()
    assert "User role changed" in audit_entry.action


def test_admin_self_demotion_prevention(app, db, test_users):
    """Test admin cannot demote themselves."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['admin'].id)
        sess['_fresh'] = True
    
    admin = test_users['admin']
    res = client.post(f'/admin/users/role/{admin.id}', data={'role': 'user'}, follow_redirects=True)
    assert b"Self-demotion is prevented" in res.data
    
    db.session.refresh(admin)
    assert admin.role == 'admin'


def test_admin_user_deletion(app, db, test_users):
    """Test deleting user accounts."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['admin'].id)
        sess['_fresh'] = True
    
    target_user = test_users['analyst']
    res = client.post(f'/admin/users/delete/{target_user.id}', follow_redirects=True)
    assert res.status_code == 200
    
    # Verify user deleted from db
    deleted = db.session.get(User, target_user.id)
    assert deleted is None


def test_admin_report_purging(app, db, test_users):
    """Test report database record deletion and physical file purging."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['admin'].id)
        sess['_fresh'] = True

    # Create dummy scan & report
    scan = Scan(target_type='website', target_destination='https://t.com', user_id=test_users['admin'].id)
    db.session.add(scan)
    db.session.commit()

    report = Report(uuid='adm-pur-rep', title='Audit', status='finalized', user_id=test_users['admin'].id, scan_id=scan.id)
    db.session.add(report)
    db.session.commit()

    # Create dummy file
    reports_dir = os.path.join(app.root_path, 'static', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, 'adm-pur-rep.pdf')
    with open(pdf_path, 'w') as f:
        f.write('dummy pdf content')

    assert os.path.exists(pdf_path)

    # Purge
    res = client.post(f'/admin/reports/delete/{report.id}', follow_redirects=True)
    assert res.status_code == 200

    # Assert database record deleted
    assert db.session.get(Report, report.id) is None
    # Assert physical file deleted
    assert not os.path.exists(pdf_path)


def test_admin_logs_view(app, db, test_users):
    """Test logs page displays audit tables and system log file contents."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['admin'].id)
        sess['_fresh'] = True

    res = client.get('/admin/logs')
    assert res.status_code == 200
    assert b"Database Security Audit Logs" in res.data
    assert b"Rotating Application Logs" in res.data
