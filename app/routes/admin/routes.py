import os
import json
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import render_template, redirect, url_for, flash, abort, request, current_app, send_from_directory
from flask_login import login_required, current_user
from sqlalchemy import func

from app.extensions import db
from app.routes.admin import admin_bp
from app.models.user import User
from app.models.report import Report
from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan
from app.models.audit import AuditLog

def admin_required(f):
    """Decorator ensuring current authenticated user has administrative role clearance."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def log_audit(action):
    """Record administration actions inside the system audit database trails."""
    try:
        ip = request.remote_addr if request else None
        ua = request.user_agent.string if request and request.user_agent else None
        log = AuditLog(
            action=action,
            ip_address=ip,
            user_agent=ua,
            user_id=current_user.id if current_user.is_authenticated else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Audit log insertion failed: {e}")


@admin_bp.route('/')
@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Render the protected Admin Panel dashboard showing telemetry graphs and platform statistics."""
    # 1. Gather counts
    total_users = User.query.count()
    admin_count = User.query.filter_by(role='admin').count()
    analyst_count = User.query.filter_by(role='analyst').count()
    user_count = User.query.filter_by(role='user').count()
    
    total_web_scans = Scan.query.count()
    total_net_scans = NetworkScan.query.count()
    total_reports = Report.query.count()

    # Average risk score (Web scans)
    avg_score_query = db.session.query(func.avg(Scan.security_score)).filter(Scan.security_score.isnot(None)).scalar()
    avg_risk_score = round(float(avg_score_query), 1) if avg_score_query is not None else 100.0

    # 2. Graph data: 7-day registration and scanning trends
    today = datetime.now(timezone.utc).date()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    chart_labels = [d.strftime('%b %d') for d in days]
    
    user_registrations = []
    scan_activity = []

    for d in days:
        start_dt = datetime.combine(d, datetime.min.time()).replace(tzinfo=timezone.utc)
        end_dt = datetime.combine(d, datetime.max.time()).replace(tzinfo=timezone.utc)
        
        # Registrations count
        u_cnt = User.query.filter(User.created_at >= start_dt, User.created_at <= end_dt).count()
        user_registrations.append(u_cnt)
        
        # Scans count (Web + Network combined)
        w_cnt = Scan.query.filter(Scan.started_at >= start_dt, Scan.started_at <= end_dt).count()
        n_cnt = NetworkScan.query.filter(NetworkScan.started_at >= start_dt, NetworkScan.started_at <= end_dt).count()
        scan_activity.append(w_cnt + n_cnt)

    stats = {
        'total_users': total_users,
        'admin_count': admin_count,
        'analyst_count': analyst_count,
        'user_count': user_count,
        'total_web_scans': total_web_scans,
        'total_net_scans': total_net_scans,
        'total_reports': total_reports,
        'avg_risk_score': avg_risk_score,
        'chart_labels': chart_labels,
        'user_registrations': user_registrations,
        'scan_activity': scan_activity
    }

    return render_template('admin/dashboard.html', stats=stats)


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """List and manage platform users."""
    all_users = User.query.order_by(User.id.asc()).all()
    return render_template('admin/users.html', users=all_users)


@admin_bp.route('/users/role/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    """Change a user's role authorization (user, analyst, admin)."""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    if new_role not in ['user', 'analyst', 'admin']:
        flash("Invalid role assignment.", "danger")
        return redirect(url_for('admin.users'))
        
    if user.id == current_user.id:
        flash("Self-demotion is prevented for safety. You cannot change your own admin role.", "warning")
        return redirect(url_for('admin.users'))
        
    old_role = user.role
    user.role = new_role
    db.session.commit()
    
    log_audit(f"User role changed for User ID {user.id} ({user.email}) from '{old_role}' to '{new_role}'")
    flash(f"Updated role for {user.email} successfully.", "success")
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user account from the system."""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash("Self-deletion is prevented. You cannot delete your own admin account.", "warning")
        return redirect(url_for('admin.users'))
        
    log_audit(f"User account deleted for User ID {user.id} ({user.email})")
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User account {user.email} successfully deleted.", "success")
    return redirect(url_for('admin.users'))


@admin_bp.route('/reports')
@login_required
@admin_required
def reports():
    """Monitor compiled compliance reports."""
    all_reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('admin/reports.html', reports=all_reports)


@admin_bp.route('/reports/delete/<int:report_id>', methods=['POST'])
@login_required
@admin_required
def delete_report(report_id):
    """Purge compliance reports and their physical PDF files."""
    report = Report.query.get_or_404(report_id)
    
    # Attempt physical file deletion
    try:
        reports_dir = os.path.join(current_app.root_path, 'static', 'reports')
        filepath = os.path.join(reports_dir, f"{report.uuid}.pdf")
        if os.path.exists(filepath):
            os.remove(filepath)
    except Exception as e:
        current_app.logger.error(f"Failed to delete report PDF file {report.uuid}: {e}")

    log_audit(f"Purged Compliance Report: {report.title} (UUID: {report.uuid})")
    
    db.session.delete(report)
    db.session.commit()
    
    flash("Compliance report purged successfully.", "success")
    return redirect(url_for('admin.reports'))


@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    """Display platform rotating logs, database audit logs, and security threat logs."""
    from app.models.threat import ThreatLog
    page = request.args.get('page', 1, type=int)
    audit_logs_pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    
    # Retrieve all ThreatLogs sorted by timestamp desc
    threat_logs = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).all()
    
    # Read last 100 lines of rotating logs file
    log_lines = []
    try:
        logs_path = os.path.join(current_app.root_path, '..', 'logs', 'cyberguard.log')
        if os.path.exists(logs_path):
            with open(logs_path, 'r', encoding='utf-8') as f:
                log_lines = f.readlines()[-100:]
            # Reverse to show latest logs first in viewer
            log_lines.reverse()
        else:
            log_lines = ["Log file cyberguard.log not found. Ensure app has written to logging handlers."]
    except Exception as e:
        log_lines = [f"Error reading platform logs: {e}"]

    return render_template(
        'admin/logs.html', 
        audit_logs=audit_logs_pagination, 
        log_lines=log_lines,
        threat_logs=threat_logs
    )


@admin_bp.route('/logs/threat/resolve/<int:threat_id>', methods=['POST'])
@login_required
@admin_required
def resolve_threat(threat_id):
    """Mark a security threat log as resolved."""
    from app.models.threat import ThreatLog
    threat = ThreatLog.query.get_or_404(threat_id)
    threat.resolved = True
    db.session.commit()
    
    log_audit(f"Resolved Threat Event ID {threat_id} ({threat.threat_type})")
    flash("Threat event has been successfully marked as resolved.", "success")
    return redirect(url_for('admin.logs'))
