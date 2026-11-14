from datetime import datetime, timezone, timedelta
from flask import render_template, current_app, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from sqlalchemy import func
from app.extensions import db
from app.models.scan import Scan, ScanResult
from app.models.network_scan import NetworkScan
from app.routes.main import main_bp
from urllib.parse import urlparse

@main_bp.route('/')
def index():
    """Render the homepage/landing page of CyberGuard AI."""
    current_app.logger.debug("Accessing the home landing page.")
    return render_template('main/index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Render the protected user security dashboard with live telemetry data."""
    current_app.logger.debug(f"User {current_user.email} accessing security dashboard.")
    
    # Calculate real KPIs from database
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    
    # Today's scans count (since midnight UTC)
    today_utc = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    todays_scans = Scan.query.filter(
        Scan.user_id == current_user.id,
        Scan.started_at >= today_utc
    ).count()
    
    # Average Risk Score - Only from completed scans (exclude failed / inconclusive)
    avg_score_query = db.session.query(
        func.avg(Scan.security_score)
    ).filter(
        Scan.user_id == current_user.id,
        Scan.status == 'completed',
        Scan.security_score.isnot(None)
    ).scalar()
    
    avg_risk_score = round(float(avg_score_query), 1) if avg_score_query is not None else 100.0

    # Inconclusive and failed scans counts (excluded from averages and score charts)
    inconclusive_count = NetworkScan.query.filter_by(
        user_id=current_user.id,
        status='inconclusive'
    ).count()

    failed_net_count = NetworkScan.query.filter_by(
        user_id=current_user.id,
        status='failed'
    ).count()
    failed_web_count = Scan.query.filter_by(
        user_id=current_user.id,
        status='failed'
    ).count()
    failed_count = failed_net_count + failed_web_count
    
    kpis = {
        'total_scans': total_scans,
        'todays_scans': todays_scans,
        'avg_risk_score': avg_risk_score,
        'inconclusive_scans': inconclusive_count,
        'failed_scans': failed_count
    }
    
    # Dynamically extract severity counts for Chart.js from real database findings
    # Get all results matching completed scans for this user (strictly excluding failed or inconclusive)
    critical_count = db.session.query(func.count(ScanResult.id)).join(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.status == 'completed',
        ScanResult.severity == 'critical'
    ).scalar() or 0
    
    high_count = db.session.query(func.count(ScanResult.id)).join(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.status == 'completed',
        ScanResult.severity == 'high'
    ).scalar() or 0
    
    medium_count = db.session.query(func.count(ScanResult.id)).join(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.status == 'completed',
        ScanResult.severity == 'medium'
    ).scalar() or 0
    
    low_count = db.session.query(func.count(ScanResult.id)).join(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.status == 'completed',
        ScanResult.severity == 'low'
    ).scalar() or 0
    
    info_count = db.session.query(func.count(ScanResult.id)).join(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.status == 'completed',
        ScanResult.severity == 'info'
    ).scalar() or 0
    
    risk_distribution = {
        'critical': critical_count,
        'high': high_count,
        'medium': medium_count,
        'low': low_count,
        'info': info_count,
        'inconclusive': inconclusive_count
    }
    
    # Fallback to display template chart aesthetics cleanly when no scans have run yet
    if total_scans == 0:
        risk_distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'inconclusive': 0
        }
    
    # Fetch real recent scans for history list
    user_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).limit(4).all()
    user_net_scans = NetworkScan.query.filter_by(user_id=current_user.id).order_by(NetworkScan.started_at.desc()).limit(4).all()
    
    combined_recent = []
    for s in user_scans:
        combined_recent.append(('website', s, s.started_at))
    for s in user_net_scans:
        combined_recent.append(('network', s, s.started_at))
    combined_recent.sort(key=lambda x: x[2] if x[2] else datetime.min, reverse=True)

    recent_activity = []
    
    for stype, scan, _ in combined_recent[:4]:
        # Time ago string format
        scan_started = scan.started_at.replace(tzinfo=timezone.utc) if scan.started_at and scan.started_at.tzinfo is None else (scan.started_at or datetime.now(timezone.utc))
        diff = datetime.now(timezone.utc) - scan_started
        if diff.days > 0:
            time_str = f"{diff.days} days ago"
        elif diff.seconds // 3600 > 0:
            time_str = f"{diff.seconds // 3600} hours ago"
        elif diff.seconds // 60 > 0:
            time_str = f"{diff.seconds // 60} mins ago"
        else:
            time_str = "just now"
            
        badge_map = {'completed': 'success', 'running': 'info', 'failed': 'danger', 'inconclusive': 'secondary'}
        
        if stype == 'website':
            action_text = f"Diagnostics Scan Complete ({scan.security_score}/100)" if scan.status == 'completed' else "Scan Running"
            target_text = scan.target_destination
            is_mock = False
        else:
            action_text = f"Network Audit Complete ({scan.risk_level} Risk)" if scan.status == 'completed' else "Network Scan Running"
            target_text = scan.ip_address
            is_mock = getattr(scan, 'scanner_mode', 'REAL_NMAP') == 'MOCK'

        recent_activity.append({
            'time': time_str,
            'action': action_text,
            'target': target_text,
            'user': current_user.email,
            'status': scan.status,
            'badge': badge_map.get(scan.status, 'secondary'),
            'is_mock': is_mock
        })
        
    # Provide placeholders if scan history is empty to retain premium dashboard aesthetics
    if not recent_activity:
        recent_activity = [
            {
                'time': 'No scans',
                'action': 'Awaiting first security audit...',
                'target': 'None',
                'user': current_user.email,
                'status': 'inactive',
                'badge': 'secondary',
                'is_mock': False
            }
        ]
        
    # Latest generated compliance reports (mock list mapped to DB scan status)
    latest_reports = []
    for index, scan in enumerate(user_scans[:3]):
        score_badge = 'danger' if scan.security_score < 50 else 'warning' if scan.security_score < 85 else 'success'
        severity_label = 'High Risk' if scan.security_score < 50 else 'Medium Risk' if scan.security_score < 85 else 'Safe'
        
        latest_reports.append({
            'uuid': scan.uuid,
            'title': f"Vulnerability Scan for {urlparse(scan.target_destination).hostname}",
            'date': scan.completed_at.strftime('%B %d, %Y') if scan.completed_at else 'In Progress',
            'findings': f"{len(scan.results)} Vulnerabilities" if scan.status == 'completed' else 'Running',
            'severity': severity_label,
            'badge': score_badge
        })
        
    import json
    latest_scan = None
    scan_type = None
    ai_data = None
    has_ai = False

    latest_web_scan = Scan.query.filter_by(
        user_id=current_user.id,
        status='completed'
    ).order_by(Scan.completed_at.desc()).first()

    latest_net_scan = NetworkScan.query.filter_by(
        user_id=current_user.id,
        status='completed'
    ).order_by(NetworkScan.completed_at.desc()).first()

    if latest_web_scan and latest_net_scan:
        web_time = latest_web_scan.completed_at or latest_web_scan.started_at
        net_time = latest_net_scan.completed_at or latest_net_scan.started_at
        if web_time >= net_time:
            latest_scan = latest_web_scan
            scan_type = 'website'
        else:
            latest_scan = latest_net_scan
            scan_type = 'network'
    elif latest_web_scan:
        latest_scan = latest_web_scan
        scan_type = 'website'
    elif latest_net_scan:
        latest_scan = latest_net_scan
        scan_type = 'network'

    if latest_scan:
        if latest_scan.ai_response:
            try:
                ai_data = json.loads(latest_scan.ai_response.response_text)
                has_ai = True
            except Exception:
                pass

    return render_template(
        'main/dashboard.html',
        kpis=kpis,
        risk_distribution=risk_distribution,
        recent_activity=recent_activity,
        latest_reports=latest_reports,
        latest_scan=latest_scan,
        scan_type=scan_type,
        ai_data=ai_data,
        has_ai=has_ai
    )


@main_bp.route('/history')
@login_required
def history():
    """Unified Scan History with search, filter, sorting, and pagination."""
    search_query = request.args.get('q', '').strip().lower()
    filter_type = request.args.get('type', 'all')
    filter_risk = request.args.get('risk', 'all')
    sort_by = request.args.get('sort', 'date_desc')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # 1. Fetch website scans
    web_scans = Scan.query.filter_by(user_id=current_user.id).all()
    
    # 2. Fetch network scans
    net_scans = NetworkScan.query.filter_by(user_id=current_user.id).all()

    # 3. Normalize into unified structure
    all_scans = []
    for s in web_scans:
        if s.status in ('failed', 'running'):
            risk_val = None
            risk_level = s.risk_level or ('Failed' if s.status == 'failed' else 'Running')
        else:
            risk_val = s.security_score if s.security_score is not None else 100
            risk_level = s.risk_level or ('High' if risk_val < 50 else 'Medium' if risk_val < 85 else 'Low')

        all_scans.append({
            'uuid': s.uuid,
            'type': 'website',
            'target': s.target_destination,
            'profile': 'Security Headers & SSL',
            'date': s.started_at.replace(tzinfo=timezone.utc),
            'status': s.status,
            'security_score': risk_val,
            'risk_level': risk_level,
            'has_ai': s.ai_response is not None
        })

    for s in net_scans:
        if s.status == 'inconclusive':
            risk_level = 'Inconclusive'
            score_val = None  # Excluded from averages; strictly no score of 0
        elif s.status == 'failed':
            risk_level = 'Failed'
            score_val = None  # Excluded from averages; strictly no score of 0
        else:
            risk_level = s.risk_level or 'Low'
            score_map = {'High': 20, 'Medium': 60, 'Low': 90}
            score_val = score_map.get(risk_level, 90)

        all_scans.append({
            'uuid': s.uuid,
            'type': 'network',
            'target': s.ip_address,
            'profile': s.scan_profile,
            'date': s.started_at.replace(tzinfo=timezone.utc),
            'status': s.status,
            'security_score': score_val,
            'risk_level': risk_level,
            'has_ai': s.ai_response is not None,
            'scanner_mode': getattr(s, 'scanner_mode', 'REAL_NMAP')
        })

    # 4. Search filter
    if search_query:
        all_scans = [s for s in all_scans if search_query in s['target'].lower() or search_query in s['profile'].lower()]

    # 5. Type filter
    if filter_type != 'all':
        all_scans = [s for s in all_scans if s['type'] == filter_type]

    # 6. Risk filter
    if filter_risk != 'all':
        all_scans = [s for s in all_scans if s['risk_level'].lower() == filter_risk.lower()]

    # 7. Sorting
    if sort_by == 'date_desc':
        all_scans.sort(key=lambda x: x['date'], reverse=True)
    elif sort_by == 'date_asc':
        all_scans.sort(key=lambda x: x['date'])
    elif sort_by == 'target_asc':
        all_scans.sort(key=lambda x: x['target'].lower())
    elif sort_by == 'target_desc':
        all_scans.sort(key=lambda x: x['target'].lower(), reverse=True)
    elif sort_by == 'risk_desc':
        all_scans.sort(key=lambda x: x['security_score'])  # lower score is higher risk
    elif sort_by == 'risk_asc':
        all_scans.sort(key=lambda x: x['security_score'], reverse=True)

    # 8. Pagination
    total_items = len(all_scans)
    total_pages = (total_items + per_page - 1) // per_page
    page = max(1, min(page, total_pages)) if total_pages > 0 else 1
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_scans = all_scans[start_idx:end_idx]

    return render_template(
        'main/history.html',
        scans=paginated_scans,
        page=page,
        total_pages=total_pages,
        total_items=total_items,
        search_query=search_query,
        filter_type=filter_type,
        filter_risk=filter_risk,
        sort_by=sort_by
    )


@main_bp.route('/history/delete/<scan_type>/<uuid>', methods=['POST'])
@login_required
def delete_scan(scan_type, uuid):
    """Delete a security scan, its physical PDF report, and cascaded database objects."""
    import os
    if scan_type == 'website':
        scan = Scan.query.filter_by(uuid=uuid).first()
    elif scan_type == 'network':
        scan = NetworkScan.query.filter_by(uuid=uuid).first()
    else:
        abort(400)

    if not scan:
        abort(404)

    if scan.user_id != current_user.id:
        abort(403)

    # Delete physical PDF files if they exist
    for report in scan.reports:
        try:
            reports_dir = os.path.join(current_app.root_path, 'static', 'reports')
            filepath = os.path.join(reports_dir, f"{report.uuid}.pdf")
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            current_app.logger.error(f"Failed to remove report PDF file: {e}")

    db.session.delete(scan)
    db.session.commit()

    flash("Scan record successfully deleted.", "success")
    return redirect(url_for('main.history'))
