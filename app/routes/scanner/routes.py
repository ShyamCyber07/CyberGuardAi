import json
import os
from urllib.parse import urlparse
from flask import render_template, redirect, url_for, flash, abort, current_app, request, jsonify, send_from_directory
from flask_login import login_required, current_user
from app.routes.scanner import scanner_bp
from app.routes.scanner.forms import ScanForm
from app.services.scanner_service import ScannerService
from app.models.scan import Scan
from app.extensions import limiter

@scanner_bp.route('/', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute; 20 per hour")
def index():
    """Render scan trigger form and handle submissions."""
    form = ScanForm()
    if form.validate_on_submit():
        target = form.target_url.data.strip()
        current_app.logger.info(f"User {current_user.email} initiated scan on target: {target}")
        
        # Trigger service layer active scan
        try:
            scan = ScannerService.run_active_scan(current_user.id, target)
            flash(f"Scan completed successfully for: {target}", "success")
            return redirect(url_for('scanner.results', uuid=scan.uuid))
        except ValueError as e:
            flash(str(e), "danger")
        
    return render_template('scanner/scan.html', form=form)


@scanner_bp.route('/results/<uuid>')
@login_required
def results(uuid):
    """Render details and findings of a specific scan."""
    scan = Scan.query.filter_by(uuid=uuid).first()
    if not scan:
        abort(404)
        
    # Check authorization - only owners can view results
    if scan.user_id != current_user.id:
        try:
            from app.models.threat import ThreatLog
            from app.extensions import db
            threat = ThreatLog(
                source_ip=request.remote_addr if request else "127.0.0.1",
                threat_type="BOLA Attempt",
                severity="Critical",
                description=f"Website Scan Results BOLA block: User ID {current_user.id} tried to access scan they do not own (UUID: {uuid})"
            )
            db.session.add(threat)
            db.session.commit()
        except Exception:
            pass
        abort(403)
        
    ai_data = None
    if scan.ai_response:
        try:
            ai_data = json.loads(scan.ai_response.response_text)
        except Exception:
            pass

    evidence_data = None
    if scan.evidence_json:
        try:
            evidence_data = json.loads(scan.evidence_json)
        except Exception:
            evidence_data = None

    # Calculate normalized headers status
    http_failed = any(
        r.vulnerability_name in ('Target Request Timed Out', 'Target Connection Failed', 'Target Request Failed')
        for r in scan.results
    )
    
    header_definitions = [
        ('HSTS', 'Strict-Transport-Security (HSTS) Header', 'Strict-Transport-Security'),
        ('CSP', 'Content-Security-Policy (CSP) Header', 'Content-Security-Policy'),
        ('X-Frame-Options', 'X-Frame-Options Header', 'X-Frame-Options'),
        ('X-Content-Type-Options', 'X-Content-Type-Options Header', 'X-Content-Type-Options'),
        ('Referrer-Policy', 'Referrer-Policy Header', 'Referrer-Policy'),
        ('Permissions-Policy', 'Permissions-Policy Header', 'Permissions-Policy')
    ]
    
    findings_by_header = {}
    for r in scan.results:
        if r.raw_payload and isinstance(r.raw_payload, dict) and 'header_checked' in r.raw_payload:
            findings_by_header[r.raw_payload['header_checked']] = r
    findings_names = [r.vulnerability_name for r in scan.results]

    headers_status = []
    for label, check_name, header_key in header_definitions:
        if http_failed:
            status = 'not_tested'
            label_text = 'NOT TESTED'
            badge = 'warning'
            icon = 'bi-dash-circle'
        elif header_key in findings_by_header or any(check_name in fn for fn in findings_names):
            status = 'missing'
            label_text = 'MISSING'
            badge = 'danger'
            icon = 'bi-x-circle'
        else:
            status = 'present'
            label_text = 'PRESENT'
            badge = 'emerald'
            icon = 'bi-check-circle'
            
        headers_status.append({
            'label': label,
            'check_name': check_name,
            'header_key': header_key,
            'status': status,
            'label_text': label_text,
            'badge': badge,
            'icon': icon
        })

    # Calculate normalized SSL status
    is_https = scan.target_destination.lower().startswith('https://')
    if not is_https:
        ssl_status = {
            'state': 'not_applicable',
            'label': 'Not Applicable',
            'badge': 'secondary',
            'icon': 'bi-dash-circle'
        }
    elif http_failed and any('Handshake Failure' in r.vulnerability_name for r in scan.results):
        ssl_status = {
            'state': 'error',
            'label': 'Handshake Failure',
            'badge': 'danger',
            'icon': 'bi-shield-exclamation'
        }
    elif any(any(kw in r.vulnerability_name for kw in ['Expired', 'Self-Signed', 'Untrusted', 'Mismatch']) for r in scan.results):
        ssl_status = {
            'state': 'error',
            'label': 'SSL Issues',
            'badge': 'danger',
            'icon': 'bi-shield-exclamation'
        }
    elif any('Near Expiration' in r.vulnerability_name for r in scan.results):
        ssl_status = {
            'state': 'warning',
            'label': 'Expiring Soon',
            'badge': 'warning',
            'icon': 'bi-shield-exclamation'
        }
    elif http_failed:
        ssl_status = {
            'state': 'not_tested',
            'label': 'Not Tested',
            'badge': 'warning',
            'icon': 'bi-dash-circle'
        }
    else:
        ssl_status = {
            'state': 'valid',
            'label': 'Valid SSL',
            'badge': 'emerald',
            'icon': 'bi-shield-fill-check'
        }
        
    return render_template(
        'scanner/results.html',
        scan=scan,
        results=scan.results,
        ai_data=ai_data,
        headers_status=headers_status,
        ssl_status=ssl_status,
        evidence_data=evidence_data
    )


@scanner_bp.route('/api/scan', methods=['POST'])
@login_required
@limiter.limit("5 per minute; 20 per hour")
def api_scan():
    """API endpoint to trigger security scans and return JSON results."""
    data = request.get_json(silent=True)
    if not data or 'target_url' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing target_url parameter in JSON body.'
        }), 400
        
    target_url = data['target_url'].strip()
    
    # Validate URL structure
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return jsonify({
            'success': False,
            'error': 'Invalid URL format. Please include protocol scheme (e.g. https://).'
        }), 400
        
    current_app.logger.info(f"User {current_user.email} triggered scan via API on target: {target_url}")
    
    try:
        # Trigger active scan
        scan = ScannerService.run_active_scan(current_user.id, target_url)
        
        # Format JSON response
        findings = []
        for result in scan.results:
            findings.append({
                'vulnerability_name': result.vulnerability_name,
                'severity': result.severity,
                'description': result.description,
                'remediation': result.remediation,
                'raw_payload': result.raw_payload
            })
            
        return jsonify({
            'success': True,
            'scan': {
                'uuid': scan.uuid,
                'target_destination': scan.target_destination,
                'status': scan.status,
                'security_score': scan.security_score,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'findings': findings
            }
        }), 200
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        current_app.logger.error(f"API Scan Error: {e}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred during the scanning process.'
        }), 500


@scanner_bp.route('/results/<uuid>/ai', methods=['POST'])
@login_required
def trigger_ai(uuid):
    """Trigger Gemini AI remediation analysis on website scans and store results."""
    scan = Scan.query.filter_by(uuid=uuid).first()
    if not scan:
        abort(404)
    if scan.user_id != current_user.id:
        try:
            from app.models.threat import ThreatLog
            from app.extensions import db
            threat = ThreatLog(
                source_ip=request.remote_addr if request else "127.0.0.1",
                threat_type="BOLA Attempt",
                severity="Critical",
                description=f"Website Scan AI Trigger BOLA block: User ID {current_user.id} tried to assess scan they do not own (UUID: {uuid})"
            )
            db.session.add(threat)
            db.session.commit()
        except Exception:
            pass
        abort(403)
        
    if scan.ai_response:
        flash("AI analysis report already compiled.", "info")
        return redirect(url_for('scanner.results', uuid=scan.uuid))
        
    from app.services.ai_service import AIAnalysisService, AIServiceError, GeminiQuotaExceededError
    from app.models.ai import AIResponse
    from app.extensions import db
    
    # Format findings for AIAnalysisService
    findings_data = []
    for result in scan.results:
        findings_data.append({
            "name": result.vulnerability_name,
            "severity": result.severity,
            "description": result.description,
            "remediation": result.remediation
        })

    auth_score = scan.security_score if scan.security_score is not None else 100
    auth_risk = scan.risk_level
    if not auth_risk:
        if auth_score >= 85:
            auth_risk = 'Low' if len(scan.results) > 0 else 'None'
        elif auth_score >= 70:
            auth_risk = 'Medium'
        elif auth_score >= 40:
            auth_risk = 'High'
        else:
            auth_risk = 'Critical'
        scan.risk_level = auth_risk
        db.session.commit()

    scan_results_payload = {
        "target": scan.target_destination,
        "scan_type": "website",
        "security_score": auth_score,
        "overall_risk": auth_risk,
        "enforce_authoritative_metrics": True,
        "findings": findings_data
    }
    
    try:
        ai_data = AIAnalysisService.analyze_scan(scan_results_payload, fallback_on_quota=True, user_id=current_user.id)
        model_used = ai_data.get("_model_used", AIAnalysisService.DEFAULT_MODEL)
        
        db_response = AIResponse(
            prompt="Manually triggered report from website scanner results.",
            response_text=json.dumps(ai_data),
            model_used=model_used,
            scan_id=scan.id
        )
        db.session.add(db_response)
        db.session.commit()
        if ai_data.get("_fallback"):
            flash("AI Analysis: Gemini API quota reached. Generated rule-based fallback analysis.", "warning")
        else:
            flash("AI Remediation Report compiled successfully.", "success")
    except GeminiQuotaExceededError as e:
        flash(f"AI Analysis unavailable: {e.user_message}", "warning")
    except AIServiceError as e:
        flash(f"AI Analysis failed: {str(e)}", "danger")
    except Exception as e:
        current_app.logger.error(f"Unexpected AI analysis error: {e}")
        flash("An unexpected error occurred during AI analysis.", "danger")
        
    return redirect(url_for('scanner.results', uuid=scan.uuid))


@scanner_bp.route('/results/<uuid>/pdf', methods=['GET'])
@login_required
def download_pdf(uuid):
    """Generate and return PDF compliance report for website scans."""
    import re
    scan = Scan.query.filter_by(uuid=uuid).first()
    if not scan:
        from app.models.report import Report
        from app.extensions import db
        rep = Report.query.filter_by(uuid=uuid).first()
        if rep:
            if rep.scan_id:
                scan = db.session.get(Scan, rep.scan_id)
            elif rep.network_scan_id:
                return redirect(url_for('network_scanner.download_pdf', uuid=uuid))
    if not scan:
        abort(404)
    if scan.user_id != current_user.id:
        try:
            from app.models.threat import ThreatLog
            from app.extensions import db
            threat = ThreatLog(
                source_ip=request.remote_addr if request else "127.0.0.1",
                threat_type="BOLA Attempt",
                severity="Critical",
                description=f"Website PDF Download BOLA block: User ID {current_user.id} tried to download report they do not own (UUID: {uuid})"
            )
            db.session.add(threat)
            db.session.commit()
        except Exception:
            pass
        abort(403)
        
    ai_data = None
    if scan.ai_response:
        try:
            if isinstance(scan.ai_response.response_text, str):
                ai_data = json.loads(scan.ai_response.response_text)
            elif isinstance(scan.ai_response.response_text, dict):
                ai_data = scan.ai_response.response_text
        except Exception:
            pass
            
    from app.services.pdf_service import PDFGeneratorService
    
    report = PDFGeneratorService.generate_scan_report(current_user.id, scan, ai_data)
    
    reports_dir = os.path.normpath(os.path.join(current_app.root_path, 'static', 'reports'))
    filename = os.path.basename(f"{report.uuid}.pdf")
    
    # Extra security validation: ensure target file resides strictly inside reports_dir
    target_filepath = os.path.normpath(os.path.join(reports_dir, filename))
    if not target_filepath.startswith(reports_dir) or not os.path.isfile(target_filepath):
        abort(404)

    target_host = urlparse(scan.target_destination).hostname or "website"
    safe_target = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', target_host)
    download_filename = f"CyberGuard_Web_Audit_{safe_target}_{report.uuid[:8]}.pdf"
    
    return send_from_directory(
        directory=reports_dir,
        path=filename,
        as_attachment=True,
        download_name=download_filename,
        mimetype='application/pdf'
    )

