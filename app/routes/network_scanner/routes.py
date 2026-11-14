import json
import os
from flask import render_template, redirect, url_for, flash, abort, request, jsonify, current_app, send_from_directory
from flask_login import login_required, current_user
from app.routes.network_scanner import network_scanner_bp
from app.extensions import db, limiter
from app.routes.network_scanner.forms import NetworkScanForm
from app.repositories.network_scan_repository import SQLAlchemyNetworkScanRepository
from app.services.risk_calculator import SimpleRiskCalculator
from app.services.network_scan_service import NetworkScannerService, is_nmap_available, NmapUnavailableError

# Clean Architecture Dependency Injection Registry
repo = SQLAlchemyNetworkScanRepository()
risk_calc = SimpleRiskCalculator()
# Pluggable dispatcher scanner service
scanner_service = NetworkScannerService(repo, risk_calc)


@network_scanner_bp.route('/', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute; 20 per hour")
def index():
    """Render the network assessment form page."""
    form = NetworkScanForm()
    is_nmap_installed = is_nmap_available()
    
    if form.validate_on_submit():
        ip = form.ip_address.data.strip()
        profile = form.scan_profile.data
        mode = form.scanner_mode.data
        
        is_testing = current_app.config.get('TESTING', False)
        if is_testing and request.form.get('scanner_mode') != 'REAL_NMAP':
            mode = 'MOCK'
            
        current_app.logger.info(f"User {current_user.email} triggered network scan on: {ip} with profile: {profile} using mode: {mode}")
        
        # Trigger service with mode
        try:
            scan = scanner_service.execute_scan(current_user.id, ip, profile, mode)
            if scan.status == 'inconclusive':
                flash("Scan did not complete - no conclusion about exposure can be drawn. Re-run the scan.", "warning")
            else:
                flash(f"Network scan assessment completed for: {ip}", "success")
            return redirect(url_for('network_scanner.results', uuid=scan.uuid))
        except (NmapUnavailableError, ValueError) as e:
            flash(str(e), "danger")
        
    return render_template('network_scanner/scan.html', form=form, is_nmap_installed=is_nmap_installed)


@network_scanner_bp.route('/history')
@login_required
def history():
    """Redirect to the unified scan history page."""
    return redirect(url_for('main.history'))


@network_scanner_bp.route('/results/<uuid>')
@login_required
def results(uuid):
    """Display detailed results and open ports of a network scan."""
    scan = repo.find_by_uuid(uuid)
    if not scan:
        abort(404)
        
    # Access control verification (BOLA defense)
    if scan.user_id != current_user.id:
        try:
            from app.models.threat import ThreatLog
            from app.extensions import db
            threat = ThreatLog(
                source_ip=request.remote_addr if request else "127.0.0.1",
                threat_type="BOLA Attempt",
                severity="Critical",
                description=f"Network Scan Results BOLA block: User ID {current_user.id} tried to access scan they do not own (UUID: {uuid})"
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
            if ai_data and isinstance(ai_data, dict):
                score_map = {'Low': 90, 'Medium': 70, 'High': 40, 'Critical': 20}
                net_score = 100 if not scan.results else score_map.get(scan.risk_level, 70)
                ai_data["overall_risk"] = scan.risk_level
                ai_data["security_score"] = net_score
        except Exception:
            pass
        
    return render_template('network_scanner/results.html', scan=scan, results=scan.results, ai_data=ai_data)


@network_scanner_bp.route('/api/scan', methods=['POST'])
@login_required
@limiter.limit("5 per minute; 20 per hour")
def api_scan():
    """JSON API endpoint executing network assessments."""
    data = request.get_json(silent=True)
    if not data or 'ip_address' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing ip_address parameter.'
        }), 400
        
    ip = data['ip_address'].strip()
    profile = data.get('scan_profile', 'Quick Scan').strip()
    
    is_testing = current_app.config.get('TESTING', False)
    demo_mode = current_app.config.get('DEMO_MODE', False)
    default_mode = 'MOCK' if (is_testing and demo_mode) else 'REAL_NMAP'
    mode = data.get('scanner_mode', default_mode).strip()
    
    if mode == 'MOCK' and not demo_mode:
        return jsonify({
            'success': False,
            'error': 'Simulated demonstration mode is disabled.'
        }), 400
    
    # 1. Run basic validator programmatically
    form = NetworkScanForm(data=data)
    if not form.validate():
        errors = [err for err_list in form.errors.values() for err in err_list]
        return jsonify({
            'success': False,
            'error': errors[0] if errors else 'Invalid parameters.'
        }), 400
        
    try:
        # 2. Trigger pluggable service
        scan = scanner_service.execute_scan(current_user.id, ip, profile, mode)
        
        findings = []
        for result in scan.results:
            findings.append({
                'port': result.port,
                'protocol': result.protocol,
                'service_name': result.service_name,
                'service_version': result.service_version,
                'state': result.state,
                'severity': result.severity,
                'remediation': result.remediation
            })
            
        if scan.status == 'inconclusive':
            return jsonify({
                'success': False,
                'status': 'inconclusive',
                'error': 'Scan did not complete - no conclusion about exposure can be drawn. Re-run the scan.',
                'scan': {
                    'uuid': scan.uuid,
                    'ip_address': scan.ip_address,
                    'scan_profile': scan.scan_profile,
                    'scanner_mode': scan.scanner_mode,
                    'status': scan.status,
                    'risk_level': scan.risk_level,
                    'started_at': scan.started_at.isoformat() if scan.started_at else None,
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'findings': []
                }
            }), 409

        return jsonify({
            'success': True,
            'status': scan.status,
            'scan': {
                'uuid': scan.uuid,
                'ip_address': scan.ip_address,
                'scan_profile': scan.scan_profile,
                'scanner_mode': scan.scanner_mode,
                'status': scan.status,
                'risk_level': scan.risk_level,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'findings': findings
            }
        }), 200
        
    except NmapUnavailableError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        current_app.logger.error(f"Network Scan API error: {e}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred during the assessment process.'
        }), 500


@network_scanner_bp.route('/results/<uuid>/ai', methods=['POST'])
@login_required
def trigger_ai(uuid):
    """Trigger Gemini AI remediation analysis on network scans and store results."""
    scan = repo.find_by_uuid(uuid)
    if not scan:
        abort(404)
    if scan.user_id != current_user.id:
        try:
            from app.models.threat import ThreatLog
            threat = ThreatLog(
                source_ip=request.remote_addr if request else "127.0.0.1",
                threat_type="BOLA Attempt",
                severity="Critical",
                description=f"Network Scan AI Trigger BOLA block: User ID {current_user.id} tried to assess scan they do not own (UUID: {uuid})"
            )
            db.session.add(threat)
            db.session.commit()
        except Exception:
            pass
        abort(403)
        
    if scan.status == 'inconclusive':
        flash("AI analysis cannot be generated for an inconclusive scan.", "warning")
        return redirect(url_for('network_scanner.results', uuid=scan.uuid))

    if scan.ai_response:
        flash("AI analysis report already compiled.", "info")
        return redirect(url_for('network_scanner.results', uuid=scan.uuid))
        
    from app.services.ai_service import AIAnalysisService, AIServiceError, GeminiQuotaExceededError
    from app.models.ai import AIResponse
    
    # Format findings for AIAnalysisService
    findings_data = []
    for result in scan.results:
        findings_data.append({
            "name": f"Open Port {result.port}/{result.protocol} ({result.service_name})",
            "severity": result.severity,
            "description": f"Port {result.port}/{result.protocol} is open and running service {result.service_name} (version: {result.service_version or 'Unknown'}). An open port/service increases the target's attack surface but does not automatically mean a vulnerability exists unless explicitly exploited or misconfigured.",
            "remediation": result.remediation or "Restrict access to trusted hosts using local firewall configurations."
        })

    score_map = {'Low': 90, 'Medium': 70, 'High': 40, 'Critical': 20}
    net_score = 100 if not findings_data else score_map.get(scan.risk_level, 70)

    scan_results_payload = {
        "target": scan.ip_address,
        "scan_type": "network",
        "overall_risk": scan.risk_level,
        "security_score": net_score,
        "enforce_authoritative_metrics": True,
        "findings": findings_data
    }
    
    try:
        ai_data = AIAnalysisService.analyze_scan(scan_results_payload, fallback_on_quota=True, user_id=current_user.id)
        # Force authoritative network scanner values
        ai_data["overall_risk"] = scan.risk_level
        ai_data["security_score"] = net_score
        model_used = ai_data.get("_model_used", AIAnalysisService.DEFAULT_MODEL)
        
        db_response = AIResponse(
            prompt="Manually triggered report from network scanner results.",
            response_text=json.dumps(ai_data),
            model_used=model_used,
            network_scan_id=scan.id
        )
        repo.save(scan) # Ensure scan session is attached
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
        
    return redirect(url_for('network_scanner.results', uuid=scan.uuid))


@network_scanner_bp.route('/results/<uuid>/pdf', methods=['GET'])
@login_required
def download_pdf(uuid):
    """Generate and return PDF compliance report for network scans."""
    import re
    scan = repo.find_by_uuid(uuid)
    if not scan:
        from app.models.report import Report
        rep = Report.query.filter_by(uuid=uuid).first()
        if rep:
            if rep.network_scan_id:
                scan = repo.find_by_id(rep.network_scan_id)
            elif rep.scan_id:
                return redirect(url_for('scanner.download_pdf', uuid=uuid))
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
                description=f"Network PDF Download BOLA block: User ID {current_user.id} tried to download report they do not own (UUID: {uuid})"
            )
            db.session.add(threat)
            db.session.commit()
        except Exception:
            pass
        abort(403)

    ai_data = None
    if scan.status != 'inconclusive' and scan.ai_response:
        try:
            if isinstance(scan.ai_response.response_text, str):
                ai_data = json.loads(scan.ai_response.response_text)
            elif isinstance(scan.ai_response.response_text, dict):
                ai_data = scan.ai_response.response_text
            if ai_data and isinstance(ai_data, dict):
                score_map = {'Low': 90, 'Medium': 70, 'High': 40, 'Critical': 20}
                net_score = 100 if not scan.results else score_map.get(scan.risk_level, 70)
                ai_data["overall_risk"] = scan.risk_level
                ai_data["security_score"] = net_score
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

    target_host = scan.ip_address or "network"
    safe_target = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', target_host)
    download_filename = f"CyberGuard_Network_Audit_{safe_target}_{report.uuid[:8]}.pdf"
    
    return send_from_directory(
        directory=reports_dir,
        path=filename,
        as_attachment=True,
        download_name=download_filename,
        mimetype='application/pdf'
    )

