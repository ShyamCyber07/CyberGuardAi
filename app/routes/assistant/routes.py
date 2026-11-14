from flask import render_template, request, jsonify, abort
from flask_login import login_required, current_user
from app.extensions import limiter
from app.routes.assistant import assistant_bp
from app.models.scan import Scan
from app.models.network_scan import NetworkScan
from app.services.ai_assistant_service import AIAssistantService, ScanNotFoundError, UnauthorizedScanAccessError
from app.services.ai_service import AIServiceError, GeminiQuotaExceededError

@assistant_bp.route('/')
@login_required
@limiter.limit("30 per minute")
def index():
    """Render the AI Security Assistant interface populated with completed scans."""
    web_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').order_by(Scan.completed_at.desc()).all()
    net_scans = NetworkScan.query.filter_by(user_id=current_user.id, status='completed').order_by(NetworkScan.completed_at.desc()).all()
    
    # Unified list for selector UI
    all_scans = []
    for s in web_scans:
        all_scans.append({
            'uuid': s.uuid,
            'type': 'website',
            'target': s.target_destination,
            'score': f"{s.security_score}/100" if s.security_score is not None else "0/100"
        })
    for s in net_scans:
        all_scans.append({
            'uuid': s.uuid,
            'type': 'network',
            'target': s.ip_address,
            'score': s.risk_level or ('Inconclusive' if s.status == 'inconclusive' else 'Low')
        })
        
    return render_template('main/assistant.html', scans=all_scans)


@assistant_bp.route('/ask', methods=['POST'])
@login_required
@limiter.limit("10 per minute; 100 per day")
def ask():
    """Context-aware Q&A route returning safe text answers about scan findings."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request payload."}), 400
        
    scan_uuid = data.get("scan_uuid")
    scan_type = data.get("scan_type")
    question = data.get("question")
    
    if not scan_uuid or not scan_type or not question:
        return jsonify({"error": "Missing required fields."}), 400
        
    try:
        answer = AIAssistantService.ask_question(
            user_id=current_user.id,
            scan_type=scan_type,
            scan_uuid=scan_uuid,
            user_question=question
        )
        return jsonify({"answer": answer})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except ScanNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except UnauthorizedScanAccessError as e:
        try:
            from app.models.threat import ThreatLog
            from app.extensions import db
            threat = ThreatLog(
                source_ip=request.remote_addr if request else "127.0.0.1",
                threat_type="BOLA Attempt",
                severity="Critical",
                description=f"AI Assistant BOLA block: User ID {current_user.id} tried to query scan they do not own (UUID: {scan_uuid})"
            )
            db.session.add(threat)
            db.session.commit()
        except Exception:
            pass
        return jsonify({"error": str(e)}), 403
    except GeminiQuotaExceededError as e:
        return jsonify({"error": e.user_message}), 429
    except AIServiceError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred."}), 500
