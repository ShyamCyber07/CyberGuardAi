from flask import render_template, redirect, url_for, flash, abort, request, jsonify, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.routes.password_security import password_security_bp
from app.routes.password_security.forms import PasswordCheckForm, PasswordGeneratorForm
from app.models.saved_password import SavedPassword
from app.services.password_service import PasswordService

@password_security_bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    """Render password checker and generator dashboard with vault registries."""
    check_form = PasswordCheckForm()
    gen_form = PasswordGeneratorForm()
    
    analysis_results = None
    generated_password = None

    # Handle Forms trigger separation
    form_type = request.form.get('form_type')

    if form_type == 'check' and check_form.validate_on_submit():
        raw_pwd = check_form.password.data
        analysis_results = PasswordService.analyze_password(raw_pwd)
        
    elif form_type == 'generate' and gen_form.validate_on_submit():
        length = gen_form.length.data
        upper = gen_form.use_upper.data
        lower = gen_form.use_lower.data
        digits = gen_form.use_digits.data
        symbols = gen_form.use_symbols.data
        
        # 1. Check if user is saving an already generated password
        action = request.form.get('action')
        if action == 'save' and gen_form.generated_password_val.data:
            label = gen_form.label.data.strip() or "Saved Vault Credential"
            pwd_to_save = gen_form.generated_password_val.data
            
            # Encrypt password using app config SECRET_KEY
            enc_pwd = PasswordService.encrypt_vault_password(pwd_to_save, current_app.config['SECRET_KEY'])
            
            saved_rec = SavedPassword(
                label=label,
                encrypted_password=enc_pwd,
                encryption_version=2,
                user_id=current_user.id
            )
            db.session.add(saved_rec)
            db.session.commit()
            
            flash(f"Secure password saved to vault registry under: '{label}'", "success")
            return redirect(url_for('password_security.index'))
            
        else:
            # 2. Otherwise generate a new random password
            generated_password = PasswordService.generate_password(
                length=length,
                use_upper=upper,
                use_lower=lower,
                use_digits=digits,
                use_symbols=symbols
            )
            # Seed the hidden field to allow saving it in subsequent requests
            gen_form.generated_password_val.data = generated_password
            flash("New secure password generated.", "info")
 
    # Load and decrypt saved credentials for user vault history display
    db_saved = SavedPassword.query.filter_by(user_id=current_user.id).order_by(SavedPassword.created_at.desc()).all()
    vault_history = []
    
    for rec in db_saved:
        decrypted = PasswordService.decrypt_vault_password(
            rec.encrypted_password, 
            current_app.config['SECRET_KEY'],
            version=rec.encryption_version
        )
        vault_history.append({
            'uuid': rec.uuid,
            'label': rec.label,
            'decrypted_password': decrypted,
            'created_at': rec.created_at
        })

    return render_template(
        'password_security/checker.html',
        check_form=check_form,
        gen_form=gen_form,
        analysis=analysis_results,
        generated_password=generated_password,
        history=vault_history
    )


@password_security_bp.route('/delete/<uuid>', methods=['POST'])
@login_required
def delete_password(uuid):
    """Delete a saved credential from the user's password vault."""
    saved_pwd = SavedPassword.query.filter_by(uuid=uuid).first()
    if not saved_pwd:
        abort(404)
        
    # Security check: verify owner
    if saved_pwd.user_id != current_user.id:
        abort(403)
        
    db.session.delete(saved_pwd)
    db.session.commit()
    
    flash("Credential removed from password vault.", "warning")
    return redirect(url_for('password_security.index'))


@password_security_bp.route('/api/check', methods=['POST'])
@login_required
def api_check():
    """API endpoint to audit password strength metrics."""
    data = request.get_json(silent=True)
    if not data or 'password' not in data:
        return jsonify({'success': False, 'error': 'Missing password parameter in JSON.'}), 400
        
    pwd = data['password']
    metrics = PasswordService.analyze_password(pwd)
    
    return jsonify({
        'success': True,
        'metrics': metrics
    }), 200


@password_security_bp.route('/api/generate', methods=['POST'])
@login_required
def api_generate():
    """API endpoint to generate secure random credentials."""
    data = request.get_json(silent=True) or {}
    length = data.get('length', 16)
    upper = data.get('use_upper', True)
    lower = data.get('use_lower', True)
    digits = data.get('use_digits', True)
    symbols = data.get('use_symbols', True)
    
    if not isinstance(length, int) or length < 8 or length > 64:
        return jsonify({'success': False, 'error': 'Length must be an integer between 8 and 64.'}), 400
        
    pwd = PasswordService.generate_password(
        length=length,
        use_upper=upper,
        use_lower=lower,
        use_digits=digits,
        use_symbols=symbols
    )
    
    return jsonify({
        'success': True,
        'password': pwd,
        'entropy': PasswordService.calculate_entropy(pwd)
    }), 200
