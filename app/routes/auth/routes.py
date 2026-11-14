from urllib.parse import urlsplit
from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, current_user, login_required
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from app.extensions import db, limiter
from app.models.user import User
from app.models.audit import AuditLog
from app.routes.auth import auth_bp
from app.routes.auth.forms import (
    RegistrationForm, LoginForm, ForgotPasswordForm,
    ResetPasswordForm, ChangePasswordForm, UpdateProfileForm
)

def create_audit_entry(action, user_id=None):
    """Utility helper to record system security audit logs."""
    try:
        user_agent = request.headers.get('User-Agent', '')[:255]
        ip_addr = request.remote_addr
        log = AuditLog(
            action=action,
            ip_address=ip_addr,
            user_agent=user_agent,
            user_id=user_id
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to write audit log: {e}")

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute; 30 per hour")
def register():
    """Handle user account registration."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            email=form.email.data.lower().strip(),
            role=form.role.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        # Log audit trail
        create_audit_entry('user_registration_success', user.id)
        
        # Email verification placeholder
        current_app.logger.info(f"Verification email placeholder sent to: {user.email}")
        flash('Account created successfully! Verification email placeholder triggered.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute; 30 per hour")
def login():
    """Handle user authentication and login."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact support.', 'danger')
                create_audit_entry('login_attempt_deactivated_user', user.id)
                return redirect(url_for('auth.login'))
                
            login_user(user, remember=form.remember.data)
            create_audit_entry('login_success', user.id)
            
            # Secure redirect validation to prevent Open Redirect vulnerability
            next_page = request.args.get('next')
            if not next_page or urlsplit(next_page).netloc != '':
                next_page = url_for('main.dashboard')
                
            flash('Successfully accessed CyberGuard AI security console.', 'success')
            return redirect(next_page)
        else:
            flash('Login unsuccessful. Please check credentials.', 'danger')
            create_audit_entry('login_attempt_failed')
            
    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Handle user logout session teardown."""
    user_id = current_user.id
    logout_user()
    create_audit_entry('logout_success', user_id)
    flash('Logged out from security console.', 'info')
    return redirect(url_for('main.index'))


def generate_reset_token(user):
    """Generate a timed, cryptographically signed token containing user email and password hash."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps((user.email, user.password_hash), salt='password-reset-salt')

def verify_reset_token(token, expiration=900):
    """Verify reset token signature, expiration (default 15 mins), and confirm user's current password hash."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email, stored_hash = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
        user = User.query.filter_by(email=email).first()
        if user and user.password_hash == stored_hash:
            return user
        return None
    except Exception:
        return None

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute; 30 per hour")
def forgot_password():
    """Request a password reset."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
        
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if user:
            token = generate_reset_token(user)
            # In debug/testing mode, output link to logs for automated/E2E runners to complete verification
            if current_app.config.get('DEBUG') or current_app.config.get('TESTING'):
                current_app.logger.info(f"Password reset link generated: {url_for('auth.reset_password', token=token, _external=True)}")
            else:
                current_app.logger.info(f"Password reset triggered for user ID: {user.id}")
            create_audit_entry('password_reset_requested', user.id)
            
        # Flash same message regardless to prevent user enumeration security issues
        flash('If the email is registered, a password reset link has been dispatched to it.', 'info')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/forgot_password.html', form=form)


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute; 30 per hour")
def reset_password(token):
    """Perform password reset from token link."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    user = verify_reset_token(token)
    if not user:
        flash('Invalid or expired password reset token.', 'danger')
        return redirect(url_for('auth.login'))
        
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        create_audit_entry('password_reset_success', user.id)
        flash('Your password has been successfully updated. You may now login.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/reset_password.html', form=form)


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Display user profile page and handle updates / password change."""
    profile_form = UpdateProfileForm(original_email=current_user.email)
    password_form = ChangePasswordForm()
    
    # Handle forms submission (separate based on submitted button ID)
    if 'submit_profile' in request.form and profile_form.validate_on_submit():
        current_user.email = profile_form.email.data.lower().strip()
        db.session.commit()
        create_audit_entry('profile_email_updated', current_user.id)
        flash('Your profile details have been updated.', 'success')
        return redirect(url_for('auth.profile'))
        
    if 'submit_password' in request.form and password_form.validate_on_submit():
        if current_user.check_password(password_form.current_password.data):
            current_user.set_password(password_form.new_password.data)
            db.session.commit()
            create_audit_entry('password_change_success', current_user.id)
            flash('Your password has been changed successfully.', 'success')
            return redirect(url_for('auth.profile'))
        else:
            flash('Incorrect current password.', 'danger')
            create_audit_entry('password_change_failed_bad_current', current_user.id)
            
    # Set default values for GET request
    if request.method == 'GET':
        profile_form.email.data = current_user.email
        
    return render_template(
        'auth/profile.html',
        profile_form=profile_form,
        password_form=password_form
    )
