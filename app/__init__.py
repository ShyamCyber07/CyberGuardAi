import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from flask import Flask, render_template, session
from config import config_by_name
from app.extensions import db, migrate, login_manager, csrf, bcrypt, limiter
from app import models


def create_app(config_name='development'):
    """Application factory for creating and configuring the Flask app instance."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config_by_name.get(config_name, config_by_name['default']))
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)
    
    # Configure Flask-Login settings
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    
    # Setup logging
    configure_logging(app)
    
    # Register Blueprints
    register_blueprints(app)
    
    # Register Error Handlers
    register_error_handlers(app)

    @app.before_request
    def make_session_permanent():
        session.permanent = True

    @app.after_request
    def add_security_headers(response):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "font-src 'self' data: https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "frame-ancestors 'none';"
        )
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
        return response
    
    return app

def configure_logging(app):
    """Set up structured logging for the application."""
    log_level_str = os.environ.get('LOG_LEVEL', 'INFO').upper()
    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    level = log_levels.get(log_level_str, logging.INFO)
    
    # Ensure logs directory exists
    logs_dir = Path(app.root_path).parent / 'logs'
    logs_dir.mkdir(exist_ok=True)
    
    # Formatter for log messages
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s [%(pathname)s:%(lineno)d]: %(message)s'
    )
    
    # File Handler (rotating logs, max 1MB each, keep 10 backups)
    file_handler = RotatingFileHandler(
        logs_dir / 'cyberguard.log',
        maxBytes=1024 * 1024,
        backupCount=10
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    
    # Stream Handler (console output)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)
    
    # Bind handlers to Flask's logger
    app.logger.setLevel(level)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(stream_handler)
    
    app.logger.info('CyberGuard AI Application startup sequence initiated.')

def register_blueprints(app):
    """Register all Flask blueprints."""
    from app.routes.main.routes import main_bp
    app.register_blueprint(main_bp)

    from app.routes.auth.routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.routes.scanner.routes import scanner_bp
    app.register_blueprint(scanner_bp, url_prefix='/scanner')

    from app.routes.network_scanner.routes import network_scanner_bp
    app.register_blueprint(network_scanner_bp, url_prefix='/scanner/network')

    from app.routes.password_security.routes import password_security_bp
    app.register_blueprint(password_security_bp, url_prefix='/password-security')

    from app.routes.admin import admin_bp
    app.register_blueprint(admin_bp)

    from app.routes.assistant import assistant_bp
    app.register_blueprint(assistant_bp)

def register_error_handlers(app):
    """Register custom error page templates."""
    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        app.logger.warning(f"CSRF Validation Failed: {e.description}")
        return render_template('errors/400.html'), 400

    @app.errorhandler(400)
    def bad_request(error):
        app.logger.warning(f"400 Bad Request: {error}")
        return render_template('errors/400.html'), 400

    @app.errorhandler(403)
    def forbidden(error):
        app.logger.warning(f"403 Forbidden Access Attempt: {error}")
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(error):
        app.logger.warning(f"404 Page Not Found: {error}")
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        app.logger.error(f"500 Internal Server Error: {error}")
        return render_template('errors/500.html'), 500
