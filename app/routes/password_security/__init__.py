from flask import Blueprint

# Define Pluggable Password Security Blueprint
password_security_bp = Blueprint('password_security', __name__)

# Import routes to register them with the blueprint
from app.routes.password_security import routes
