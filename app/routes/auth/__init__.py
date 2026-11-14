from flask import Blueprint

# Define the Authentication Blueprint
auth_bp = Blueprint('auth', __name__)

# Import routes to register them with the blueprint
from app.routes.auth import routes
