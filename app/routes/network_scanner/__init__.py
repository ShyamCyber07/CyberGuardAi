from flask import Blueprint

# Define Pluggable Network Scanner Blueprint
network_scanner_bp = Blueprint('network_scanner', __name__)

# Import routes to register them with the blueprint
from app.routes.network_scanner import routes
