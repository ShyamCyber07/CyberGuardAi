from flask import Blueprint

# Define the Scanner Blueprint
scanner_bp = Blueprint('scanner', __name__)

# Import routes to register them with the blueprint
from app.routes.scanner import routes
