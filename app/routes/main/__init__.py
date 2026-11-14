from flask import Blueprint

# Define the Main Blueprint
main_bp = Blueprint('main', __name__)

# Import routes to register them with the blueprint
from app.routes.main import routes
