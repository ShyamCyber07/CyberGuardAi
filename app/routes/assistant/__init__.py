from flask import Blueprint

assistant_bp = Blueprint('assistant', __name__, url_prefix='/assistant')

from app.routes.assistant import routes
