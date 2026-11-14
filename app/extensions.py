from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Instantiate SQLAlchemy ORM
db = SQLAlchemy()

# Instantiate Database Migration Tool
migrate = Migrate()

# Instantiate Authentication Manager
login_manager = LoginManager()

# Instantiate CSRF Protection
csrf = CSRFProtect()

# Instantiate Bcrypt Hashing Tool
bcrypt = Bcrypt()

# Instantiate Rate Limiter (Standard Limits: 100/hr, 10/min)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour", "10 per minute"],
    storage_uri="memory://"
)

@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return db.session.get(User, int(user_id))

