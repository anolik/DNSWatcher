"""
F01 - Flask application factory for SPF/DMARC/DKIM Watcher.

Creates and configures the Flask application, registers all blueprints,
and initialises extensions (SQLAlchemy, Flask-Login, Flask-WTF).
"""

from __future__ import annotations

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from app.config import Config

# ---------------------------------------------------------------------------
# Extension instances (created here, initialised in create_app)
# ---------------------------------------------------------------------------
db: SQLAlchemy = SQLAlchemy()
login_manager: LoginManager = LoginManager()
csrf: CSRFProtect = CSRFProtect()


def create_app(config_object: object = Config) -> Flask:
    """Application factory.

    Args:
        config_object: Configuration class or object to load settings from.

    Returns:
        A fully configured Flask application instance.
    """
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config_object)

    # ------------------------------------------------------------------
    # Initialise extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    csrf.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"  # type: ignore[assignment]
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    # ------------------------------------------------------------------
    # Register blueprints
    # ------------------------------------------------------------------
    from app.auth import bp as auth_bp
    from app.dashboard import bp as dashboard_bp
    from app.history import bp as history_bp
    from app.settings import bp as settings_bp
    from app.ingest import bp as ingest_bp
    from app.api import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(api_bp)

    return app
