"""
F01 - Flask application factory for SPF/DMARC/DKIM Watcher.

Creates and configures the Flask application, registers all blueprints,
and initialises extensions (SQLAlchemy, Flask-Login, Flask-WTF).
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone

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


def _configure_logging(debug: bool) -> None:
    """Configure root logger for the application.

    Logging is sent to stdout so PythonAnywhere and most WSGI hosts
    capture it automatically without requiring file handlers.

    Format: timestamp  level  logger-name  message

    Args:
        debug: When True, sets the root level to DEBUG.  Otherwise INFO.
    """
    level = logging.DEBUG if debug else logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )

    root_logger = logging.getLogger()
    # Avoid adding duplicate handlers if create_app() is called multiple times
    # (e.g. in tests).
    if not root_logger.handlers:
        root_logger.addHandler(handler)
    root_logger.setLevel(level)


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
    # Configure structured logging (F32)
    # Must run before extension init so extensions use the same handlers.
    # ------------------------------------------------------------------
    _configure_logging(debug=app.debug)

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

    # Exempt API blueprint from CSRF (JSON endpoints)
    csrf.exempt(api_bp)

    # ------------------------------------------------------------------
    # Template context processors
    # ------------------------------------------------------------------
    @app.context_processor
    def inject_now():
        """Make now() available in all templates."""
        return {"now": lambda: datetime.now(timezone.utc)}

    # ------------------------------------------------------------------
    # Security headers (F33)
    # Applied to every response from this application.
    # ------------------------------------------------------------------
    from flask import Response

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        """Attach security-related HTTP response headers.

        Headers applied:
        - X-Content-Type-Options: Prevents MIME-type sniffing.
        - X-Frame-Options: Blocks clickjacking by forbidding iframe embedding.
        - X-XSS-Protection: Legacy XSS filter hint for older browsers.
        - Content-Security-Policy: Whitelists allowed resource origins.
          cdn.jsdelivr.net is needed for Bootstrap CSS/JS loaded from CDN.
          'unsafe-inline' is required for Bootstrap's own inline styles.
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' cdn.jsdelivr.net; "
            "style-src 'self' cdn.jsdelivr.net 'unsafe-inline'; "
            "font-src cdn.jsdelivr.net; "
            "img-src 'self' data:;"
        )
        return response

    return app
