"""
F01 - Flask application factory for SPF/DMARC/DKIM Watcher.

Creates and configures the Flask application, registers all blueprints,
and initialises extensions (SQLAlchemy, Flask-Login, Flask-WTF).
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

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

    # Enable SQLite WAL mode for concurrent read/write access.
    # WAL lets readers and a single writer operate simultaneously, which is
    # essential when threaded batch checks write results in parallel.
    with app.app_context():
        from sqlalchemy import event

        @event.listens_for(db.engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, connection_record):  # noqa: ARG001
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()
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

    from app.dmarc_reports import bp as dmarc_reports_bp
    app.register_blueprint(dmarc_reports_bp)

    # ------------------------------------------------------------------
    # Template context processors & filters
    # ------------------------------------------------------------------

    def _get_display_tz_name() -> str:
        """Load the display timezone name from DnsSettings (singleton)."""
        try:
            from app.models import DnsSettings
            settings = db.session.get(DnsSettings, 1)
            if settings and settings.display_timezone:
                return settings.display_timezone
        except Exception:
            pass
        return "UTC"

    @app.context_processor
    def inject_now():
        """Make now(), timezone info, and date thresholds available."""
        from flask import g
        tz_name = _get_display_tz_name()
        g._display_tz_name = tz_name
        target_tz = ZoneInfo(tz_name)

        _now_utc = datetime.now(timezone.utc)
        _now_local = _now_utc.astimezone(target_tz)

        return {
            "now": lambda: _now_local,
            "today_str": _now_local.strftime("%Y-%m-%d"),
            "warn30_str": (_now_local + timedelta(days=30)).strftime("%Y-%m-%d"),
            "warn90_str": (_now_local + timedelta(days=90)).strftime("%Y-%m-%d"),
            "display_tz": tz_name,
        }

    @app.template_filter("timeago")
    def timeago_filter(dt: datetime | None) -> str:
        """Return a human-readable relative time string like '2h ago', '3d ago'.

        The full datetime is intended to be shown in a title attribute for
        hover access.  This filter only produces the short label.

        Args:
            dt: A datetime (assumed UTC if naive).

        Returns:
            A short relative-time string such as "just now", "5m ago", "3d ago".
        """
        if dt is None:
            return ""
        _now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = _now - dt
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return "just now"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m ago"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h ago"
        days = hours // 24
        if days < 30:
            return f"{days}d ago"
        months = days // 30
        if months < 12:
            return f"{months}mo ago"
        years = days // 365
        return f"{years}y ago"

    @app.template_filter("to_tz")
    def to_tz_filter(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
        """Convert a UTC datetime to the configured display timezone."""
        if dt is None:
            return ""
        from flask import g
        tz_name = getattr(g, "_display_tz_name", None) or _get_display_tz_name()
        target_tz = ZoneInfo(tz_name)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(target_tz).strftime(fmt)

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
          cdn.jsdelivr.net is needed for Bootstrap Icons CSS and Chart.js.
          'unsafe-inline' is required for inline styles and FOUC prevention script.
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' cdn.jsdelivr.net 'unsafe-inline'; "
            "style-src 'self' cdn.jsdelivr.net 'unsafe-inline'; "
            "font-src 'self' cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response

    return app
