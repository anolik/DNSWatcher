"""
F02 - Configuration module for SPF/DMARC/DKIM Watcher.

Loads settings from environment variables with sensible defaults.
"""

import os


class Config:
    """Base configuration shared by all environments."""

    # Security
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    # Database
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        "sqlite:///watcher.db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # SQLite tuning: WAL mode for concurrent reads during threaded checks,
    # and a 30-second busy timeout so writers wait instead of failing.
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "connect_args": {"timeout": 30},
    }

    # Session hardening
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    SESSION_COOKIE_SECURE: bool = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"

    # Upload / payload limits
    MAX_CONTENT_LENGTH: int = 1 * 1024 * 1024  # 1 MB

    # CSRF protection (Flask-WTF)
    WTF_CSRF_ENABLED: bool = True

    # Application-level defaults
    ITEMS_PER_PAGE: int = 25
    HISTORY_DAYS: int = 90
