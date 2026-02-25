"""
Shared pytest fixtures for the SPF/DMARC/DKIM Watcher test suite.

All fixtures use an in-memory SQLite database so tests are fully
isolated and require no external services or real DNS lookups.
"""

from __future__ import annotations

import pytest

from app import create_app
from app import db as _db
from app.models import DnsSettings, User


# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------


class TestConfig:
    """Minimal Flask config for automated testing."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-key-not-for-production"
    # NOTE: Do NOT set SERVER_NAME here; it causes 404s in the test client
    # because all routes would need the Host header to match exactly.
    LOGIN_DISABLED = False


# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def app():
    """Create a Flask application instance backed by an in-memory database.

    A fresh database is created for every test function and torn down
    after the function completes, guaranteeing full isolation.
    """
    flask_app = create_app(TestConfig)

    with flask_app.app_context():
        _db.create_all()

        # Seed the DnsSettings singleton (id=1) required by checker modules
        settings = DnsSettings(
            id=1,
            timeout_seconds=2.0,
            retries=1,
            flap_threshold=2,
        )
        _db.session.add(settings)

        # Create a standard test user
        user = User(username="testuser")
        user.set_password("testpass123")
        _db.session.add(user)

        _db.session.commit()

        yield flask_app

        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app):
    """Return a Flask test client (unauthenticated)."""
    return app.test_client()


@pytest.fixture(scope="function")
def auth_client(client, app):
    """Return a Flask test client that is already authenticated.

    The login POST is issued inside the application context so that
    Flask-Login can store the session cookie correctly.
    """
    with app.app_context():
        client.post(
            "/auth/login",
            data={"username": "testuser", "password": "testpass123"},
            follow_redirects=False,
        )
    return client


@pytest.fixture(scope="function")
def db(app):
    """Yield the SQLAlchemy db object within an active application context."""
    with app.app_context():
        yield _db
