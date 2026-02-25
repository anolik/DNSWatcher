"""
F05 - Authentication blueprint for SPF/DMARC/DKIM Watcher.

Registers routes for login and logout under the 'auth' blueprint.
Also registers the Flask-Login user_loader callback.
"""

from __future__ import annotations

from flask import Blueprint

bp: Blueprint = Blueprint("auth", __name__, url_prefix="/auth")

# Import routes after bp is defined to avoid circular imports.
from app.auth import routes  # noqa: E402, F401
