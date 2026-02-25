"""Settings blueprint - DNS resolver configuration and domain management."""

from __future__ import annotations

from flask import Blueprint

bp: Blueprint = Blueprint("settings", __name__, url_prefix="/settings")

from app.settings import routes  # noqa: E402, F401
