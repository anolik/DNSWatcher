"""API blueprint - JSON endpoints for domain checks and status queries."""

from __future__ import annotations

from flask import Blueprint

bp: Blueprint = Blueprint("api", __name__, url_prefix="/api/v1")

from app.api import routes  # noqa: E402, F401
