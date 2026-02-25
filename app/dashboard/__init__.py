"""Dashboard blueprint - displays domain statuses and summary metrics."""

from __future__ import annotations

from flask import Blueprint

bp: Blueprint = Blueprint("dashboard", __name__, url_prefix="/")

from app.dashboard import routes  # noqa: E402, F401
