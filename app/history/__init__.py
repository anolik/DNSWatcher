"""History blueprint - change log and check result history."""

from __future__ import annotations

from flask import Blueprint

bp: Blueprint = Blueprint("history", __name__, url_prefix="/changes")

from app.history import routes  # noqa: E402, F401
