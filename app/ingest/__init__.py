"""Ingest blueprint - bulk domain import from email list files."""

from __future__ import annotations

from flask import Blueprint

bp: Blueprint = Blueprint("ingest", __name__, url_prefix="/import")

from app.ingest import routes  # noqa: E402, F401
