"""
Ingest blueprint routes.

Accepts an uploaded file containing email addresses and extracts unique
domains, adding any that are not already tracked in the database.
"""

from __future__ import annotations

from flask import render_template
from flask_login import login_required

from app.ingest import bp


@bp.route("/")
@login_required
def index():
    """Render the domain import page."""
    return render_template("ingest/index.html")
