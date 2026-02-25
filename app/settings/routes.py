"""
Settings blueprint routes.

Provides a UI for managing DNS resolver configuration (DnsSettings singleton)
and for adding / removing monitored domains and their DKIM selectors.
"""

from __future__ import annotations

from flask import render_template
from flask_login import login_required

from app import db
from app.settings import bp
from app.models import DnsSettings


@bp.route("/")
@login_required
def index():
    """Render the settings page."""
    dns_settings = db.session.get(DnsSettings, 1)
    return render_template("settings/index.html", dns_settings=dns_settings)
