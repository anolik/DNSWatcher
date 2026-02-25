"""
Settings blueprint routes - F22.

Provides a UI for managing DNS resolver configuration (DnsSettings singleton).
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from app import db
from app.settings import bp
from app.settings.forms import DnsSettingsForm
from app.models import DnsSettings


@bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Render and process the DNS settings form."""
    dns_settings = db.session.get(DnsSettings, 1)

    # Create the singleton row if it does not exist yet
    if dns_settings is None:
        dns_settings = DnsSettings(id=1)
        db.session.add(dns_settings)
        db.session.flush()

    form = DnsSettingsForm()

    if form.validate_on_submit():
        # Parse the textarea into a list of IPs
        resolver_lines = [
            line.strip()
            for line in (form.resolvers.data or "").splitlines()
            if line.strip()
        ]
        dns_settings.set_resolvers(resolver_lines)
        dns_settings.timeout_seconds = float(form.timeout_seconds.data)
        dns_settings.retries = form.retries.data
        dns_settings.flap_threshold = form.flap_threshold.data
        dns_settings.updated_at = datetime.now(timezone.utc)
        dns_settings.updated_by = current_user.id
        db.session.commit()
        flash("DNS settings saved successfully.", "success")
        return redirect(url_for("settings.index"))

    # Pre-fill form with current values on GET (or failed POST)
    if not form.is_submitted():
        form.resolvers.data = "\n".join(dns_settings.get_resolvers())
        form.timeout_seconds.data = int(dns_settings.timeout_seconds)
        form.retries.data = dns_settings.retries
        form.flap_threshold.data = dns_settings.flap_threshold

    return render_template("settings.html", form=form, dns_settings=dns_settings)
