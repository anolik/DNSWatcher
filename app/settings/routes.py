"""
Settings blueprint routes - F22.

Provides a UI for managing DNS resolver configuration (DnsSettings singleton).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from app import db
from app.settings import bp
from app.settings.forms import DnsSettingsForm
from app.models import DnsSettings

logger = logging.getLogger(__name__)


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
        dns_settings.display_timezone = form.display_timezone.data
        dns_settings.check_concurrency = form.check_concurrency.data
        dns_settings.managed_domains = form.managed_domains.data or ""
        dns_settings.check_spf_enabled = form.check_spf_enabled.data
        dns_settings.check_dmarc_enabled = form.check_dmarc_enabled.data
        dns_settings.check_dkim_enabled = form.check_dkim_enabled.data
        dns_settings.check_mx_enabled = form.check_mx_enabled.data
        dns_settings.check_reputation_enabled = form.check_reputation_enabled.data
        dns_settings.check_registrar_enabled = form.check_registrar_enabled.data
        dns_settings.check_geolocation_enabled = form.check_geolocation_enabled.data
        dns_settings.check_mta_sts_enabled = form.check_mta_sts_enabled.data
        dns_settings.check_bimi_enabled = form.check_bimi_enabled.data
        dns_settings.check_tls_enabled = form.check_tls_enabled.data
        dns_settings.graph_enabled = form.graph_enabled.data
        dns_settings.graph_tenant_id = (form.graph_tenant_id.data or "").strip() or None
        dns_settings.graph_client_id = (form.graph_client_id.data or "").strip() or None
        dns_settings.graph_client_secret = (form.graph_client_secret.data or "").strip() or None
        dns_settings.graph_mailbox = (form.graph_mailbox.data or "").strip() or None
        dns_settings.updated_at = datetime.now(timezone.utc)
        dns_settings.updated_by = current_user.id
        db.session.commit()
        logger.info(
            "DNS settings updated: resolvers=%r timeout=%.1fs retries=%d "
            "flap_threshold=%d timezone=%s concurrency=%d user=%r",
            resolver_lines,
            dns_settings.timeout_seconds,
            dns_settings.retries,
            dns_settings.flap_threshold,
            dns_settings.display_timezone,
            dns_settings.check_concurrency,
            current_user.username,
        )
        flash("DNS settings saved successfully.", "success")
        return redirect(url_for("settings.index"))

    # Pre-fill form with current values on GET (or failed POST)
    if not form.is_submitted():
        form.resolvers.data = "\n".join(dns_settings.get_resolvers())
        form.timeout_seconds.data = int(dns_settings.timeout_seconds)
        form.retries.data = dns_settings.retries
        form.flap_threshold.data = dns_settings.flap_threshold
        form.display_timezone.data = dns_settings.display_timezone
        form.check_concurrency.data = dns_settings.check_concurrency
        form.managed_domains.data = dns_settings.managed_domains or ""
        form.check_spf_enabled.data = dns_settings.check_spf_enabled
        form.check_dmarc_enabled.data = dns_settings.check_dmarc_enabled
        form.check_dkim_enabled.data = dns_settings.check_dkim_enabled
        form.check_mx_enabled.data = dns_settings.check_mx_enabled
        form.check_reputation_enabled.data = dns_settings.check_reputation_enabled
        form.check_registrar_enabled.data = dns_settings.check_registrar_enabled
        form.check_geolocation_enabled.data = dns_settings.check_geolocation_enabled
        form.check_mta_sts_enabled.data = dns_settings.check_mta_sts_enabled
        form.check_bimi_enabled.data = dns_settings.check_bimi_enabled
        form.check_tls_enabled.data = dns_settings.check_tls_enabled
        form.graph_enabled.data = dns_settings.graph_enabled
        form.graph_tenant_id.data = dns_settings.graph_tenant_id or ""
        form.graph_client_id.data = dns_settings.graph_client_id or ""
        form.graph_client_secret.data = ""  # never pre-fill secrets
        form.graph_mailbox.data = dns_settings.graph_mailbox or ""

    return render_template("settings.html", form=form, dns_settings=dns_settings)
