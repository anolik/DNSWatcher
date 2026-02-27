"""
Settings blueprint routes - F22 / F50.

Provides a UI for managing DNS resolver configuration.
Settings are per-organization with a global (org_id=NULL) fallback.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import flash, redirect, render_template, url_for
from flask_login import current_user

from app import db
from app.settings import bp
from app.settings.forms import DnsSettingsForm
from app.models import DnsSettings
from app.utils.auth import admin_required
from app.utils.tenant import get_current_org_id, get_org_settings

logger = logging.getLogger(__name__)


def _apply_form_to_settings(dns_settings: DnsSettings, form: DnsSettingsForm) -> list[str]:
    """Copy all form field values onto a DnsSettings instance.

    Args:
        dns_settings: The DnsSettings row to update.
        form: The validated form.

    Returns:
        The parsed list of resolver IPs (for logging).
    """
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
    rdap_lines = [
        line.strip()
        for line in (form.rdap_servers.data or "").splitlines()
        if line.strip()
    ]
    dns_settings.set_rdap_servers(rdap_lines if rdap_lines else ["https://rdap.org"])
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
    dns_settings.data_retention_days = form.data_retention_days.data
    dns_settings.graph_enabled = form.graph_enabled.data
    dns_settings.graph_tenant_id = (form.graph_tenant_id.data or "").strip() or None
    dns_settings.graph_client_id = (form.graph_client_id.data or "").strip() or None
    graph_secret = (form.graph_client_secret.data or "").strip()
    if graph_secret:
        dns_settings.graph_client_secret = graph_secret
    dns_settings.graph_mailbox = (form.graph_mailbox.data or "").strip() or None
    dns_settings.outbound_enabled = form.outbound_enabled.data
    dns_settings.outbound_tenant_id = (form.outbound_tenant_id.data or "").strip() or None
    dns_settings.outbound_client_id = (form.outbound_client_id.data or "").strip() or None
    outbound_secret = (form.outbound_client_secret.data or "").strip()
    if outbound_secret:
        dns_settings.outbound_client_secret = outbound_secret
    dns_settings.outbound_mailbox = (form.outbound_mailbox.data or "").strip() or None
    dns_settings.updated_at = datetime.now(timezone.utc)
    dns_settings.updated_by = current_user.id
    return resolver_lines


@bp.route("/", methods=["GET", "POST"])
@admin_required
def index():
    """Render and process the DNS settings form.

    F50 - Per-Organization DnsSettings:
      * On GET, load org-specific settings first; fall back to global defaults.
      * On POST/save, create a new org-specific row if the user was viewing
        inherited global defaults.  The global row (org_id=NULL) is never
        modified by an org-admin save.
    """
    org_id = get_current_org_id()

    # Load settings with org-specific > global fallback
    dns_settings = get_org_settings(org_id)

    # Track whether we are inheriting from global (need to create org copy on save)
    using_global = dns_settings.org_id != org_id and org_id is not None

    # If no settings exist at all, create the global default row
    if not db.inspect(dns_settings).persistent:
        dns_settings.org_id = None
        db.session.add(dns_settings)
        db.session.flush()
        using_global = org_id is not None

    form = DnsSettingsForm()

    if form.validate_on_submit():
        if using_global:
            # Create an org-specific copy instead of modifying the global row.
            # Carry over secrets from the global row since the form never
            # pre-fills password fields — without this the new org row would
            # lose all secrets on first save.
            global_row = dns_settings
            dns_settings = DnsSettings(org_id=org_id)
            dns_settings.graph_client_secret = global_row.graph_client_secret
            dns_settings.outbound_client_secret = global_row.outbound_client_secret
            db.session.add(dns_settings)

        resolver_lines = _apply_form_to_settings(dns_settings, form)
        db.session.commit()
        logger.info(
            "DNS settings updated (org_id=%s): resolvers=%r timeout=%.1fs retries=%d "
            "flap_threshold=%d timezone=%s concurrency=%d user=%r",
            dns_settings.org_id,
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
        form.rdap_servers.data = "\n".join(dns_settings.get_rdap_servers())
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
        form.data_retention_days.data = dns_settings.data_retention_days
        form.graph_enabled.data = dns_settings.graph_enabled
        form.graph_tenant_id.data = dns_settings.graph_tenant_id or ""
        form.graph_client_id.data = dns_settings.graph_client_id or ""
        form.graph_client_secret.data = ""  # never pre-fill secrets
        form.graph_mailbox.data = dns_settings.graph_mailbox or ""
        form.outbound_enabled.data = dns_settings.outbound_enabled
        form.outbound_tenant_id.data = dns_settings.outbound_tenant_id or ""
        form.outbound_client_id.data = dns_settings.outbound_client_id or ""
        form.outbound_client_secret.data = ""  # never pre-fill secrets
        form.outbound_mailbox.data = dns_settings.outbound_mailbox or ""

    return render_template("settings.html", form=form, dns_settings=dns_settings)
