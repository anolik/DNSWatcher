"""
Dashboard blueprint routes - F16 through F21.

Handles:
  F16 - Main dashboard with domain status table and summary bar
  F17 - Add domain (POST /domains/add)
  F18 - Delete (soft) domain (POST /domains/<id>/delete)
  F19 - Manual check trigger (POST /domains/<id>/check and /domains/check-all)
  F20 - Domain detail page (GET /domains/<id>)
  F21 - DKIM selector management (GET/POST /domains/<id>/selectors, POST /selectors/<id>/toggle)
"""

from __future__ import annotations

import logging
import re
import threading

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.dashboard import bp
from app.dashboard.forms import AddDomainForm, AddSelectorForm
from app.models import DkimSelector, DmarcReport, DnsSettings, Domain
from app.utils.rate_limit import is_rate_limited

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$"
)

_DEFAULT_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "dkim",
    "mail",
    "s1",
    "s2",
    "protonmail",
]


def _create_domain_with_selectors(hostname: str, user_id: int | None) -> Domain:
    """Create a Domain row plus the 10 default DkimSelector rows."""
    domain = Domain(hostname=hostname, added_by=user_id, current_status="pending")
    db.session.add(domain)
    db.session.flush()  # populate domain.id before creating selectors

    for sel_name in _DEFAULT_SELECTORS:
        db.session.add(DkimSelector(domain_id=domain.id, selector=sel_name, is_active=True))

    return domain


# ---------------------------------------------------------------------------
# F16 - Dashboard
# ---------------------------------------------------------------------------


@bp.route("/")
@login_required
def index():
    """Main dashboard - domain status overview."""
    add_form = AddDomainForm()

    domains = (
        db.session.execute(
            db.select(Domain).where(Domain.is_active == True).order_by(Domain.hostname)
        )
        .scalars()
        .all()
    )

    status_counts: dict[str, int] = {"ok": 0, "warning": 0, "critical": 0, "pending": 0}
    for domain in domains:
        key = domain.current_status if domain.current_status in status_counts else "pending"
        status_counts[key] += 1

    dns_settings = db.session.get(DnsSettings, 1)
    managed_set = dns_settings.get_managed_domains() if dns_settings else set()

    return render_template(
        "dashboard.html",
        domains=domains,
        status_counts=status_counts,
        add_form=add_form,
        managed_set=managed_set,
    )


# ---------------------------------------------------------------------------
# F17 - Add Domain
# ---------------------------------------------------------------------------


@bp.route("/domains/add", methods=["POST"])
@login_required
def add_domain():
    """Add a new domain (or reactivate an existing inactive one)."""
    add_form = AddDomainForm()
    if not add_form.validate_on_submit():
        for field, errors in add_form.errors.items():
            for error in errors:
                flash(error, "danger")
        return redirect(url_for("dashboard.index"))

    hostname = (add_form.hostname.data or "").strip().lower()

    # Check for existing domain (active or inactive)
    existing: Domain | None = (
        db.session.execute(db.select(Domain).where(Domain.hostname == hostname))
        .scalars()
        .first()
    )

    if existing is not None:
        if existing.is_active:
            logger.info(
                "Add domain skipped (already active): hostname=%r user=%r",
                hostname,
                current_user.username,
            )
            flash(f"Domain '{hostname}' is already being monitored.", "warning")
        else:
            existing.is_active = True
            existing.current_status = "pending"
            db.session.commit()
            logger.info(
                "Domain reactivated: hostname=%r user=%r",
                hostname,
                current_user.username,
            )
            flash(f"Domain '{hostname}' has been reactivated.", "success")
        return redirect(url_for("dashboard.index"))

    _create_domain_with_selectors(hostname, current_user.id)
    db.session.commit()
    logger.info(
        "Domain added: hostname=%r user=%r selectors=%d",
        hostname,
        current_user.username,
        len(_DEFAULT_SELECTORS),
    )
    flash(f"Domain '{hostname}' added with {len(_DEFAULT_SELECTORS)} default DKIM selectors.", "success")
    return redirect(url_for("dashboard.index"))


# ---------------------------------------------------------------------------
# F18 - Delete Domain (soft delete)
# ---------------------------------------------------------------------------


@bp.route("/domains/<int:domain_id>/delete", methods=["POST"])
@login_required
def delete_domain(domain_id: int):
    """Soft-delete a domain by setting is_active=False."""
    domain = db.session.get(Domain, domain_id)
    if domain is None or not domain.is_active:
        abort(404)

    domain.is_active = False
    db.session.commit()
    logger.info(
        "Domain deleted (soft): hostname=%r domain_id=%d user=%r",
        domain.hostname,
        domain.id,
        current_user.username,
    )
    flash(f"Domain '{domain.hostname}' has been removed from monitoring.", "info")
    return redirect(url_for("dashboard.index"))


# ---------------------------------------------------------------------------
# F19 - Manual Check
# ---------------------------------------------------------------------------


@bp.route("/domains/<int:domain_id>/check", methods=["POST"])
@login_required
def check_domain(domain_id: int):
    """Trigger a manual check for a single domain."""
    domain = db.session.get(Domain, domain_id)
    if domain is None or not domain.is_active:
        abort(404)

    # Rate limit: allow at most one manual check per domain per 60 seconds.
    # This prevents accidental double-clicks and deliberate hammering.
    if is_rate_limited("domain", domain.id):
        flash(
            f"Please wait at least 60 seconds before re-checking '{domain.hostname}'.",
            "warning",
        )
        return redirect(request.referrer or url_for("dashboard.index"))

    logger.info(
        "Manual check triggered: hostname=%r domain_id=%d user=%r",
        domain.hostname,
        domain.id,
        current_user.username,
    )
    try:
        from app.checker.engine import run_domain_check

        result = run_domain_check(domain, trigger_type="manual")
        db.session.commit()
        logger.info(
            "Manual check complete: hostname=%r overall_status=%r",
            domain.hostname,
            result.overall_status,
        )
        flash(f"Check completed for '{domain.hostname}'.", "success")
    except ImportError:
        flash("Check engine not yet available.", "warning")
    except Exception as exc:  # noqa: BLE001
        logger.exception("Manual check failed: hostname=%r error=%s", domain.hostname, exc)
        flash(f"Check failed for '{domain.hostname}': {exc}", "danger")

    return redirect(request.referrer or url_for("dashboard.index"))


@bp.route("/domains/check-all", methods=["POST"])
@login_required
def check_all_domains():
    """Trigger manual checks for all active domains in a background thread.

    DNS checks for multiple domains can easily exceed Gunicorn's worker
    timeout, so the work is dispatched to a daemon thread.  The HTTP
    response returns immediately with an informational flash message.
    """
    # Rate limit the global "check all" action with entity_id=0 (sentinel).
    # 60 seconds between consecutive check-all requests prevents runaway load.
    if is_rate_limited("all", 0):
        flash(
            "Please wait at least 60 seconds before running another full check.",
            "warning",
        )
        return redirect(url_for("dashboard.index"))

    logger.info("Manual check-all triggered: user=%r", current_user.username)

    try:
        from app.checker.engine import run_all_checks  # noqa: PLC0415
    except ImportError:
        flash("Check engine not yet available.", "warning")
        return redirect(url_for("dashboard.index"))

    from flask import current_app

    app = current_app._get_current_object()

    def _run_checks_background(app_obj: object) -> None:
        """Execute the full check batch inside an application context."""
        with app_obj.app_context():
            try:
                results = run_all_checks(trigger_type="manual")
                logger.info(
                    "Background check-all complete: domains_checked=%d",
                    len(results),
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Background check-all failed: %s", exc)

    thread = threading.Thread(
        target=_run_checks_background,
        args=(app,),
        daemon=True,
        name="check-all-bg",
    )
    thread.start()

    flash(
        "DNS checks started in background — results will appear as each domain completes. "
        "Refresh the page to see updates.",
        "info",
    )
    return redirect(url_for("dashboard.index"))


# ---------------------------------------------------------------------------
# F20 - Domain Detail
# ---------------------------------------------------------------------------


@bp.route("/domains/<int:domain_id>")
@login_required
def domain_detail(domain_id: int):
    """Detailed view of a domain's latest check results."""
    domain = db.session.get(Domain, domain_id)
    if domain is None:
        abort(404)

    latest_result = domain.check_results.first()

    spf_details = latest_result.get_spf_details() if latest_result else {}
    dmarc_details = latest_result.get_dmarc_details() if latest_result else {}
    dkim_records = latest_result.get_dkim_records() if latest_result else []
    reputation_details = latest_result.get_reputation_details() if latest_result else {}
    dns_errors = latest_result.get_dns_errors() if latest_result else []
    mx_records = latest_result.get_mx_records() if latest_result else []
    mx_provider = latest_result.mx_provider if latest_result else None
    registrar_name = latest_result.registrar if latest_result else None
    registrar_details = latest_result.get_registrar_details() if latest_result else {}
    mx_geolocation = latest_result.get_mx_geolocation() if latest_result else []
    law25_status = latest_result.law25_status if latest_result else None
    mta_sts_details = latest_result.get_mta_sts_details() if latest_result else {}
    bimi_details = latest_result.get_bimi_details() if latest_result else {}

    # DMARC reports linked to this domain
    dmarc_reports = (
        db.session.execute(
            db.select(DmarcReport)
            .where(DmarcReport.domain_id == domain.id)
            .order_by(DmarcReport.begin_date.desc())
            .limit(20)
        )
        .scalars()
        .all()
    )

    return render_template(
        "domain_detail.html",
        domain=domain,
        latest_result=latest_result,
        spf_details=spf_details,
        dmarc_details=dmarc_details,
        dkim_records=dkim_records,
        reputation_details=reputation_details,
        dns_errors=dns_errors,
        mx_records=mx_records,
        mx_provider=mx_provider,
        registrar_name=registrar_name,
        registrar_details=registrar_details,
        mx_geolocation=mx_geolocation,
        law25_status=law25_status,
        mta_sts_details=mta_sts_details,
        bimi_details=bimi_details,
        dmarc_reports=dmarc_reports,
    )


# ---------------------------------------------------------------------------
# F21 - DKIM Selectors
# ---------------------------------------------------------------------------


@bp.route("/domains/<int:domain_id>/selectors", methods=["GET", "POST"])
@login_required
def domain_selectors(domain_id: int):
    """Manage DKIM selectors for a domain."""
    domain = db.session.get(Domain, domain_id)
    if domain is None:
        abort(404)

    add_form = AddSelectorForm()

    if add_form.validate_on_submit():
        selector_name = (add_form.selector.data or "").strip().lower()

        # Check for duplicate selector on this domain
        existing_sel: DkimSelector | None = (
            db.session.execute(
                db.select(DkimSelector).where(
                    DkimSelector.domain_id == domain_id,
                    DkimSelector.selector == selector_name,
                )
            )
            .scalars()
            .first()
        )

        if existing_sel is not None:
            if existing_sel.is_active:
                flash(f"Selector '{selector_name}' already exists.", "warning")
            else:
                existing_sel.is_active = True
                db.session.commit()
                flash(f"Selector '{selector_name}' has been reactivated.", "success")
        else:
            db.session.add(
                DkimSelector(domain_id=domain_id, selector=selector_name, is_active=True)
            )
            db.session.commit()
            flash(f"Selector '{selector_name}' added.", "success")

        return redirect(url_for("dashboard.domain_selectors", domain_id=domain_id))

    selectors = (
        db.session.execute(
            db.select(DkimSelector)
            .where(DkimSelector.domain_id == domain_id)
            .order_by(DkimSelector.selector)
        )
        .scalars()
        .all()
    )

    return render_template(
        "domain_selectors.html",
        domain=domain,
        selectors=selectors,
        add_form=add_form,
    )


@bp.route("/selectors/<int:selector_id>/toggle", methods=["POST"])
@login_required
def toggle_selector(selector_id: int):
    """Toggle the is_active flag on a DKIM selector."""
    selector = db.session.get(DkimSelector, selector_id)
    if selector is None:
        abort(404)

    selector.is_active = not selector.is_active
    db.session.commit()

    state = "enabled" if selector.is_active else "disabled"
    flash(f"Selector '{selector.selector}' has been {state}.", "info")
    return redirect(
        url_for("dashboard.domain_selectors", domain_id=selector.domain_id)
    )
