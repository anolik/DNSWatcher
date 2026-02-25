"""
F25/F26/F30 - History blueprint routes.

Renders:
  F25 - Per-domain check result history with Chart.js timeline
  F26 - Global change log with filtering and pagination
  F30 - Health / system status page
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from flask import current_app, render_template, request
from flask_login import login_required

from app import db
from app.history import bp
from app.models import ChangeLog, CheckResult, DnsSettings, Domain


# ---------------------------------------------------------------------------
# F26 - Changes page (all domains)
# ---------------------------------------------------------------------------


@bp.route("/")
@login_required
def index():
    """Render the paginated, filterable change log across all domains."""
    page = request.args.get("page", 1, type=int)
    severity_filter = request.args.get("severity", "").lower()
    per_page = current_app.config.get("ITEMS_PER_PAGE", 25)

    query = (
        db.select(ChangeLog)
        .join(Domain, ChangeLog.domain_id == Domain.id)
        .order_by(ChangeLog.detected_at.desc())
    )

    if severity_filter in ("info", "warning", "critical"):
        query = query.where(ChangeLog.severity == severity_filter)

    pagination = db.paginate(query, page=page, per_page=per_page, error_out=False)

    return render_template(
        "changes.html",
        pagination=pagination,
        changes=pagination.items,
        severity_filter=severity_filter,
    )


# ---------------------------------------------------------------------------
# F25 - Domain history timeline
# ---------------------------------------------------------------------------


@bp.route("/domain/<int:domain_id>")
@login_required
def domain_history(domain_id: int):
    """Render the check history timeline and change log for a single domain."""
    domain = db.session.get(Domain, domain_id)
    if domain is None:
        from flask import abort

        abort(404)

    # Last 30 check results for the chart
    results = (
        db.session.execute(
            db.select(CheckResult)
            .where(CheckResult.domain_id == domain_id)
            .order_by(CheckResult.checked_at.desc())
            .limit(30)
        )
        .scalars()
        .all()
    )
    # Reverse for chronological order in the chart
    results = list(reversed(results))

    # Recent changes for this domain
    page = request.args.get("page", 1, type=int)
    per_page = current_app.config.get("ITEMS_PER_PAGE", 25)

    changes_query = (
        db.select(ChangeLog)
        .where(ChangeLog.domain_id == domain_id)
        .order_by(ChangeLog.detected_at.desc())
    )
    changes_pagination = db.paginate(changes_query, page=page, per_page=per_page, error_out=False)

    return render_template(
        "domain_history.html",
        domain=domain,
        results=results,
        changes_pagination=changes_pagination,
        changes=changes_pagination.items,
    )


# ---------------------------------------------------------------------------
# F30 - Health page
# ---------------------------------------------------------------------------


@bp.route("/health")
@login_required
def health_page():
    """Render the system health and diagnostics page."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Total domains
    total_domains = db.session.execute(
        db.select(db.func.count(Domain.id)).where(Domain.is_active == True)
    ).scalar() or 0

    # Domains checked today
    checked_today = db.session.execute(
        db.select(db.func.count(Domain.id)).where(
            Domain.is_active == True,
            Domain.last_checked_at >= today_start,
        )
    ).scalar() or 0

    # DNS errors today (check results with non-empty dns_errors)
    errors_today = db.session.execute(
        db.select(db.func.count(CheckResult.id)).where(
            CheckResult.checked_at >= today_start,
            CheckResult.dns_errors.isnot(None),
            CheckResult.dns_errors != "[]",
            CheckResult.dns_errors != "",
        )
    ).scalar() or 0

    # Last scheduled run
    last_scheduled = db.session.execute(
        db.select(CheckResult)
        .where(CheckResult.trigger_type == "scheduled")
        .order_by(CheckResult.checked_at.desc())
        .limit(1)
    ).scalars().first()

    # Last scheduled batch: find all results from that run
    last_run_duration = None
    last_run_at = None
    if last_scheduled:
        last_run_at = last_scheduled.checked_at
        # Sum execution times from that approximate batch window (within 5 minutes)
        batch_window = last_scheduled.checked_at - timedelta(minutes=5)
        total_ms = db.session.execute(
            db.select(db.func.sum(CheckResult.execution_time_ms)).where(
                CheckResult.trigger_type == "scheduled",
                CheckResult.checked_at >= batch_window,
                CheckResult.checked_at <= last_scheduled.checked_at,
            )
        ).scalar()
        if total_ms:
            last_run_duration = total_ms

    # Database file size
    db_uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
    db_size = None
    if "sqlite:///" in db_uri:
        db_path = db_uri.replace("sqlite:///", "")
        if not os.path.isabs(db_path):
            db_path = os.path.join(current_app.instance_path, db_path)
        try:
            db_size = os.path.getsize(db_path)
        except OSError:
            # Try relative to app root
            try:
                db_path_alt = os.path.join(current_app.root_path, "..", db_path)
                db_size = os.path.getsize(db_path_alt)
            except OSError:
                db_size = None

    # DNS resolvers and their status
    dns_settings = db.session.get(DnsSettings, 1)
    resolvers = dns_settings.get_resolvers() if dns_settings else ["8.8.8.8", "1.1.1.1"]
    resolver_statuses = _check_resolver_reachability(resolvers)

    # Last 50 check events
    recent_checks = (
        db.session.execute(
            db.select(CheckResult)
            .join(Domain, CheckResult.domain_id == Domain.id)
            .order_by(CheckResult.checked_at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )

    return render_template(
        "health.html",
        total_domains=total_domains,
        checked_today=checked_today,
        errors_today=errors_today,
        last_run_at=last_run_at,
        last_run_duration=last_run_duration,
        db_size=db_size,
        resolver_statuses=resolver_statuses,
        recent_checks=recent_checks,
        dns_settings=dns_settings,
    )


def _check_resolver_reachability(resolvers: list[str]) -> list[dict]:
    """Check if DNS resolvers are reachable via a simple UDP probe.

    Returns a list of dicts with 'resolver' and 'reachable' keys.
    This is a best-effort check - errors are caught and marked as unreachable.
    """
    import socket

    results = []
    for resolver in resolvers:
        reachable = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            # Send a minimal DNS query (ANY for root)
            sock.sendto(
                b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x01\x00\x01",
                (resolver, 53),
            )
            sock.recvfrom(512)
            reachable = True
        except (OSError, socket.timeout):
            reachable = False
        finally:
            try:
                sock.close()
            except Exception:
                pass
        results.append({"resolver": resolver, "reachable": reachable})
    return results
