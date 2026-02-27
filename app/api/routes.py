"""
F27 - API blueprint routes.

Provides JSON endpoints for programmatic access to domain status,
check history, dashboard summary, and application health.

All authenticated endpoints return 401 JSON when the user is not logged in.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import jsonify, request
from flask_login import current_user, login_required

from app import db
from app.api import bp
from app.models import CheckResult, DmarcReport, Domain
from app.utils.tenant import get_current_org_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_required(f):
    """Decorator that returns JSON 401 instead of redirecting to login."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Public endpoint
# ---------------------------------------------------------------------------


@bp.route("/health")
def health():
    """Public health-check endpoint -- no authentication required."""
    return jsonify(
        {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "SPF/DMARC/DKIM Watcher",
        }
    )


# ---------------------------------------------------------------------------
# Authenticated endpoints
# ---------------------------------------------------------------------------


@bp.route("/domains")
@_auth_required
def domains():
    """Return a JSON list of all active domains and their current status."""
    domain_list = (
        db.session.execute(
            db.select(Domain)
            .where(Domain.is_active == True, Domain.org_id == get_current_org_id())
            .order_by(Domain.hostname)
        )
        .scalars()
        .all()
    )
    return jsonify(
        [
            {
                "id": d.id,
                "hostname": d.hostname,
                "current_status": d.current_status,
                "last_checked_at": d.last_checked_at.isoformat() if d.last_checked_at else None,
                "last_ok_at": d.last_ok_at.isoformat() if d.last_ok_at else None,
            }
            for d in domain_list
        ]
    )


@bp.route("/domains/<int:domain_id>/history")
@_auth_required
def domain_history(domain_id: int):
    """Return check history data for Chart.js rendering.

    Response format:
    {
        "labels": ["2025-01-01 12:00", ...],
        "datasets": {
            "ok": [1, 0, ...],
            "warning": [0, 1, ...],
            "critical": [0, 0, ...]
        }
    }

    Each data point represents a single check. The value is 1 if the overall
    status matches that category, 0 otherwise. This enables stacked bar charts.
    """
    # Verify domain belongs to current org
    domain = db.session.get(Domain, domain_id)
    if domain is None:
        return jsonify({"error": "Domain not found"}), 404
    if not current_user.is_superadmin and domain.org_id != get_current_org_id():
        return jsonify({"error": "Domain not found"}), 404

    limit = request.args.get("limit", 30, type=int)
    limit = min(limit, 100)  # Cap at 100

    results = (
        db.session.execute(
            db.select(CheckResult)
            .where(CheckResult.domain_id == domain_id)
            .order_by(CheckResult.checked_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    # Reverse for chronological order
    results = list(reversed(results))

    labels = []
    ok_data = []
    warning_data = []
    critical_data = []

    for r in results:
        labels.append(r.checked_at.strftime("%Y-%m-%d %H:%M"))
        status = r.overall_status
        ok_data.append(1 if status == "ok" else 0)
        warning_data.append(1 if status == "warning" else 0)
        critical_data.append(1 if status in ("critical", "error") else 0)

    return jsonify(
        {
            "labels": labels,
            "datasets": {
                "ok": ok_data,
                "warning": warning_data,
                "critical": critical_data,
            },
        }
    )


@bp.route("/domains/<int:domain_id>/status")
@_auth_required
def domain_status(domain_id: int):
    """Return the current status breakdown for a single domain."""
    domain = db.session.get(Domain, domain_id)
    if domain is None:
        return jsonify({"error": "Domain not found"}), 404
    if not current_user.is_superadmin and domain.org_id != get_current_org_id():
        return jsonify({"error": "Domain not found"}), 404

    latest_result = (
        db.session.execute(
            db.select(CheckResult)
            .where(CheckResult.domain_id == domain_id)
            .order_by(CheckResult.checked_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )

    return jsonify(
        {
            "domain_id": domain.id,
            "hostname": domain.hostname,
            "overall_status": domain.current_status,
            "spf_status": latest_result.spf_status if latest_result else None,
            "dmarc_status": latest_result.dmarc_status if latest_result else None,
            "dkim_status": latest_result.dkim_status if latest_result else None,
            "reputation_status": latest_result.reputation_status if latest_result else None,
            "mx_provider": latest_result.mx_provider if latest_result else None,
            "registrar": latest_result.registrar if latest_result else None,
            "law25_status": latest_result.law25_status if latest_result else None,
            "mx_geolocation": latest_result.get_mx_geolocation() if latest_result else [],
            "last_checked": domain.last_checked_at.isoformat() if domain.last_checked_at else None,
            "last_ok": domain.last_ok_at.isoformat() if domain.last_ok_at else None,
        }
    )


@bp.route("/dashboard/summary")
@_auth_required
def dashboard_summary():
    """Return summary counts for the dashboard auto-refresh feature.

    Response format:
    {
        "total": 10,
        "ok": 7,
        "warning": 2,
        "critical": 1,
        "pending": 0,
        "timestamp": "2025-01-01T12:00:00+00:00"
    }
    """
    domain_list = (
        db.session.execute(
            db.select(Domain).where(
                Domain.is_active == True, Domain.org_id == get_current_org_id()
            )
        )
        .scalars()
        .all()
    )

    counts = {"ok": 0, "warning": 0, "critical": 0, "pending": 0}
    for d in domain_list:
        key = d.current_status if d.current_status in counts else "pending"
        counts[key] += 1

    return jsonify(
        {
            "total": len(domain_list),
            "ok": counts["ok"],
            "warning": counts["warning"],
            "critical": counts["critical"],
            "pending": counts["pending"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@bp.route("/dmarc-reports/trends")
@_auth_required
def dmarc_trends():
    """Return daily pass/fail aggregates for DMARC reports trend chart.

    Accepts optional ``domain`` query parameter to filter by policy_domain.
    Returns at most 90 days of data, sorted chronologically.
    """
    domain_filter: str = request.args.get("domain", "").strip()
    org_id = get_current_org_id()

    query = (
        db.select(
            db.func.date(DmarcReport.begin_date).label("day"),
            db.func.sum(DmarcReport.pass_count).label("pass_total"),
            db.func.sum(DmarcReport.fail_count).label("fail_total"),
        )
        .where(DmarcReport.org_id == org_id)
        .group_by(db.func.date(DmarcReport.begin_date))
        .order_by(db.func.date(DmarcReport.begin_date).asc())
    )
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    # Limit to last 90 days
    rows = db.session.execute(query).all()
    rows = rows[-90:] if len(rows) > 90 else rows

    labels = []
    pass_data = []
    fail_data = []
    for row in rows:
        labels.append(str(row.day))
        pass_data.append(int(row.pass_total or 0))
        fail_data.append(int(row.fail_total or 0))

    return jsonify({"labels": labels, "pass": pass_data, "fail": fail_data})
