"""
Dashboard blueprint routes.

Displays the list of monitored domains with their current check status,
plus summary counters (OK / warning / critical / pending).
"""

from __future__ import annotations

from flask import render_template
from flask_login import login_required

from app import db
from app.dashboard import bp
from app.models import Domain


@bp.route("/")
@login_required
def index():
    """Main dashboard - domain status overview."""
    domains = (
        db.session.execute(
            db.select(Domain).where(Domain.is_active == True).order_by(Domain.hostname)
        )
        .scalars()
        .all()
    )

    # Summary counters
    status_counts: dict[str, int] = {
        "ok": 0,
        "warning": 0,
        "critical": 0,
        "pending": 0,
        "error": 0,
    }
    for domain in domains:
        key = domain.current_status if domain.current_status in status_counts else "pending"
        status_counts[key] = status_counts.get(key, 0) + 1

    return render_template(
        "dashboard/index.html",
        domains=domains,
        status_counts=status_counts,
    )
