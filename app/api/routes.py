"""
API blueprint routes.

Provides JSON endpoints for programmatic access to domain status,
manual check triggering, and application health.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import jsonify
from flask_login import login_required

from app.api import bp


@bp.route("/health")
def health():
    """Public health-check endpoint — no authentication required."""
    return jsonify(
        {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "SPF/DMARC/DKIM Watcher",
        }
    )


@bp.route("/domains")
@login_required
def domains():
    """Return a JSON list of all active domains and their current status."""
    from app import db
    from app.models import Domain

    domain_list = (
        db.session.execute(
            db.select(Domain).where(Domain.is_active == True).order_by(Domain.hostname)
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
