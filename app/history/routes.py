"""
History blueprint routes.

Renders the change log and per-domain check result history.
"""

from __future__ import annotations

from flask import render_template
from flask_login import login_required

from app import db
from app.history import bp
from app.models import ChangeLog


@bp.route("/")
@login_required
def index():
    """Render the recent change log across all domains."""
    changes = (
        db.session.execute(
            db.select(ChangeLog).order_by(ChangeLog.detected_at.desc()).limit(200)
        )
        .scalars()
        .all()
    )
    return render_template("history/index.html", changes=changes)
