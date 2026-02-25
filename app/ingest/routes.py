"""
Ingest blueprint routes - F23.

Accepts an uploaded file containing email addresses and extracts unique
domains, adding any that are not already tracked in the database.
"""

from __future__ import annotations

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.ingest import bp
from app.ingest.parser import parse_email_file
from app.models import DkimSelector, Domain

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
    """Create a Domain plus default DkimSelector rows."""
    domain = Domain(hostname=hostname, added_by=user_id, current_status="pending")
    db.session.add(domain)
    db.session.flush()
    for sel_name in _DEFAULT_SELECTORS:
        db.session.add(DkimSelector(domain_id=domain.id, selector=sel_name, is_active=True))
    return domain


@bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Render the domain import page and process uploaded files."""
    if request.method == "POST":
        uploaded_file = request.files.get("email_file")

        if not uploaded_file or uploaded_file.filename == "":
            flash("No file selected. Please choose a file to upload.", "warning")
            return redirect(url_for("ingest.index"))

        # Read and decode file content
        try:
            raw_bytes = uploaded_file.read()
            content = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            flash("Could not read the uploaded file. Please upload a plain-text file.", "danger")
            return redirect(url_for("ingest.index"))

        if not content.strip():
            flash("The uploaded file is empty.", "warning")
            return redirect(url_for("ingest.index"))

        # Parse domains from the file
        result = parse_email_file(content)
        parsed_domains: list[str] = result["domains"]
        invalid_lines: list[str] = result["invalid_lines"]

        if not parsed_domains:
            flash(
                f"No valid email addresses found in the file. "
                f"{len(invalid_lines)} line(s) could not be parsed.",
                "warning",
            )
            return redirect(url_for("ingest.index"))

        # Determine which domains already exist
        existing_hostnames: set[str] = set(
            row[0]
            for row in db.session.execute(
                db.select(Domain.hostname).where(Domain.hostname.in_(parsed_domains))
            ).all()
        )

        added: list[str] = []
        reactivated: list[str] = []
        skipped: list[str] = []

        for hostname in parsed_domains:
            if hostname in existing_hostnames:
                # Check if inactive - reactivate if so
                existing = (
                    db.session.execute(
                        db.select(Domain).where(Domain.hostname == hostname)
                    )
                    .scalars()
                    .first()
                )
                if existing is not None and not existing.is_active:
                    existing.is_active = True
                    existing.current_status = "pending"
                    reactivated.append(hostname)
                else:
                    skipped.append(hostname)
            else:
                _create_domain_with_selectors(hostname, current_user.id)
                added.append(hostname)

        db.session.commit()

        # Build summary flash message
        parts: list[str] = []
        if added:
            parts.append(f"{len(added)} domain(s) added")
        if reactivated:
            parts.append(f"{len(reactivated)} reactivated")
        if skipped:
            parts.append(f"{len(skipped)} already monitored")
        if invalid_lines:
            parts.append(f"{len(invalid_lines)} line(s) skipped (no email found)")

        summary = "Import complete: " + ", ".join(parts) + "."
        flash(summary, "success" if (added or reactivated) else "info")
        return redirect(url_for("ingest.index"))

    return render_template("import.html")
