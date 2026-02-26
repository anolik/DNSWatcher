"""
Ingest blueprint routes - F23.

Accepts an uploaded file containing email addresses, domain names, or a
mix of both, and extracts unique domains to add to monitoring.

Security controls (F33):
- Only .txt and .csv file extensions are accepted.
- File size is capped at 1 MB to prevent memory exhaustion.
- Filenames are never used in filesystem paths (no path traversal risk).
"""

from __future__ import annotations

import logging
import os

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.ingest import bp
from app.ingest.parser import parse_import_file
from app.models import DkimSelector, Domain

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Upload security constants
# ---------------------------------------------------------------------------

# Maximum file size accepted for upload (1 MiB).
_MAX_UPLOAD_BYTES: int = 1 * 1024 * 1024

# Allowed file extensions (lowercase, including the leading dot).
_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".txt", ".csv"})

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

        # ------------------------------------------------------------------
        # Security: validate file extension (F33)
        # Use only the extension from the original filename; never use the
        # filename itself as a filesystem path to avoid path traversal.
        # ------------------------------------------------------------------
        original_name = uploaded_file.filename or ""
        _, ext = os.path.splitext(original_name.lower())
        if ext not in _ALLOWED_EXTENSIONS:
            logger.warning(
                "Upload rejected - disallowed extension: ext=%r user=%r",
                ext,
                current_user.username,
            )
            flash(
                "Invalid file type. Only .txt and .csv files are accepted.",
                "danger",
            )
            return redirect(url_for("ingest.index"))

        # ------------------------------------------------------------------
        # Security: enforce 1 MB size limit (F33)
        # Read one byte beyond the limit so we can detect oversized files
        # without storing the entire content first.
        # ------------------------------------------------------------------
        try:
            raw_bytes = uploaded_file.read(_MAX_UPLOAD_BYTES + 1)
        except Exception:
            flash("Could not read the uploaded file. Please upload a plain-text file.", "danger")
            return redirect(url_for("ingest.index"))

        if len(raw_bytes) > _MAX_UPLOAD_BYTES:
            logger.warning(
                "Upload rejected - file too large: user=%r filename=%r",
                current_user.username,
                original_name,
            )
            flash("File is too large. Maximum allowed size is 1 MB.", "danger")
            return redirect(url_for("ingest.index"))

        # Decode the bytes now that size and extension are verified.
        try:
            content = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            flash("Could not read the uploaded file. Please upload a plain-text file.", "danger")
            return redirect(url_for("ingest.index"))

        if not content.strip():
            flash("The uploaded file is empty.", "warning")
            return redirect(url_for("ingest.index"))

        # Parse domains from the file (supports emails, bare domains, or mixed)
        result = parse_import_file(content)
        parsed_domains: list[str] = result["domains"]
        invalid_lines: list[str] = result["invalid_lines"]

        if not parsed_domains:
            flash(
                f"No valid domains found in the file. "
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

        logger.info(
            "File import complete: added=%d reactivated=%d skipped=%d invalid_lines=%d user=%r filename=%r",
            len(added),
            len(reactivated),
            len(skipped),
            len(invalid_lines),
            current_user.username,
            uploaded_file.filename,
        )

        # Build summary flash message with domain names (up to 10)
        parts: list[str] = []
        if added:
            names = ", ".join(added[:10])
            suffix = f" (+{len(added) - 10} more)" if len(added) > 10 else ""
            parts.append(f"{len(added)} domain(s) added: {names}{suffix}")
        if reactivated:
            names = ", ".join(reactivated[:10])
            suffix = f" (+{len(reactivated) - 10} more)" if len(reactivated) > 10 else ""
            parts.append(f"{len(reactivated)} reactivated: {names}{suffix}")
        if skipped:
            parts.append(f"{len(skipped)} already monitored")
        if invalid_lines:
            parts.append(f"{len(invalid_lines)} line(s) skipped (no domain found)")

        summary = "Import complete: " + ". ".join(parts) + "."
        flash(summary, "success" if (added or reactivated) else "info")
        return redirect(url_for("ingest.index"))

    return render_template("import.html")
