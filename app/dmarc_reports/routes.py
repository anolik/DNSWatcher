"""
DMARC aggregate report blueprint routes.

Provides four endpoints:
  GET  /dmarc-reports/         — paginated report list with domain filter
  POST /dmarc-reports/upload   — manual file upload (ZIP/GZ/XML, max 1 MiB)
  POST /dmarc-reports/fetch    — trigger Graph API fetch manually
  GET  /dmarc-reports/<id>     — full report detail

Security controls (consistent with F33 standards):
- Only .zip, .gz, and .xml file extensions are accepted on upload.
- File size is capped at 1 MiB to prevent memory exhaustion.
- Filenames are never used as filesystem paths (no path traversal risk).
- All routes require an authenticated session.
"""

from __future__ import annotations

import json
import logging
import os

from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import login_required
from sqlalchemy.exc import IntegrityError

from app import db
from app.dmarc_reports import bp
from app.dmarc_reports.parser import parse_dmarc_attachment
from app.models import DmarcReport, DnsSettings, Domain

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Upload security constants
# ---------------------------------------------------------------------------

# Maximum file size accepted for upload (1 MiB).
_MAX_UPLOAD_BYTES: int = 1 * 1024 * 1024

# Allowed file extensions (lowercase, including the leading dot).
_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".zip", ".gz", ".xml"})


# ---------------------------------------------------------------------------
# Shared helper: persist a parsed DMARC report
# ---------------------------------------------------------------------------


def _ingest_parsed_report(
    parsed: dict,
    source: str,
    subject: str | None = None,
) -> tuple[bool, str]:
    """Save a parsed DMARC report to the database.

    Computes aggregate pass/fail counts from the individual records,
    resolves the policy domain to a known Domain row, and persists the
    DmarcReport.  The unique constraint on (report_id, org_name) is used
    to detect duplicates without a prior SELECT.

    Args:
        parsed: Dict returned by parse_dmarc_attachment().
        source: Origin of the report; either 'manual' or 'auto'.
        subject: Email subject line when the report arrived via Graph API.

    Returns:
        (True, "ok") on successful insertion.
        (False, "duplicate") when (report_id, org_name) already exists.
        (False, "error") on any other database failure.
    """
    records: list[dict] = parsed.get("records", [])

    # Aggregate counters
    total_messages: int = sum(r.get("count", 0) for r in records)
    pass_count: int = sum(
        r.get("count", 0)
        for r in records
        if r.get("dkim") == "pass" and r.get("spf") == "pass"
    )
    fail_count: int = total_messages - pass_count

    # Resolve policy domain to an active Domain row (optional FK)
    policy_domain: str = parsed.get("policy_domain", "")
    domain_row = db.session.execute(
        db.select(Domain).where(
            Domain.hostname == policy_domain,
            Domain.is_active.is_(True),
        )
    ).scalars().first()
    domain_id: int | None = domain_row.id if domain_row is not None else None

    report = DmarcReport(
        report_id=parsed.get("report_id", ""),
        org_name=parsed.get("org_name", ""),
        policy_domain=policy_domain,
        begin_date=parsed["begin_date"],
        end_date=parsed["end_date"],
        total_messages=total_messages,
        pass_count=pass_count,
        fail_count=fail_count,
        records_json=json.dumps(records),
        source=source,
        domain_id=domain_id,
        email_subject=subject,
    )
    db.session.add(report)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        logger.info(
            "_ingest_parsed_report: duplicate skipped report_id=%r org=%r",
            parsed.get("report_id"),
            parsed.get("org_name"),
        )
        return False, "duplicate"
    except Exception:
        db.session.rollback()
        logger.exception(
            "_ingest_parsed_report: database error for report_id=%r org=%r",
            parsed.get("report_id"),
            parsed.get("org_name"),
        )
        return False, "error"

    logger.info(
        "_ingest_parsed_report: ingested report_id=%r org=%r domain=%r source=%r",
        report.report_id,
        report.org_name,
        policy_domain,
        source,
    )
    return True, "ok"


# ---------------------------------------------------------------------------
# Graph API fetch (callable inside and outside request context)
# ---------------------------------------------------------------------------


def run_graph_fetch(app) -> tuple[int, int]:
    """Fetch DMARC reports from Exchange Online via the Microsoft Graph API.

    Designed to be called both from a Flask request context (POST /fetch)
    and from scheduled_check.py outside of any request context.  The
    ``app`` argument provides the application context explicitly so the
    function does not rely on the request-bound ``current_app`` proxy.

    Args:
        app: Flask application instance (not the proxy).

    Returns:
        A (imported_count, dupe_count) tuple.  Both values are zero when
        the Graph integration is disabled or unconfigured.
    """
    # Import here to avoid a circular import at module load time.
    from app.dmarc_reports.graph_client import fetch_dmarc_emails  # noqa: PLC0415

    with app.app_context():
        settings = db.session.get(DnsSettings, 1)
        if settings is None or not settings.graph_enabled:
            logger.debug("run_graph_fetch: Graph integration disabled or not configured.")
            return 0, 0

        try:
            emails = fetch_dmarc_emails(settings)
        except Exception:
            logger.exception("run_graph_fetch: fetch_dmarc_emails raised an exception.")
            return 0, 0

        imported: int = 0
        dupes: int = 0

        for email in emails:
            subject: str = email.get("subject", "")
            for attachment in email.get("attachments", []):
                name: str = attachment.get("name", "")
                data: bytes = attachment.get("data", b"")

                parsed = parse_dmarc_attachment(name, data)
                if parsed is None:
                    logger.debug(
                        "run_graph_fetch: skipping unrecognised attachment %r in email %r",
                        name,
                        email.get("message_id"),
                    )
                    continue

                ok, reason = _ingest_parsed_report(parsed, "auto", subject)
                if ok:
                    imported += 1
                elif reason == "duplicate":
                    dupes += 1
                # reason == "error" is already logged inside _ingest_parsed_report

        logger.info(
            "run_graph_fetch: complete imported=%d dupes=%d",
            imported,
            dupes,
        )
        return imported, dupes


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@bp.route("/", methods=["GET"])
@login_required
def index():
    """Render the paginated list of ingested DMARC reports.

    Supports optional filtering by policy_domain via the ``domain`` query
    parameter, and standard page-based pagination (20 rows per page).
    """
    domain_filter: str = request.args.get("domain", "").strip()
    page: int = request.args.get("page", 1, type=int)

    query = db.select(DmarcReport).order_by(DmarcReport.begin_date.desc())
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    pager = db.paginate(query, page=page, per_page=20, error_out=False)

    # Distinct policy_domains for the filter dropdown
    domains_result = db.session.execute(
        db.select(DmarcReport.policy_domain)
        .distinct()
        .order_by(DmarcReport.policy_domain)
    ).scalars().all()

    return render_template(
        "dmarc_reports/index.html",
        pager=pager,
        domains=domains_result,
        domain_filter=domain_filter,
    )


@bp.route("/upload", methods=["POST"])
@login_required
def upload():
    """Accept a manual DMARC report file upload and ingest it.

    Validates extension (.zip, .gz, .xml) and size (<= 1 MiB) before
    attempting to parse and store the report.  The uploaded filename is
    used only for extension detection; it is never treated as a path.
    """
    uploaded_file = request.files.get("dmarc_file")

    if not uploaded_file or not uploaded_file.filename:
        flash("No file selected. Please choose a file to upload.", "warning")
        return redirect(url_for("dmarc_reports.index"))

    # ------------------------------------------------------------------
    # Security: validate file extension
    # Use os.path.splitext on the lowercased original name only.
    # The filename is never used as a filesystem path.
    # ------------------------------------------------------------------
    original_name: str = uploaded_file.filename
    _, ext = os.path.splitext(original_name.lower())

    if ext not in _ALLOWED_EXTENSIONS:
        logger.warning(
            "upload: rejected disallowed extension ext=%r filename=%r",
            ext,
            original_name,
        )
        flash(
            "Invalid file type. Only .zip, .gz, and .xml files are accepted.",
            "danger",
        )
        return redirect(url_for("dmarc_reports.index"))

    # ------------------------------------------------------------------
    # Security: enforce 1 MiB size limit.
    # Read one byte beyond the limit to detect oversized uploads without
    # buffering the entire content first.
    # ------------------------------------------------------------------
    try:
        raw_bytes: bytes = uploaded_file.read(_MAX_UPLOAD_BYTES + 1)
    except Exception:
        flash("Could not read the uploaded file.", "danger")
        return redirect(url_for("dmarc_reports.index"))

    if len(raw_bytes) > _MAX_UPLOAD_BYTES:
        logger.warning(
            "upload: rejected oversized file filename=%r size>%d",
            original_name,
            _MAX_UPLOAD_BYTES,
        )
        flash("File is too large. Maximum allowed size is 1 MiB.", "danger")
        return redirect(url_for("dmarc_reports.index"))

    # ------------------------------------------------------------------
    # Parse and ingest
    # ------------------------------------------------------------------
    parsed = parse_dmarc_attachment(original_name, raw_bytes)
    if parsed is None:
        flash(
            "The file could not be parsed as a valid DMARC aggregate report.",
            "danger",
        )
        return redirect(url_for("dmarc_reports.index"))

    ok, reason = _ingest_parsed_report(parsed, "manual")

    if ok:
        flash(
            f"Report ingested: {parsed.get('report_id', '(unknown)')} "
            f"from {parsed.get('org_name', '(unknown)')} "
            f"for {parsed.get('policy_domain', '(unknown)')}.",
            "success",
        )
    elif reason == "duplicate":
        flash(
            "This report has already been ingested (duplicate report_id / org_name).",
            "warning",
        )
    else:
        flash(
            "A database error occurred while saving the report. Please try again.",
            "danger",
        )

    return redirect(url_for("dmarc_reports.index"))


@bp.route("/fetch", methods=["POST"])
@login_required
def fetch():
    """Trigger a manual Graph API fetch of DMARC report emails.

    Calls run_graph_fetch() with the real application object (not the
    proxy) so the function can be safely called outside request context
    as well.
    """
    imported, dupes = run_graph_fetch(current_app._get_current_object())

    if imported == 0 and dupes == 0:
        flash(
            "Graph API fetch complete: no new reports found "
            "(integration may be disabled or mailbox is empty).",
            "info",
        )
    else:
        parts: list[str] = []
        if imported:
            parts.append(f"{imported} report(s) imported")
        if dupes:
            parts.append(f"{dupes} duplicate(s) skipped")
        flash("Graph API fetch complete: " + ", ".join(parts) + ".", "success")

    return redirect(url_for("dmarc_reports.index"))


@bp.route("/<int:id>", methods=["GET"])
@login_required
def detail(id: int):
    """Render the full detail page for a single DMARC report.

    Args:
        id: Primary key of the DmarcReport row.
    """
    report = db.get_or_404(DmarcReport, id)
    records = report.get_records()

    return render_template(
        "dmarc_reports/detail.html",
        report=report,
        records=records,
    )
