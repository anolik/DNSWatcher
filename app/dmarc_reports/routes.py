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

import csv
import io
import json
import logging
import os

from flask import (
    Response,
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
# Analytics helpers
# ---------------------------------------------------------------------------


def _compute_summary_stats(domain_filter: str = "") -> dict:
    """Compute aggregate summary statistics for DMARC reports.

    Args:
        domain_filter: Optional policy_domain to filter by.

    Returns:
        Dict with total_reports, total_messages, pass_count, fail_count,
        pass_rate, top_failing_domain.
    """
    query = db.select(
        db.func.count(DmarcReport.id).label("total_reports"),
        db.func.coalesce(db.func.sum(DmarcReport.total_messages), 0).label("total_messages"),
        db.func.coalesce(db.func.sum(DmarcReport.pass_count), 0).label("pass_count"),
        db.func.coalesce(db.func.sum(DmarcReport.fail_count), 0).label("fail_count"),
    )
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    row = db.session.execute(query).one()
    total_messages = row.total_messages
    pass_rate = round((row.pass_count / total_messages * 100), 1) if total_messages > 0 else 0.0

    # Top failing domain (highest fail_count sum)
    top_fail_query = (
        db.select(
            DmarcReport.policy_domain,
            db.func.sum(DmarcReport.fail_count).label("total_fails"),
        )
        .group_by(DmarcReport.policy_domain)
        .order_by(db.func.sum(DmarcReport.fail_count).desc())
        .limit(1)
    )
    if domain_filter:
        top_fail_query = top_fail_query.where(DmarcReport.policy_domain == domain_filter)

    top_fail_row = db.session.execute(top_fail_query).first()
    top_failing_domain = top_fail_row.policy_domain if top_fail_row and top_fail_row.total_fails > 0 else None

    return {
        "total_reports": row.total_reports,
        "total_messages": total_messages,
        "pass_count": row.pass_count,
        "fail_count": row.fail_count,
        "pass_rate": pass_rate,
        "top_failing_domain": top_failing_domain,
    }


def _top_failing_ips(domain_filter: str = "", limit: int = 10) -> list[dict]:
    """Aggregate source IPs with highest fail counts from records_json.

    Args:
        domain_filter: Optional policy_domain to filter by.
        limit: Maximum number of IPs to return.

    Returns:
        List of dicts with source_ip, fail_count, total_count keys,
        sorted by fail_count descending.
    """
    query = db.select(DmarcReport.records_json)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    rows = db.session.execute(query).scalars().all()

    ip_stats: dict[str, dict] = {}
    for raw in rows:
        if not raw:
            continue
        try:
            records = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        for rec in records:
            ip = rec.get("source_ip", "unknown")
            count = rec.get("count", 0)
            dkim = rec.get("dkim", "")
            spf = rec.get("spf", "")
            is_pass = (dkim == "pass" and spf == "pass")

            if ip not in ip_stats:
                ip_stats[ip] = {"source_ip": ip, "fail_count": 0, "total_count": 0}
            ip_stats[ip]["total_count"] += count
            if not is_pass:
                ip_stats[ip]["fail_count"] += count

    sorted_ips = sorted(ip_stats.values(), key=lambda x: x["fail_count"], reverse=True)
    return sorted_ips[:limit]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


_SORTABLE_COLUMNS: dict[str, any] = {
    "begin_date": DmarcReport.begin_date,
    "org_name": DmarcReport.org_name,
    "policy_domain": DmarcReport.policy_domain,
    "total_messages": DmarcReport.total_messages,
    "pass_count": DmarcReport.pass_count,
    "fail_count": DmarcReport.fail_count,
    "source": DmarcReport.source,
    "email_subject": DmarcReport.email_subject,
}


@bp.route("/", methods=["GET"])
@login_required
def index():
    """Render the paginated list of ingested DMARC reports.

    Supports optional filtering by policy_domain via the ``domain`` query
    parameter, by org_name via the ``org`` query parameter, column sorting
    via ``sort`` and ``order`` parameters, and standard page-based
    pagination (20 rows per page).
    """
    domain_filter: str = request.args.get("domain", "").strip()
    org_filter: str = request.args.get("org", "").strip()
    page: int = request.args.get("page", 1, type=int)
    sort_col: str = request.args.get("sort", "begin_date").strip()
    sort_order: str = request.args.get("order", "desc").strip().lower()

    # Validate sort parameters
    if sort_col not in _SORTABLE_COLUMNS:
        sort_col = "begin_date"
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"

    column = _SORTABLE_COLUMNS[sort_col]
    order_clause = column.asc() if sort_order == "asc" else column.desc()

    query = db.select(DmarcReport).order_by(order_clause)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)
    if org_filter:
        query = query.where(DmarcReport.org_name == org_filter)

    pager = db.paginate(query, page=page, per_page=20, error_out=False)

    # Distinct policy_domains for the filter dropdown
    domains_result = db.session.execute(
        db.select(DmarcReport.policy_domain)
        .distinct()
        .order_by(DmarcReport.policy_domain)
    ).scalars().all()

    # Distinct org_names for the filter dropdown
    orgs_result = db.session.execute(
        db.select(DmarcReport.org_name)
        .distinct()
        .order_by(DmarcReport.org_name)
    ).scalars().all()

    # Analytics: summary stats and top failing IPs
    summary_stats = _compute_summary_stats(domain_filter)
    top_ips = _top_failing_ips(domain_filter)

    return render_template(
        "dmarc_reports/index.html",
        pager=pager,
        domains=domains_result,
        domain_filter=domain_filter,
        org_filter=org_filter,
        orgs=orgs_result,
        sort_col=sort_col,
        sort_order=sort_order,
        summary_stats=summary_stats,
        top_ips=top_ips,
    )


@bp.route("/upload", methods=["POST"])
@login_required
def upload():
    """Accept one or more DMARC report file uploads and ingest them.

    Validates extension (.zip, .gz, .xml) and size (<= 1 MiB) for each file
    before attempting to parse and store the report.
    """
    uploaded_files = request.files.getlist("dmarc_file")

    if not uploaded_files or all(not f.filename for f in uploaded_files):
        flash("No file selected. Please choose one or more files to upload.", "warning")
        return redirect(url_for("dmarc_reports.index"))

    imported: int = 0
    duplicates: int = 0
    errors: int = 0
    skipped: int = 0

    for uploaded_file in uploaded_files:
        if not uploaded_file or not uploaded_file.filename:
            continue

        original_name: str = uploaded_file.filename
        _, ext = os.path.splitext(original_name.lower())

        # Validate extension
        if ext not in _ALLOWED_EXTENSIONS:
            logger.warning(
                "upload: rejected disallowed extension ext=%r filename=%r",
                ext,
                original_name,
            )
            skipped += 1
            continue

        # Enforce size limit
        try:
            raw_bytes: bytes = uploaded_file.read(_MAX_UPLOAD_BYTES + 1)
        except Exception:
            errors += 1
            continue

        if len(raw_bytes) > _MAX_UPLOAD_BYTES:
            logger.warning(
                "upload: rejected oversized file filename=%r size>%d",
                original_name,
                _MAX_UPLOAD_BYTES,
            )
            skipped += 1
            continue

        # Parse and ingest
        parsed = parse_dmarc_attachment(original_name, raw_bytes)
        if parsed is None:
            errors += 1
            continue

        ok, reason = _ingest_parsed_report(parsed, "manual")
        if ok:
            imported += 1
        elif reason == "duplicate":
            duplicates += 1
        else:
            errors += 1

    # Flash summary
    parts: list[str] = []
    if imported:
        parts.append(f"{imported} report(s) imported")
    if duplicates:
        parts.append(f"{duplicates} duplicate(s) skipped")
    if skipped:
        parts.append(f"{skipped} file(s) rejected (invalid type or too large)")
    if errors:
        parts.append(f"{errors} file(s) failed to parse")

    if parts:
        category = "success" if imported > 0 else ("warning" if duplicates > 0 else "danger")
        flash("Upload complete: " + ", ".join(parts) + ".", category)
    else:
        flash("No valid files were processed.", "warning")

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


@bp.route("/export", methods=["GET"])
@login_required
def export_csv():
    """Export filtered DMARC reports as a CSV download.

    Respects the same domain and org query parameters as the index view.
    Returns all matching reports (no pagination) as a text/csv response.
    """
    domain_filter: str = request.args.get("domain", "").strip()
    org_filter: str = request.args.get("org", "").strip()
    sort_col: str = request.args.get("sort", "begin_date").strip()
    sort_order: str = request.args.get("order", "desc").strip().lower()

    if sort_col not in _SORTABLE_COLUMNS:
        sort_col = "begin_date"
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"

    column = _SORTABLE_COLUMNS[sort_col]
    order_clause = column.asc() if sort_order == "asc" else column.desc()

    query = db.select(DmarcReport).order_by(order_clause)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)
    if org_filter:
        query = query.where(DmarcReport.org_name == org_filter)

    reports = db.session.execute(query).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Report ID",
        "Org Name",
        "Policy Domain",
        "Begin Date",
        "End Date",
        "Total Messages",
        "Pass",
        "Fail",
        "Source",
        "Email Subject",
    ])

    # Data rows
    for report in reports:
        writer.writerow([
            report.report_id,
            report.org_name,
            report.policy_domain,
            report.begin_date.strftime("%Y-%m-%d") if report.begin_date else "",
            report.end_date.strftime("%Y-%m-%d") if report.end_date else "",
            report.total_messages,
            report.pass_count,
            report.fail_count,
            report.source,
            report.email_subject or "",
        ])

    csv_content = output.getvalue()
    output.close()

    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=dmarc_reports.csv",
        },
    )
