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
from datetime import datetime, timedelta, timezone

from flask import (
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from app import db
from app.dmarc_reports import bp
from app.dmarc_reports.parser import parse_dmarc_attachment
from app.models import DmarcReport, DnsSettings, Domain
from app.utils.auth import admin_required, editor_required
from app.utils.tenant import get_current_org_id

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
    org_id: int | None = None,
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
        org_id: Organization ID to assign to the report.

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
        org_id=org_id,
        email_subject=subject,
        policy_published_json=json.dumps({
            "adkim": parsed.get("published_adkim", ""),
            "aspf": parsed.get("published_aspf", ""),
            "pct": parsed.get("published_pct"),
            "sp": parsed.get("published_sp", ""),
        }) if parsed.get("published_adkim") is not None else None,
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


def run_graph_fetch(app, dns_settings: DnsSettings | None = None) -> tuple[int, int]:
    """Fetch DMARC reports from Exchange Online via the Microsoft Graph API.

    Designed to be called both from a Flask request context (POST /fetch)
    and from scheduled_check.py outside of any request context.  The
    ``app`` argument provides the application context explicitly so the
    function does not rely on the request-bound ``current_app`` proxy.

    F50: accepts an optional *dns_settings* parameter so the caller can
    pass a specific per-org DnsSettings row with its own Graph credentials.
    When omitted, falls back to loading the global row (org_id=NULL).

    Args:
        app: Flask application instance (not the proxy).
        dns_settings: Optional DnsSettings row to use for Graph credentials.
            When None, loads the global settings row.

    Returns:
        A (imported_count, dupe_count) tuple.  Both values are zero when
        the Graph integration is disabled or unconfigured.
    """
    # Import here to avoid a circular import at module load time.
    from app.dmarc_reports.graph_client import fetch_dmarc_emails  # noqa: PLC0415

    with app.app_context():
        if dns_settings is None:
            from app.utils.tenant import get_org_settings  # noqa: PLC0415
            settings = get_org_settings(None)
        else:
            # Re-merge in case the caller's session differs from this context
            settings = db.session.merge(dns_settings, load=False)
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


def _compute_summary_stats(domain_filter: str = "", org_id: int | None = None) -> dict:
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
    if org_id is not None:
        query = query.where(DmarcReport.org_id == org_id)
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
    if org_id is not None:
        top_fail_query = top_fail_query.where(DmarcReport.org_id == org_id)
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


def _top_failing_ips(domain_filter: str = "", limit: int = 10, org_id: int | None = None) -> list[dict]:
    """Aggregate source IPs with highest fail counts from records_json.

    Args:
        domain_filter: Optional policy_domain to filter by.
        limit: Maximum number of IPs to return.

    Returns:
        List of dicts with source_ip, fail_count, total_count keys,
        sorted by fail_count descending.
    """
    query = db.select(DmarcReport.records_json)
    if org_id is not None:
        query = query.where(DmarcReport.org_id == org_id)
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


def _stats_by_envelope_to(domain_filter: str = "", limit: int = 20, org_id: int | None = None) -> list[dict]:
    """Aggregate DMARC record statistics grouped by envelope_to (destination domain).

    Args:
        domain_filter: Optional policy_domain to filter by.
        limit: Maximum number of destination domains to return.

    Returns:
        List of dicts with envelope_to, total_count, pass_count, fail_count,
        pass_rate keys, sorted by total_count descending.
    """
    query = db.select(DmarcReport.records_json)
    if org_id is not None:
        query = query.where(DmarcReport.org_id == org_id)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    rows = db.session.execute(query).scalars().all()

    dest_stats: dict[str, dict] = {}
    for raw in rows:
        if not raw:
            continue
        try:
            records = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        for rec in records:
            envelope_to = rec.get("envelope_to", "").strip()
            if not envelope_to:
                continue
            count = rec.get("count", 0)
            dkim = rec.get("dkim", "")
            spf = rec.get("spf", "")
            is_pass = dkim == "pass" and spf == "pass"

            if envelope_to not in dest_stats:
                dest_stats[envelope_to] = {
                    "envelope_to": envelope_to,
                    "total_count": 0,
                    "pass_count": 0,
                    "fail_count": 0,
                }
            dest_stats[envelope_to]["total_count"] += count
            if is_pass:
                dest_stats[envelope_to]["pass_count"] += count
            else:
                dest_stats[envelope_to]["fail_count"] += count

    # Compute pass rates
    for stats in dest_stats.values():
        total = stats["total_count"]
        stats["pass_rate"] = round(stats["pass_count"] / total * 100, 1) if total > 0 else 0.0

    sorted_dests = sorted(dest_stats.values(), key=lambda x: x["total_count"], reverse=True)
    return sorted_dests[:limit]


def _distinct_envelope_to_domains(domain_filter: str = "", org_id: int | None = None) -> list[str]:
    """Return distinct envelope_to values from all DMARC records.

    Args:
        domain_filter: Optional policy_domain to filter by.

    Returns:
        Sorted list of unique envelope_to domain strings.
    """
    query = db.select(DmarcReport.records_json)
    if org_id is not None:
        query = query.where(DmarcReport.org_id == org_id)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    rows = db.session.execute(query).scalars().all()

    destinations: set[str] = set()
    for raw in rows:
        if not raw:
            continue
        try:
            records = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        for rec in records:
            envelope_to = rec.get("envelope_to", "").strip()
            if envelope_to:
                destinations.add(envelope_to)

    return sorted(destinations)


def _load_all_records(domain_filter: str = "", org_id: int | None = None) -> list[dict]:
    """Load and parse all records_json entries for analytics."""
    query = db.select(DmarcReport.records_json)
    if org_id is not None:
        query = query.where(DmarcReport.org_id == org_id)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)
    rows = db.session.execute(query).scalars().all()
    all_records = []
    for raw in rows:
        if not raw:
            continue
        try:
            records = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        all_records.extend(records)
    return all_records


def _failure_mode_breakdown(domain_filter: str = "", org_id: int | None = None) -> dict:
    """Categorize failures into distinct modes."""
    all_records = _load_all_records(domain_filter, org_id=org_id)
    total_pass = 0
    total_fail = 0
    dkim_only_fail = 0
    spf_only_fail = 0
    both_fail = 0
    forwarding = 0
    mailing_list = 0
    sampled_out = 0
    local_policy = 0

    for rec in all_records:
        count = rec.get("count", 0)
        dkim = rec.get("dkim", "")
        spf = rec.get("spf", "")
        override = rec.get("override_reason", "")
        is_pass = dkim == "pass" and spf == "pass"

        if is_pass:
            total_pass += count
        else:
            total_fail += count
            if dkim == "pass" and spf != "pass":
                spf_only_fail += count
            elif dkim != "pass" and spf == "pass":
                dkim_only_fail += count
            else:
                both_fail += count

        if override in ("forwarded", "trusted_forwarder"):
            forwarding += count
        elif override == "mailing_list":
            mailing_list += count
        elif override == "sampled_out":
            sampled_out += count
        elif override == "local_policy":
            local_policy += count

    true_fail = total_fail - forwarding - mailing_list
    if true_fail < 0:
        true_fail = 0

    return {
        "dkim_only_fail": dkim_only_fail,
        "spf_only_fail": spf_only_fail,
        "both_fail": both_fail,
        "forwarding": forwarding,
        "mailing_list": mailing_list,
        "sampled_out": sampled_out,
        "local_policy": local_policy,
        "total_pass": total_pass,
        "total_fail": total_fail,
        "true_fail": true_fail,
    }


def _override_stats(domain_filter: str = "", org_id: int | None = None) -> list[dict]:
    """Count records by override reason type."""
    all_records = _load_all_records(domain_filter, org_id=org_id)
    reason_counts: dict[str, int] = {}
    total = 0

    for rec in all_records:
        override = rec.get("override_reason", "")
        if not override:
            continue
        count = rec.get("count", 0)
        reason_counts[override] = reason_counts.get(override, 0) + count
        total += count

    result = []
    for reason, count in sorted(reason_counts.items(), key=lambda x: x[1], reverse=True):
        result.append({
            "reason": reason,
            "count": count,
            "percentage": round(count / total * 100, 1) if total > 0 else 0.0,
        })
    return result


def _stats_by_dkim_selector(domain_filter: str = "", limit: int = 20, org_id: int | None = None) -> list[dict]:
    """Per-selector pass rates from all_dkim_results."""
    all_records = _load_all_records(domain_filter, org_id=org_id)
    selector_stats: dict[str, dict] = {}

    for rec in all_records:
        count = rec.get("count", 0)
        for dkim_entry in rec.get("all_dkim_results", []):
            selector = dkim_entry.get("selector") or "unknown"
            domain = dkim_entry.get("domain") or ""
            result = dkim_entry.get("result", "")
            key = f"{selector}|{domain}"

            if key not in selector_stats:
                selector_stats[key] = {
                    "selector": selector,
                    "domain": domain,
                    "total": 0,
                    "pass_count": 0,
                    "fail_count": 0,
                }
            selector_stats[key]["total"] += count
            if result == "pass":
                selector_stats[key]["pass_count"] += count
            else:
                selector_stats[key]["fail_count"] += count

    result_list = list(selector_stats.values())
    for s in result_list:
        s["pass_rate"] = round(s["pass_count"] / s["total"] * 100, 1) if s["total"] > 0 else 0.0

    result_list.sort(key=lambda x: x["total"], reverse=True)
    return result_list[:limit]


def _alignment_analysis(domain_filter: str = "", org_id: int | None = None) -> list[dict]:
    """Identify envelope_from vs header_from mismatches."""
    all_records = _load_all_records(domain_filter, org_id=org_id)
    alignment_stats: dict[str, dict] = {}

    for rec in all_records:
        envelope_from = rec.get("envelope_from", "").strip()
        header_from = rec.get("header_from", "").strip()
        if not envelope_from and not header_from:
            continue
        count = rec.get("count", 0)
        spf = rec.get("spf", "")
        key = f"{envelope_from}|{header_from}"

        if key not in alignment_stats:
            aligned = (
                envelope_from == header_from
                or envelope_from.endswith("." + header_from)
                or header_from.endswith("." + envelope_from)
                or not envelope_from
            )
            alignment_stats[key] = {
                "envelope_from": envelope_from or "(empty)",
                "header_from": header_from or "(empty)",
                "count": 0,
                "aligned": aligned,
                "spf_pass": 0,
                "total": 0,
            }
        alignment_stats[key]["count"] += count
        alignment_stats[key]["total"] += count
        if spf == "pass":
            alignment_stats[key]["spf_pass"] += count

    result_list = list(alignment_stats.values())
    for a in result_list:
        a["spf_pass_rate"] = round(a["spf_pass"] / a["total"] * 100, 1) if a["total"] > 0 else 0.0

    result_list.sort(key=lambda x: x["count"], reverse=True)
    return result_list[:20]


def _stats_by_subdomain(domain_filter: str = "", limit: int = 20, org_id: int | None = None) -> list[dict]:
    """Group records by subdomain of header_from relative to policy_domain."""
    query = db.select(DmarcReport.policy_domain, DmarcReport.records_json)
    if org_id is not None:
        query = query.where(DmarcReport.org_id == org_id)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    rows = db.session.execute(query).all()
    subdomain_stats: dict[str, dict] = {}

    for policy_domain, raw in rows:
        if not raw:
            continue
        try:
            records = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        for rec in records:
            header_from = rec.get("header_from", "").strip()
            count = rec.get("count", 0)
            dkim = rec.get("dkim", "")
            spf = rec.get("spf", "")
            is_pass = dkim == "pass" and spf == "pass"

            if header_from == policy_domain:
                subdomain = "(root)"
            elif header_from.endswith("." + policy_domain):
                subdomain = header_from[: -(len(policy_domain) + 1)]
            else:
                subdomain = header_from

            if subdomain not in subdomain_stats:
                subdomain_stats[subdomain] = {
                    "subdomain": subdomain,
                    "total": 0,
                    "pass_count": 0,
                    "fail_count": 0,
                }
            subdomain_stats[subdomain]["total"] += count
            if is_pass:
                subdomain_stats[subdomain]["pass_count"] += count
            else:
                subdomain_stats[subdomain]["fail_count"] += count

    result_list = list(subdomain_stats.values())
    for s in result_list:
        s["pass_rate"] = round(s["pass_count"] / s["total"] * 100, 1) if s["total"] > 0 else 0.0

    result_list.sort(key=lambda x: x["total"], reverse=True)
    return result_list[:limit]


def _new_disappeared_ips(domain_filter: str = "", days_recent: int = 7, days_previous: int = 7, org_id: int | None = None) -> dict:
    """Compare IPs between recent and previous period."""
    now = datetime.now(timezone.utc)
    recent_start = now - timedelta(days=days_recent)
    previous_start = recent_start - timedelta(days=days_previous)

    def _collect_ips(start: datetime, end: datetime) -> dict[str, dict]:
        query = db.select(DmarcReport.records_json).where(
            DmarcReport.begin_date >= start,
            DmarcReport.begin_date < end,
        )
        if org_id is not None:
            query = query.where(DmarcReport.org_id == org_id)
        if domain_filter:
            query = query.where(DmarcReport.policy_domain == domain_filter)
        rows = db.session.execute(query).scalars().all()

        ip_data: dict[str, dict] = {}
        for raw in rows:
            if not raw:
                continue
            try:
                records = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            for rec in records:
                ip = rec.get("source_ip", "")
                count = rec.get("count", 0)
                dkim = rec.get("dkim", "")
                spf = rec.get("spf", "")
                if ip not in ip_data:
                    ip_data[ip] = {"ip": ip, "count": 0, "dkim_pass": 0, "spf_pass": 0}
                ip_data[ip]["count"] += count
                if dkim == "pass":
                    ip_data[ip]["dkim_pass"] += count
                if spf == "pass":
                    ip_data[ip]["spf_pass"] += count
        return ip_data

    recent_ips = _collect_ips(recent_start, now)
    previous_ips = _collect_ips(previous_start, recent_start)

    new_ips = []
    for ip, data in recent_ips.items():
        if ip not in previous_ips:
            new_ips.append({
                "ip": ip,
                "count": data["count"],
                "dkim": "pass" if data["dkim_pass"] > data["count"] // 2 else "fail",
                "spf": "pass" if data["spf_pass"] > data["count"] // 2 else "fail",
                "first_seen": "recent",
            })

    disappeared_ips = []
    for ip, data in previous_ips.items():
        if ip not in recent_ips:
            disappeared_ips.append({
                "ip": ip,
                "last_count": data["count"],
                "last_seen": "previous",
            })

    new_ips.sort(key=lambda x: x["count"], reverse=True)
    disappeared_ips.sort(key=lambda x: x["last_count"], reverse=True)

    return {
        "new_ips": new_ips[:20],
        "disappeared_ips": disappeared_ips[:20],
        "period_recent": f"{recent_start.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}",
        "period_previous": f"{previous_start.strftime('%Y-%m-%d')} to {recent_start.strftime('%Y-%m-%d')}",
    }


def _classify_sending_sources(domain_filter: str = "", limit: int = 30, org_id: int | None = None) -> list[dict]:
    """Classify top source IPs via PTR lookup."""
    from app.dmarc_reports.source_classifier import classify_sources

    all_records = _load_all_records(domain_filter, org_id=org_id)
    ip_stats: dict[str, dict] = {}

    for rec in all_records:
        ip = rec.get("source_ip", "")
        count = rec.get("count", 0)
        dkim = rec.get("dkim", "")
        spf = rec.get("spf", "")
        is_pass = dkim == "pass" and spf == "pass"

        if ip not in ip_stats:
            ip_stats[ip] = {"ip": ip, "count": 0, "pass_count": 0, "fail_count": 0}
        ip_stats[ip]["count"] += count
        if is_pass:
            ip_stats[ip]["pass_count"] += count
        else:
            ip_stats[ip]["fail_count"] += count

    # Sort by total count, take top N
    top_ips = sorted(ip_stats.values(), key=lambda x: x["count"], reverse=True)[:limit]

    if not top_ips:
        return []

    # PTR classify
    ip_list = [entry["ip"] for entry in top_ips]
    classifications = classify_sources(ip_list, max_ips=limit)

    result = []
    for entry in top_ips:
        cls = classifications.get(entry["ip"], {})
        result.append({
            "ip": entry["ip"],
            "count": entry["count"],
            "pass_count": entry["pass_count"],
            "fail_count": entry["fail_count"],
            "provider": cls.get("provider"),
            "category": cls.get("category", "unknown"),
            "ptr": cls.get("ptr"),
        })
    return result


def _bimi_readiness(domain_filter: str = "", org_id: int | None = None) -> list[dict]:
    """Per-domain BIMI readiness based on DMARC report data."""
    query = db.select(
        DmarcReport.policy_domain,
        db.func.sum(DmarcReport.total_messages).label("total"),
        db.func.sum(DmarcReport.pass_count).label("passes"),
        DmarcReport.policy_published_json,
    ).group_by(DmarcReport.policy_domain)
    if org_id is not None:
        query = query.where(DmarcReport.org_id == org_id)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    rows = db.session.execute(query).all()
    result = []

    for row in rows:
        total = row.total or 0
        passes = row.passes or 0
        pass_rate = round(passes / total * 100, 1) if total > 0 else 0.0

        policy_data = {}
        if row.policy_published_json:
            try:
                policy_data = json.loads(row.policy_published_json)
            except (json.JSONDecodeError, TypeError):
                pass

        policy = policy_data.get("p", "none")
        pct = policy_data.get("pct")

        issues = []
        if pass_rate < 95:
            issues.append(f"Pass rate {pass_rate}% < 95%")
        if policy not in ("quarantine", "reject"):
            issues.append(f"Policy is '{policy}' (need quarantine or reject)")
        if pct is not None and pct < 100:
            issues.append(f"pct={pct} (need 100)")

        result.append({
            "domain": row.policy_domain,
            "pass_rate": pass_rate,
            "policy": policy,
            "pct": pct,
            "bimi_ready": len(issues) == 0,
            "issues": issues,
        })

    result.sort(key=lambda x: (not x["bimi_ready"], -x["pass_rate"]))
    return result


def _multi_domain_comparison(org_id: int | None = None) -> list[dict]:
    """Side-by-side DMARC posture for all monitored domains."""
    query = db.select(
        DmarcReport.policy_domain,
        db.func.sum(DmarcReport.total_messages).label("total"),
        db.func.sum(DmarcReport.pass_count).label("passes"),
        db.func.sum(DmarcReport.fail_count).label("fails"),
    ).group_by(DmarcReport.policy_domain).order_by(
        db.func.sum(DmarcReport.total_messages).desc()
    )
    if org_id is not None:
        query = query.where(DmarcReport.org_id == org_id)

    rows = db.session.execute(query).all()
    result = []

    for row in rows:
        total = row.total or 0
        passes = row.passes or 0
        pass_rate = round(passes / total * 100, 1) if total > 0 else 0.0

        # Get latest policy published
        latest = db.session.execute(
            db.select(DmarcReport.policy_published_json)
            .where(DmarcReport.policy_domain == row.policy_domain)
            .where(DmarcReport.policy_published_json.isnot(None))
            .order_by(DmarcReport.begin_date.desc())
            .limit(1)
        ).scalar()

        policy_data = {}
        if latest:
            try:
                policy_data = json.loads(latest)
            except (json.JSONDecodeError, TypeError):
                pass

        result.append({
            "domain": row.policy_domain,
            "total_messages": total,
            "pass_rate": pass_rate,
            "policy": policy_data.get("p", "—"),
            "pct": policy_data.get("pct"),
            "adkim": policy_data.get("adkim", "—"),
            "aspf": policy_data.get("aspf", "—"),
        })
    return result


def _check_pass_rate_alerts(domain_filter: str = "", org_id: int | None = None) -> list[dict]:
    """Detect pass rate drops between periods."""
    now = datetime.now(timezone.utc)
    current_start = now - timedelta(days=7)
    previous_start = current_start - timedelta(days=7)

    def _period_rates(start: datetime, end: datetime) -> dict[str, float]:
        query = db.select(
            DmarcReport.policy_domain,
            db.func.sum(DmarcReport.total_messages).label("total"),
            db.func.sum(DmarcReport.pass_count).label("passes"),
        ).where(
            DmarcReport.begin_date >= start,
            DmarcReport.begin_date < end,
        ).group_by(DmarcReport.policy_domain)
        if org_id is not None:
            query = query.where(DmarcReport.org_id == org_id)
        if domain_filter:
            query = query.where(DmarcReport.policy_domain == domain_filter)

        rows = db.session.execute(query).all()
        rates = {}
        for row in rows:
            total = row.total or 0
            if total > 0:
                rates[row.policy_domain] = round((row.passes or 0) / total * 100, 1)
        return rates

    current_rates = _period_rates(current_start, now)
    previous_rates = _period_rates(previous_start, current_start)

    alerts = []
    for domain, current_rate in current_rates.items():
        previous_rate = previous_rates.get(domain)
        if previous_rate is not None:
            drop = round(previous_rate - current_rate, 1)
            if drop > 5 or current_rate < 90:
                severity = "critical" if (drop > 15 or current_rate < 70) else "warning"
                alerts.append({
                    "domain": domain,
                    "current_rate": current_rate,
                    "previous_rate": previous_rate,
                    "drop": drop,
                    "severity": severity,
                })
        elif current_rate < 90:
            alerts.append({
                "domain": domain,
                "current_rate": current_rate,
                "previous_rate": None,
                "drop": 0,
                "severity": "warning",
            })

    alerts.sort(key=lambda x: (-x.get("drop", 0), x["current_rate"]))
    return alerts


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

_AGG_SORTABLE_COLUMNS: dict[str, any] = {
    "policy_domain": DmarcReport.policy_domain,
    "report_count": db.func.count(DmarcReport.id),
    "earliest_date": db.func.min(DmarcReport.begin_date),
    "total_messages": db.func.sum(DmarcReport.total_messages),
    "pass_count": db.func.sum(DmarcReport.pass_count),
    "fail_count": db.func.sum(DmarcReport.fail_count),
}


class _AggPagination:
    """Pagination-compatible object for aggregate (non-model) queries.

    Flask-SQLAlchemy's ``db.paginate()`` calls ``.scalars()`` internally,
    which strips grouped Row objects to just the first column.  This helper
    performs the pagination manually and exposes the same interface that the
    Jinja ``pagination`` macro expects.
    """

    def __init__(self, items: list, total: int, page: int, per_page: int) -> None:
        self.items = items
        self.total = total
        self.page = page
        self.per_page = per_page
        self.pages: int = max(1, -(-total // per_page)) if total else 1
        self.has_prev: bool = page > 1
        self.has_next: bool = page < self.pages
        self.prev_num: int | None = page - 1 if self.has_prev else None
        self.next_num: int | None = page + 1 if self.has_next else None

    def iter_pages(
        self,
        left_edge: int = 2,
        right_edge: int = 2,
        left_current: int = 2,
        right_current: int = 2,
    ):
        """Yield page numbers with ``None`` gaps for ellipsis."""
        last = 0
        for num in range(1, self.pages + 1):
            if (
                num <= left_edge
                or (self.page - left_current <= num <= self.page + right_current)
                or num > self.pages - right_edge
            ):
                if last + 1 != num:
                    yield None
                yield num
                last = num


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
    dest_filter: str = request.args.get("dest", "").strip()
    page: int = request.args.get("page", 1, type=int)
    sort_col: str = request.args.get("sort", "earliest_date").strip()
    sort_order: str = request.args.get("order", "desc").strip().lower()

    # Validate sort parameters for aggregated view
    if sort_col not in _AGG_SORTABLE_COLUMNS:
        sort_col = "earliest_date"
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"

    sort_expr = _AGG_SORTABLE_COLUMNS[sort_col]
    order_clause = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()

    org_id = get_current_org_id()

    # Aggregated query: one row per policy_domain (scoped to org)
    query = db.select(
        DmarcReport.policy_domain,
        db.func.count(DmarcReport.id).label("report_count"),
        db.func.min(DmarcReport.begin_date).label("earliest_date"),
        db.func.max(DmarcReport.end_date).label("latest_date"),
        db.func.sum(DmarcReport.total_messages).label("total_messages"),
        db.func.sum(DmarcReport.pass_count).label("pass_count"),
        db.func.sum(DmarcReport.fail_count).label("fail_count"),
    ).where(DmarcReport.org_id == org_id).group_by(DmarcReport.policy_domain)

    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)
    if org_filter:
        query = query.where(DmarcReport.org_name == org_filter)
    if dest_filter:
        query = query.where(DmarcReport.records_json.contains(dest_filter))

    query = query.order_by(order_clause)

    # Manual pagination for aggregate query (db.paginate calls .scalars()
    # which strips Row objects to just the first column).
    per_page = 20
    total = db.session.execute(
        db.select(db.func.count()).select_from(query.subquery())
    ).scalar()
    items = db.session.execute(
        query.limit(per_page).offset((page - 1) * per_page)
    ).all()
    pager = _AggPagination(items=items, total=total, page=page, per_page=per_page)

    # Distinct policy_domains for the filter dropdown (scoped to org)
    domains_result = db.session.execute(
        db.select(DmarcReport.policy_domain)
        .where(DmarcReport.org_id == org_id)
        .distinct()
        .order_by(DmarcReport.policy_domain)
    ).scalars().all()

    # Distinct org_names for the filter dropdown (scoped to org)
    orgs_result = db.session.execute(
        db.select(DmarcReport.org_name)
        .where(DmarcReport.org_id == org_id)
        .distinct()
        .order_by(DmarcReport.org_name)
    ).scalars().all()

    # Distinct envelope_to destinations for the filter dropdown
    dest_domains = _distinct_envelope_to_domains(domain_filter, org_id=org_id)

    # Analytics: summary stats, top failing IPs, and destination stats
    summary_stats = _compute_summary_stats(domain_filter, org_id=org_id)
    top_ips = _top_failing_ips(domain_filter, org_id=org_id)
    dest_stats = _stats_by_envelope_to(domain_filter, org_id=org_id)

    # Extended analytics
    failure_modes = _failure_mode_breakdown(domain_filter, org_id=org_id)
    override_stats = _override_stats(domain_filter, org_id=org_id)
    selector_stats = _stats_by_dkim_selector(domain_filter, org_id=org_id)
    alignment_data = _alignment_analysis(domain_filter, org_id=org_id)
    subdomain_stats = _stats_by_subdomain(domain_filter, org_id=org_id)
    ip_changes = _new_disappeared_ips(domain_filter, org_id=org_id)
    source_classes = _classify_sending_sources(domain_filter, org_id=org_id)
    bimi_readiness = _bimi_readiness(domain_filter, org_id=org_id)
    domain_comparison = _multi_domain_comparison(org_id=org_id)
    pass_rate_alerts = _check_pass_rate_alerts(domain_filter, org_id=org_id)

    return render_template(
        "dmarc_reports/index.html",
        pager=pager,
        domains=domains_result,
        domain_filter=domain_filter,
        org_filter=org_filter,
        dest_filter=dest_filter,
        orgs=orgs_result,
        dest_domains=dest_domains,
        sort_col=sort_col,
        sort_order=sort_order,
        summary_stats=summary_stats,
        top_ips=top_ips,
        dest_stats=dest_stats,
        failure_modes=failure_modes,
        override_stats=override_stats,
        selector_stats=selector_stats,
        alignment_data=alignment_data,
        subdomain_stats=subdomain_stats,
        ip_changes=ip_changes,
        source_classes=source_classes,
        bimi_readiness=bimi_readiness,
        domain_comparison=domain_comparison,
        pass_rate_alerts=pass_rate_alerts,
    )


@bp.route("/upload", methods=["POST"])
@editor_required
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

        ok, reason = _ingest_parsed_report(parsed, "manual", org_id=get_current_org_id())
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
@editor_required
def fetch():
    """Trigger a manual Graph API fetch of DMARC report emails.

    Calls run_graph_fetch() with the real application object (not the
    proxy) so the function can be safely called outside request context
    as well.
    """
    from app.utils.tenant import get_org_settings  # noqa: PLC0415

    org_id = get_current_org_id()
    settings = get_org_settings(org_id)

    # Give a clear error if config is incomplete instead of a vague "no reports"
    if not settings or not settings.graph_enabled:
        flash("Inbound email integration is disabled. Enable it in Settings → Inbound Email.", "warning")
        return redirect(url_for("dmarc_reports.index"))

    missing = [
        name for name, val in (
            ("Tenant ID", settings.graph_tenant_id),
            ("Client ID", settings.graph_client_id),
            ("Client Secret", settings.graph_client_secret),
            ("Mailbox", settings.graph_mailbox),
        ) if not val
    ]
    if missing:
        flash(f"Inbound email config incomplete — missing: {', '.join(missing)}. Check Settings → Inbound Email.", "error")
        return redirect(url_for("dmarc_reports.index"))

    imported, dupes = run_graph_fetch(current_app._get_current_object(), dns_settings=settings)

    if imported == 0 and dupes == 0:
        flash(
            "Graph API fetch complete: no new reports found (mailbox may be empty).",
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
    if not current_user.is_superadmin and report.org_id != get_current_org_id():
        from flask import abort
        abort(404)
    records = report.get_records()
    policy_published = report.get_policy_published()

    return render_template(
        "dmarc_reports/detail.html",
        report=report,
        records=records,
        policy_published=policy_published,
    )


@bp.route("/domain/<path:domain>", methods=["GET"])
@login_required
def domain_detail(domain: str):
    """Show all DMARC reports for a specific policy domain.

    Args:
        domain: The policy_domain to display reports for.
    """
    org_filter: str = request.args.get("org", "").strip()
    sort_col: str = request.args.get("sort", "begin_date").strip()
    sort_order: str = request.args.get("order", "desc").strip().lower()
    page: int = request.args.get("page", 1, type=int)

    org_id = get_current_org_id()
    query = db.select(DmarcReport).where(
        DmarcReport.policy_domain == domain,
        DmarcReport.org_id == org_id,
    )
    if org_filter:
        query = query.where(DmarcReport.org_name == org_filter)

    # Sort
    if sort_col not in _SORTABLE_COLUMNS:
        sort_col = "begin_date"
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"
    column = _SORTABLE_COLUMNS[sort_col]
    order_clause = column.asc() if sort_order == "asc" else column.desc()
    query = query.order_by(order_clause)

    pager = db.paginate(query, page=page, per_page=20, error_out=False)

    # Distinct orgs for this domain (filter dropdown)
    orgs = db.session.execute(
        db.select(DmarcReport.org_name)
        .where(DmarcReport.policy_domain == domain, DmarcReport.org_id == org_id)
        .distinct()
        .order_by(DmarcReport.org_name)
    ).scalars().all()

    # Aggregate stats for header card
    stats = db.session.execute(
        db.select(
            db.func.count(DmarcReport.id).label("report_count"),
            db.func.sum(DmarcReport.total_messages).label("total_messages"),
            db.func.sum(DmarcReport.pass_count).label("pass_count"),
            db.func.sum(DmarcReport.fail_count).label("fail_count"),
            db.func.min(DmarcReport.begin_date).label("earliest"),
            db.func.max(DmarcReport.end_date).label("latest"),
        ).where(DmarcReport.policy_domain == domain, DmarcReport.org_id == org_id)
    ).one()

    # Latest published policy
    latest_policy_json = db.session.execute(
        db.select(DmarcReport.policy_published_json)
        .where(DmarcReport.policy_domain == domain, DmarcReport.org_id == org_id)
        .where(DmarcReport.policy_published_json.isnot(None))
        .order_by(DmarcReport.begin_date.desc())
        .limit(1)
    ).scalar()
    policy_published: dict = {}
    if latest_policy_json:
        try:
            policy_published = json.loads(latest_policy_json)
        except (json.JSONDecodeError, TypeError):
            pass

    return render_template(
        "dmarc_reports/domain_detail.html",
        domain=domain,
        pager=pager,
        orgs=orgs,
        org_filter=org_filter,
        sort_col=sort_col,
        sort_order=sort_order,
        stats=stats,
        policy_published=policy_published,
    )


@bp.route("/ip/<path:ip>", methods=["GET"])
@login_required
def ip_detail(ip: str):
    """Show all DMARC records associated with a specific source IP.

    Args:
        ip: Source IP address to look up.
    """
    domain_filter: str = request.args.get("domain", "").strip()

    org_id = get_current_org_id()
    query = db.select(
        DmarcReport.id,
        DmarcReport.report_id,
        DmarcReport.org_name,
        DmarcReport.policy_domain,
        DmarcReport.begin_date,
        DmarcReport.end_date,
        DmarcReport.records_json,
    ).where(DmarcReport.org_id == org_id)
    if domain_filter:
        query = query.where(DmarcReport.policy_domain == domain_filter)

    rows = db.session.execute(query).all()

    matching_records: list[dict] = []
    for row in rows:
        if not row.records_json:
            continue
        try:
            records = json.loads(row.records_json)
        except (json.JSONDecodeError, TypeError):
            continue
        for rec in records:
            if rec.get("source_ip") == ip:
                matching_records.append({
                    **rec,
                    "report_id": row.report_id,
                    "report_db_id": row.id,
                    "org_name": row.org_name,
                    "policy_domain": row.policy_domain,
                    "begin_date": row.begin_date,
                })

    matching_records.sort(key=lambda x: x.get("begin_date") or "", reverse=True)

    # PTR classification for this IP
    from app.dmarc_reports.source_classifier import classify_sources
    classification = classify_sources([ip], max_ips=1).get(ip, {})

    # Aggregate stats
    total_messages = sum(r.get("count", 0) for r in matching_records)
    pass_count = sum(
        r.get("count", 0) for r in matching_records
        if r.get("dkim") == "pass" and r.get("spf") == "pass"
    )

    return render_template(
        "dmarc_reports/ip_detail.html",
        ip=ip,
        records=matching_records,
        classification=classification,
        total_messages=total_messages,
        pass_count=pass_count,
        fail_count=total_messages - pass_count,
        domain_filter=domain_filter,
    )


@bp.route("/export", methods=["GET"])
@login_required
def export_csv():
    """Export DMARC reports as a CSV download.

    Default format is aggregated (one row per policy_domain) matching the
    index view.  Pass ``?format=detail`` to export individual reports.
    Respects the same domain and org query parameters as the index view.
    """
    domain_filter: str = request.args.get("domain", "").strip()
    org_filter: str = request.args.get("org", "").strip()
    dest_filter: str = request.args.get("dest", "").strip()
    export_format: str = request.args.get("format", "aggregated").strip().lower()

    output = io.StringIO()
    writer = csv.writer(output)

    if export_format == "detail":
        # Per-report export (original behaviour)
        sort_col: str = request.args.get("sort", "begin_date").strip()
        sort_order: str = request.args.get("order", "desc").strip().lower()
        if sort_col not in _SORTABLE_COLUMNS:
            sort_col = "begin_date"
        if sort_order not in ("asc", "desc"):
            sort_order = "desc"
        column = _SORTABLE_COLUMNS[sort_col]
        order_clause = column.asc() if sort_order == "asc" else column.desc()

        org_id = get_current_org_id()
        query = db.select(DmarcReport).where(DmarcReport.org_id == org_id).order_by(order_clause)
        if domain_filter:
            query = query.where(DmarcReport.policy_domain == domain_filter)
        if org_filter:
            query = query.where(DmarcReport.org_name == org_filter)
        if dest_filter:
            query = query.where(DmarcReport.records_json.contains(dest_filter))

        reports = db.session.execute(query).scalars().all()

        writer.writerow([
            "Report ID", "Org Name", "Policy Domain", "Begin Date",
            "End Date", "Total Messages", "Pass", "Fail", "Source",
            "Email Subject",
        ])
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
    else:
        # Aggregated export (one row per policy_domain)
        sort_col_agg: str = request.args.get("sort", "earliest_date").strip()
        sort_order_agg: str = request.args.get("order", "desc").strip().lower()
        if sort_col_agg not in _AGG_SORTABLE_COLUMNS:
            sort_col_agg = "earliest_date"
        if sort_order_agg not in ("asc", "desc"):
            sort_order_agg = "desc"
        sort_expr = _AGG_SORTABLE_COLUMNS[sort_col_agg]
        order_clause = sort_expr.asc() if sort_order_agg == "asc" else sort_expr.desc()

        org_id = get_current_org_id()
        query = db.select(
            DmarcReport.policy_domain,
            db.func.count(DmarcReport.id).label("report_count"),
            db.func.min(DmarcReport.begin_date).label("earliest_date"),
            db.func.max(DmarcReport.end_date).label("latest_date"),
            db.func.sum(DmarcReport.total_messages).label("total_messages"),
            db.func.sum(DmarcReport.pass_count).label("pass_count"),
            db.func.sum(DmarcReport.fail_count).label("fail_count"),
        ).where(DmarcReport.org_id == org_id).group_by(DmarcReport.policy_domain)

        if domain_filter:
            query = query.where(DmarcReport.policy_domain == domain_filter)
        if org_filter:
            query = query.where(DmarcReport.org_name == org_filter)
        if dest_filter:
            query = query.where(DmarcReport.records_json.contains(dest_filter))
        query = query.order_by(order_clause)

        rows = db.session.execute(query).all()

        writer.writerow([
            "Policy Domain", "Reports", "Earliest Date", "Latest Date",
            "Total Messages", "Pass", "Fail", "Pass Rate (%)",
        ])
        for row in rows:
            total = row.total_messages or 0
            pass_rate = round(row.pass_count / total * 100, 1) if total > 0 else 0
            writer.writerow([
                row.policy_domain,
                row.report_count,
                row.earliest_date.strftime("%Y-%m-%d") if row.earliest_date else "",
                row.latest_date.strftime("%Y-%m-%d") if row.latest_date else "",
                total,
                row.pass_count or 0,
                row.fail_count or 0,
                pass_rate,
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


# ---------------------------------------------------------------------------
# Data purge
# ---------------------------------------------------------------------------

from app.models import ChangeLog, CheckResult  # noqa: E402


@bp.route("/purge", methods=["POST"])
@admin_required
def purge():
    """Delete old DMARC reports, check results, and change logs beyond retention.

    Reads ``data_retention_days`` from DnsSettings and deletes all records
    older than that threshold.  Redirects back to the settings page.
    """
    from app.utils.tenant import get_current_org_id, get_org_settings  # noqa: PLC0415
    settings = get_org_settings(get_current_org_id())
    retention_days = settings.data_retention_days if settings else 90

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    # Purge DMARC reports older than cutoff (by end_date)
    dmarc_deleted = (
        db.session.query(DmarcReport)
        .filter(DmarcReport.end_date < cutoff)
        .delete(synchronize_session=False)
    )

    # Purge check results older than cutoff
    checks_deleted = (
        db.session.query(CheckResult)
        .filter(CheckResult.checked_at < cutoff)
        .delete(synchronize_session=False)
    )

    # Purge change logs older than cutoff
    changes_deleted = (
        db.session.query(ChangeLog)
        .filter(ChangeLog.detected_at < cutoff)
        .delete(synchronize_session=False)
    )

    db.session.commit()

    total = dmarc_deleted + checks_deleted + changes_deleted
    logger.info(
        "Data purge by %s: retention=%d days, cutoff=%s, "
        "dmarc_reports=%d, check_results=%d, change_logs=%d",
        current_user.username,
        retention_days,
        cutoff.isoformat(),
        dmarc_deleted,
        checks_deleted,
        changes_deleted,
    )

    flash(
        f"Purge complete: {dmarc_deleted} DMARC report(s), "
        f"{checks_deleted} check result(s), and {changes_deleted} change log(s) "
        f"older than {retention_days} days deleted.",
        "success" if total > 0 else "info",
    )
    return redirect(url_for("settings.index"))
