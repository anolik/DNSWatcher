"""
F14 - Check orchestration engine.

Coordinates the execution of all DNS checks (SPF, DMARC, DKIM, reputation)
for a single domain or all active domains. Handles:
- Loading settings and DKIM selectors
- Running each check with individual error isolation
- Computing overall status (worst across all checks)
- Applying anti-flap logic per check type
- Persisting CheckResult to the database
- Updating Domain status fields
- Measuring execution time
- Concurrent batch checking via ThreadPoolExecutor
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from app import db
from app.checker.anti_flap import apply_flap_logic
from app.checker.bimi import check_bimi
from app.checker.dkim import check_dkim
from app.checker.dmarc import check_dmarc
from app.checker.geolocation import check_geolocation
from app.checker.mta_sts import check_mta_sts
from app.checker.mx import PROVIDER_DKIM_SELECTORS, check_mx
from app.checker.registrar import check_registrar
from app.checker.reputation import check_reputation
from app.checker.spf import check_spf
from app.checker.tls import check_tls
from app.models import CheckResult, DkimSelector, DnsSettings, Domain
from app.utils.tenant import get_org_settings

logger = logging.getLogger(__name__)

# Status severity ranking (higher = worse)
_STATUS_SEVERITY: dict[str, int] = {
    "ok": 0,
    "info": 1,
    "warning": 2,
    "critical": 3,
    "error": 4,
}


def run_domain_check(
    domain: Domain,
    trigger_type: str = "manual",
) -> CheckResult:
    """Run all DNS checks for a single *domain* and persist the results.

    Args:
        domain: The Domain model instance to check.
        trigger_type: How the check was triggered ("manual" or "scheduled").

    Returns:
        The created CheckResult instance (already committed to the database).
    """
    start_time = time.monotonic()
    now = datetime.now(timezone.utc)

    # Load DNS settings (per-org with global fallback)
    settings = get_org_settings(domain.org_id)

    dns_errors: list[str] = []
    statuses: list[str] = []

    # ---- SPF check ----
    spf_result = None
    spf_status = None
    if settings.check_spf_enabled:
        spf_result = _run_safe_check("spf", lambda: check_spf(domain.hostname, settings), dns_errors)
        spf_status_raw = spf_result.get("status", "error") if spf_result else "error"
        spf_status = apply_flap_logic(domain.id, "spf", spf_status_raw, settings=settings)
        statuses.append(spf_status)

    # ---- DMARC check ----
    dmarc_result = None
    dmarc_status = None
    if settings.check_dmarc_enabled:
        dmarc_result = _run_safe_check("dmarc", lambda: check_dmarc(domain.hostname, settings), dns_errors)
        dmarc_status_raw = dmarc_result.get("status", "error") if dmarc_result else "error"
        dmarc_status = apply_flap_logic(domain.id, "dmarc", dmarc_status_raw, settings=settings)
        statuses.append(dmarc_status)

    # ---- MX check (run BEFORE DKIM to identify provider) ----
    mx_result = None
    if settings.check_mx_enabled:
        mx_result = _run_safe_check(
            "mx",
            lambda: check_mx(domain.hostname, settings),
            dns_errors,
        )

    # ---- Sync DKIM selectors based on MX provider ----
    mx_provider = mx_result.get("provider") if mx_result else None
    active_selectors = _sync_dkim_selectors(domain, mx_provider)

    # ---- DKIM check (uses provider-aware selectors) ----
    dkim_result = None
    dkim_status = None
    if settings.check_dkim_enabled:
        dkim_result = _run_safe_check(
            "dkim",
            lambda: check_dkim(domain.hostname, active_selectors, settings),
            dns_errors,
        )
        dkim_status_raw = dkim_result.get("status", "error") if dkim_result else "error"
        dkim_status = apply_flap_logic(domain.id, "dkim", dkim_status_raw, settings=settings)
        statuses.append(dkim_status)

    # ---- Reputation check ----
    rep_result = None
    rep_status = None
    if settings.check_reputation_enabled:
        rep_result = _run_safe_check(
            "reputation",
            lambda: check_reputation(domain.hostname, settings),
            dns_errors,
        )
        rep_status_raw = rep_result.get("status", "error") if rep_result else "error"
        rep_status = apply_flap_logic(domain.id, "reputation", rep_status_raw, settings=settings)
        statuses.append(rep_status)

    # ---- Registrar check (informational, does NOT affect overall status) ----
    registrar_result = None
    if settings.check_registrar_enabled:
        registrar_result = _run_safe_check(
            "registrar",
            lambda: check_registrar(domain.hostname),
            dns_errors,
        )

    # ---- Geolocation check (informational, depends on MX results) ----
    geo_result = None
    if settings.check_geolocation_enabled and mx_result and mx_result.get("records"):
        geo_result = _run_safe_check(
            "geolocation",
            lambda: check_geolocation(mx_result["records"], settings),
            dns_errors,
        )

    # ---- MTA-STS check (informational, does NOT affect overall status) ----
    mta_sts_result = None
    if settings.check_mta_sts_enabled:
        mta_sts_result = _run_safe_check(
            "mta_sts",
            lambda: check_mta_sts(domain.hostname, settings),
            dns_errors,
        )

    # ---- BIMI check (informational, does NOT affect overall status) ----
    bimi_result = None
    if settings.check_bimi_enabled:
        bimi_result = _run_safe_check(
            "bimi",
            lambda: check_bimi(domain.hostname, settings),
            dns_errors,
        )

    # ---- TLS check (informational, depends on MX results) ----
    tls_result = None
    if settings.check_tls_enabled and mx_result and mx_result.get("records"):
        tls_result = _run_safe_check(
            "tls",
            lambda: check_tls(mx_result["records"], settings),
            dns_errors,
        )

    # ---- Compute overall status ----
    overall_status = _worst_of_statuses(statuses)

    # ---- Measure execution time ----
    elapsed_ms = int((time.monotonic() - start_time) * 1000)

    # ---- Create CheckResult ----
    check_result = CheckResult(
        domain_id=domain.id,
        checked_at=now,
        trigger_type=trigger_type,
        overall_status=overall_status,
        spf_status=spf_status,
        spf_record=spf_result.get("record") if spf_result else None,
        spf_details=_to_json(spf_result),
        dmarc_status=dmarc_status,
        dmarc_record=dmarc_result.get("record") if dmarc_result else None,
        dmarc_details=_to_json(dmarc_result),
        dkim_status=dkim_status,
        dkim_records=_to_json(dkim_result.get("results") if dkim_result else None),
        reputation_status=rep_status,
        reputation_details=_to_json(rep_result),
        mx_records=_to_json(mx_result.get("records") if mx_result else None),
        mx_provider=mx_result.get("provider") if mx_result else None,
        registrar=registrar_result.get("registrar") if registrar_result else None,
        registrar_details=_to_json(registrar_result),
        mx_geolocation=_to_json(geo_result.get("servers") if geo_result else None),
        law25_status=geo_result.get("law25_status") if geo_result else None,
        mta_sts_status=mta_sts_result.get("status") if mta_sts_result else None,
        mta_sts_record=mta_sts_result.get("record") if mta_sts_result else None,
        mta_sts_details=_to_json(mta_sts_result),
        bimi_status=bimi_result.get("status") if bimi_result else None,
        bimi_record=bimi_result.get("record") if bimi_result else None,
        bimi_details=_to_json(bimi_result),
        tls_status=tls_result.get("status") if tls_result else None,
        tls_details=_to_json(tls_result),
        dns_errors=_to_json(dns_errors) if dns_errors else None,
        execution_time_ms=elapsed_ms,
    )
    db.session.add(check_result)

    # ---- Detect changes ----
    from app.checker.diff_engine import detect_changes

    detect_changes(domain.id, check_result)

    # ---- Update Domain fields ----
    domain.last_checked_at = now
    domain.current_status = overall_status
    if overall_status == "ok":
        domain.last_ok_at = now

    # ---- Commit everything ----
    try:
        db.session.commit()
        logger.info(
            "Check completed for %s: overall_status=%s, elapsed=%dms",
            domain.hostname,
            overall_status,
            elapsed_ms,
        )
    except Exception as exc:
        logger.exception("Failed to commit check result for %s", domain.hostname)
        db.session.rollback()
        raise

    return check_result


def run_all_checks(trigger_type: str = "scheduled") -> list[CheckResult]:
    """Run DNS checks on all active domains, optionally in parallel.

    Reads the ``check_concurrency`` setting from DnsSettings to decide how
    many domains to check simultaneously.  When concurrency is 1, domains
    are checked sequentially (same behaviour as before).

    Args:
        trigger_type: How the batch was triggered (``"scheduled"`` or ``"manual"``).

    Returns:
        A list of CheckResult instances for each domain checked.
    """
    active_domains = Domain.query.filter_by(is_active=True).all()
    total = len(active_domains)

    # Read concurrency from global settings (default 5).
    # Per-org concurrency is read inside run_domain_check for each domain,
    # but the thread pool size is based on the global default.
    global_settings = get_org_settings(None)
    max_workers = global_settings.check_concurrency if global_settings else 5
    max_workers = max(1, min(max_workers, 10))  # clamp 1..10

    logger.info(
        "Starting batch check for %d active domains (trigger=%s, concurrency=%d)",
        total, trigger_type, max_workers,
    )

    if max_workers == 1 or total <= 1:
        # Sequential path (no threading overhead)
        return _run_all_sequential(active_domains, trigger_type)

    return _run_all_concurrent(active_domains, trigger_type, max_workers)


def _run_all_sequential(
    domains: list[Domain],
    trigger_type: str,
) -> list[CheckResult]:
    """Check domains one at a time."""
    results: list[CheckResult] = []
    for domain in domains:
        try:
            result = run_domain_check(domain, trigger_type=trigger_type)
            results.append(result)
        except Exception as exc:
            logger.exception("Batch check failed for domain %s: %s", domain.hostname, exc)
    logger.info("Batch check complete: %d/%d domains checked", len(results), len(domains))
    return results


def _run_all_concurrent(
    domains: list[Domain],
    trigger_type: str,
    max_workers: int,
) -> list[CheckResult]:
    """Check domains in parallel using a thread pool.

    Each worker runs inside its own Flask application context so that
    database sessions are properly scoped per thread.  SQLite WAL mode
    and a 30-second busy timeout (configured in config.py / __init__.py)
    allow concurrent readers with serialised writes.  Workers that hit a
    transient ``database is locked`` error retry up to 2 times.
    """
    import sqlite3

    from flask import current_app
    from sqlalchemy.exc import OperationalError

    app = current_app._get_current_object()  # real app, not proxy
    domain_ids = [d.id for d in domains]
    results: list[CheckResult] = []
    failed = 0

    def _check_one(domain_id: int) -> CheckResult | None:
        """Worker function executed in a thread, with retry on DB lock."""
        max_retries = 2
        for attempt in range(max_retries + 1):
            with app.app_context():
                try:
                    domain = db.session.get(Domain, domain_id)
                    if domain is None or not domain.is_active:
                        return None
                    return run_domain_check(domain, trigger_type=trigger_type)
                except OperationalError as exc:
                    # Retry on transient SQLite lock errors
                    if "database is locked" in str(exc) and attempt < max_retries:
                        wait = 1.0 * (attempt + 1)
                        logger.warning(
                            "Database locked for domain_id %d, retrying in %.0fs (attempt %d/%d)",
                            domain_id, wait, attempt + 1, max_retries,
                        )
                        db.session.rollback()
                        time.sleep(wait)
                        continue
                    logger.exception("Batch check failed for domain_id %d: %s", domain_id, exc)
                    return None
                except Exception as exc:
                    logger.exception("Batch check failed for domain_id %d: %s", domain_id, exc)
                    return None
        return None  # all retries exhausted

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_id = {
            executor.submit(_check_one, did): did for did in domain_ids
        }
        for future in as_completed(future_to_id):
            result = future.result()
            if result is not None:
                results.append(result)
            else:
                failed += 1

    logger.info(
        "Batch check complete: %d/%d domains checked (%d failed, concurrency=%d)",
        len(results), len(domains), failed, max_workers,
    )
    return results


def _run_safe_check(
    check_name: str,
    check_fn: Any,
    dns_errors: list[str],
) -> dict[str, Any] | None:
    """Execute a check function with error isolation.

    If the check raises an exception, it is caught and logged, an error
    entry is appended to *dns_errors*, and None is returned.

    Args:
        check_name: Human-readable name for logging (e.g., "spf").
        check_fn: A callable that returns a check result dict.
        dns_errors: List to append error messages to.

    Returns:
        The check result dict, or None if the check raised an exception.
    """
    try:
        return check_fn()
    except Exception as exc:
        error_msg = f"{check_name} check failed: {exc}"
        logger.exception("Error in %s check", check_name)
        dns_errors.append(error_msg)
        return None


def _worst_of_statuses(statuses: list[str]) -> str:
    """Return the worst status from a list of status strings.

    Severity order: ok < info < warning < critical < error.
    Returns "error" if the list is empty.
    """
    if not statuses:
        return "error"

    worst = "ok"
    worst_severity = 0

    for status in statuses:
        severity = _STATUS_SEVERITY.get(status, 0)
        if severity > worst_severity:
            worst_severity = severity
            worst = status

    return worst


def _sync_dkim_selectors(domain: Domain, mx_provider: str | None) -> list[str]:
    """Return the DKIM selectors to check, syncing DB rows when the MX provider is known.

    When the MX provider is recognised and has a known selector list:
    1. Ensure those selectors exist as active DkimSelector rows for the domain.
    2. Return the provider-specific selectors for the DKIM check.

    When the provider is unknown, fall back to whatever active selectors are
    already configured for the domain in the database.

    Args:
        domain: The Domain being checked.
        mx_provider: The MX provider name from check_mx(), or None.

    Returns:
        A list of selector strings to pass to check_dkim().
    """
    provider_selectors = (
        PROVIDER_DKIM_SELECTORS.get(mx_provider) if mx_provider else None
    )

    if provider_selectors:
        # Ensure each provider selector exists as an active row
        existing = {
            s.selector: s
            for s in DkimSelector.query.filter_by(domain_id=domain.id).all()
        }

        for sel_name in provider_selectors:
            if sel_name in existing:
                # Re-activate if it was disabled
                if not existing[sel_name].is_active:
                    existing[sel_name].is_active = True
            else:
                db.session.add(
                    DkimSelector(domain_id=domain.id, selector=sel_name, is_active=True)
                )

        db.session.flush()

        logger.info(
            "DKIM selectors for %s set from MX provider %s: %s",
            domain.hostname,
            mx_provider,
            provider_selectors,
        )
        return list(provider_selectors)

    # Fallback: use manually-configured active selectors
    active_selectors: list[str] = [
        s.selector
        for s in DkimSelector.query.filter_by(
            domain_id=domain.id,
            is_active=True,
        ).all()
    ]
    return active_selectors


def _to_json(data: Any) -> str | None:
    """Serialise *data* to a JSON string.

    Returns None if *data* is None or serialisation fails.
    """
    if data is None:
        return None
    try:
        return json.dumps(data, default=str, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        logger.warning("JSON serialisation failed: %s", exc)
        return None
