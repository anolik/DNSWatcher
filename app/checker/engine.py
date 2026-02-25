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
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from app import db
from app.checker.anti_flap import apply_flap_logic
from app.checker.dkim import check_dkim
from app.checker.dmarc import check_dmarc
from app.checker.reputation import check_reputation
from app.checker.spf import check_spf
from app.models import CheckResult, DkimSelector, DnsSettings, Domain

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

    # Load DNS settings
    settings = DnsSettings.query.get(1)
    if settings is None:
        settings = DnsSettings()

    # Load active DKIM selectors for this domain
    active_selectors: list[str] = [
        s.selector
        for s in DkimSelector.query.filter_by(
            domain_id=domain.id,
            is_active=True,
        ).all()
    ]

    dns_errors: list[str] = []
    statuses: list[str] = []

    # ---- SPF check ----
    spf_result = _run_safe_check("spf", lambda: check_spf(domain.hostname, settings), dns_errors)
    spf_status_raw = spf_result.get("status", "error") if spf_result else "error"
    spf_status = apply_flap_logic(domain.id, "spf", spf_status_raw)
    statuses.append(spf_status)

    # ---- DMARC check ----
    dmarc_result = _run_safe_check("dmarc", lambda: check_dmarc(domain.hostname, settings), dns_errors)
    dmarc_status_raw = dmarc_result.get("status", "error") if dmarc_result else "error"
    dmarc_status = apply_flap_logic(domain.id, "dmarc", dmarc_status_raw)
    statuses.append(dmarc_status)

    # ---- DKIM check ----
    dkim_result = _run_safe_check(
        "dkim",
        lambda: check_dkim(domain.hostname, active_selectors, settings),
        dns_errors,
    )
    dkim_status_raw = dkim_result.get("status", "error") if dkim_result else "error"
    dkim_status = apply_flap_logic(domain.id, "dkim", dkim_status_raw)
    statuses.append(dkim_status)

    # ---- Reputation check ----
    rep_result = _run_safe_check(
        "reputation",
        lambda: check_reputation(domain.hostname, settings),
        dns_errors,
    )
    rep_status_raw = rep_result.get("status", "error") if rep_result else "error"
    rep_status = apply_flap_logic(domain.id, "reputation", rep_status_raw)
    statuses.append(rep_status)

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
    """Run DNS checks on all active domains.

    Args:
        trigger_type: How the batch was triggered ("scheduled" or "manual").

    Returns:
        A list of CheckResult instances for each domain checked.
    """
    active_domains = Domain.query.filter_by(is_active=True).all()
    results: list[CheckResult] = []

    logger.info("Starting batch check for %d active domains (trigger=%s)", len(active_domains), trigger_type)

    for domain in active_domains:
        try:
            result = run_domain_check(domain, trigger_type=trigger_type)
            results.append(result)
        except Exception as exc:
            logger.exception("Batch check failed for domain %s: %s", domain.hostname, exc)
            # Continue with remaining domains even if one fails

    logger.info("Batch check complete: %d/%d domains checked", len(results), len(active_domains))
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
