"""
F24 - Diff engine for detecting changes between consecutive check results.

Compares a new CheckResult against the previous one for the same domain and
creates ChangeLog entries for every detected change. Severity is classified as:

  CRITICAL : policy downgrade, key revoked, key length decrease
  WARNING  : weaker policy, key length warning, status degradation
  INFO     : text change with same policy, new record added, status improvement
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app import db
from app.models import ChangeLog, CheckResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DMARC policy strength ranking (higher = stronger)
# ---------------------------------------------------------------------------
_DMARC_POLICY_RANK: dict[str, int] = {
    "none": 0,
    "quarantine": 1,
    "reject": 2,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_changes(domain_id: int, new_result: CheckResult) -> list[ChangeLog]:
    """Compare *new_result* with the previous CheckResult for the same domain.

    Creates and adds ChangeLog entries to the current database session
    (they will be committed by the caller).

    Args:
        domain_id: The domain being checked.
        new_result: The freshly created CheckResult (already added to session).

    Returns:
        A list of ChangeLog instances that were added to the session.
        Empty list if this is the first-ever check or no changes detected.
    """
    previous = _get_previous_result(domain_id, new_result)
    if previous is None:
        logger.debug("No previous result for domain_id=%d; skipping diff.", domain_id)
        return []

    changes: list[ChangeLog] = []

    # ---- SPF comparisons ----
    changes.extend(_compare_spf(domain_id, previous, new_result))

    # ---- DMARC comparisons ----
    changes.extend(_compare_dmarc(domain_id, previous, new_result))

    # ---- DKIM comparisons ----
    changes.extend(_compare_dkim(domain_id, previous, new_result))

    # ---- Reputation comparisons ----
    changes.extend(_compare_reputation(domain_id, previous, new_result))

    # ---- MX comparisons ----
    changes.extend(_compare_mx(domain_id, previous, new_result))

    # ---- Registrar comparisons ----
    changes.extend(_compare_registrar(domain_id, previous, new_result))

    # ---- MTA-STS comparisons ----
    changes.extend(_compare_mta_sts(domain_id, previous, new_result))

    # ---- BIMI comparisons ----
    changes.extend(_compare_bimi(domain_id, previous, new_result))

    # ---- Overall status ----
    changes.extend(_compare_overall(domain_id, previous, new_result))

    for entry in changes:
        db.session.add(entry)

    if changes:
        logger.info(
            "Detected %d change(s) for domain_id=%d (critical=%d, warning=%d, info=%d)",
            len(changes),
            domain_id,
            sum(1 for c in changes if c.severity == "critical"),
            sum(1 for c in changes if c.severity == "warning"),
            sum(1 for c in changes if c.severity == "info"),
        )

    return changes


# ---------------------------------------------------------------------------
# Internal: fetch previous result
# ---------------------------------------------------------------------------


def _get_previous_result(
    domain_id: int,
    new_result: CheckResult,
) -> CheckResult | None:
    """Return the CheckResult immediately before *new_result* for the domain.

    If *new_result* already has an ``id`` we exclude it by id; otherwise we
    exclude by ``checked_at`` timestamp to avoid comparing a result with itself.
    """
    query = (
        db.select(CheckResult)
        .where(CheckResult.domain_id == domain_id)
        .order_by(CheckResult.checked_at.desc())
    )

    if new_result.id is not None:
        query = query.where(CheckResult.id != new_result.id)
    else:
        # new_result not yet flushed - fall back to timestamp exclusion
        query = query.where(CheckResult.checked_at < new_result.checked_at)

    return db.session.execute(query.limit(1)).scalars().first()


# ---------------------------------------------------------------------------
# SPF diff
# ---------------------------------------------------------------------------


def _compare_spf(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    changes: list[ChangeLog] = []

    # Record text change
    if _normalise(old.spf_record) != _normalise(new.spf_record):
        severity = _spf_record_severity(old.spf_record, new.spf_record)
        changes.append(
            _make_entry(domain_id, "spf", "spf_record", old.spf_record, new.spf_record, severity)
        )

    # Status change
    if old.spf_status != new.spf_status:
        severity = _status_change_severity(old.spf_status, new.spf_status)
        changes.append(
            _make_entry(domain_id, "spf", "spf_status", old.spf_status, new.spf_status, severity)
        )

    return changes


def _spf_record_severity(old_rec: str | None, new_rec: str | None) -> str:
    """Classify SPF record change severity based on policy mechanism."""
    old_lower = (old_rec or "").lower()
    new_lower = (new_rec or "").lower()

    # Check for hard-fail / soft-fail transitions
    old_all = _extract_spf_all(old_lower)
    new_all = _extract_spf_all(new_lower)

    if old_all and new_all:
        # Downgrade: -all -> ~all or ?all or +all
        old_strength = _SPF_ALL_RANK.get(old_all, 0)
        new_strength = _SPF_ALL_RANK.get(new_all, 0)
        if new_strength < old_strength:
            return "critical" if old_strength - new_strength >= 2 else "warning"
        if new_strength > old_strength:
            return "info"

    # Record disappeared
    if old_rec and not new_rec:
        return "critical"
    # Record appeared
    if not old_rec and new_rec:
        return "info"

    return "info"


_SPF_ALL_RANK: dict[str, int] = {
    "+all": 0,
    "?all": 1,
    "~all": 2,
    "-all": 3,
}


def _extract_spf_all(record: str) -> str | None:
    """Extract the trailing 'all' mechanism from an SPF record."""
    for token in reversed(record.split()):
        if token.endswith("all"):
            for prefix in ["-", "~", "?", "+"]:
                if token == f"{prefix}all":
                    return token
            if token == "all":
                return "+all"
    return None


# ---------------------------------------------------------------------------
# DMARC diff
# ---------------------------------------------------------------------------


def _compare_dmarc(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    changes: list[ChangeLog] = []

    # Record text change
    if _normalise(old.dmarc_record) != _normalise(new.dmarc_record):
        severity = _dmarc_record_severity(old.dmarc_record, new.dmarc_record)
        changes.append(
            _make_entry(domain_id, "dmarc", "dmarc_record", old.dmarc_record, new.dmarc_record, severity)
        )

    # Status change
    if old.dmarc_status != new.dmarc_status:
        severity = _status_change_severity(old.dmarc_status, new.dmarc_status)
        changes.append(
            _make_entry(domain_id, "dmarc", "dmarc_status", old.dmarc_status, new.dmarc_status, severity)
        )

    # Deep detail comparison (policy, pct, rua, ruf, aspf, adkim, fo, sp)
    old_details = old.get_dmarc_details()
    new_details = new.get_dmarc_details()
    changes.extend(_compare_dmarc_details(domain_id, old_details, new_details))

    return changes


def _dmarc_record_severity(old_rec: str | None, new_rec: str | None) -> str:
    """Classify DMARC record change severity based on policy transitions."""
    old_policy = _extract_dmarc_policy(old_rec)
    new_policy = _extract_dmarc_policy(new_rec)

    if old_policy and new_policy:
        old_rank = _DMARC_POLICY_RANK.get(old_policy, -1)
        new_rank = _DMARC_POLICY_RANK.get(new_policy, -1)
        if new_rank < old_rank:
            return "critical"
        if new_rank > old_rank:
            return "info"

    if old_rec and not new_rec:
        return "critical"
    if not old_rec and new_rec:
        return "info"

    return "info"


def _extract_dmarc_policy(record: str | None) -> str | None:
    """Extract the p= value from a DMARC record string."""
    if not record:
        return None
    for part in record.lower().replace(" ", "").split(";"):
        part = part.strip()
        if part.startswith("p="):
            return part[2:]
    return None


def _compare_dmarc_details(
    domain_id: int,
    old_details: dict,
    new_details: dict,
) -> list[ChangeLog]:
    """Compare parsed DMARC detail fields for granular change detection."""
    changes: list[ChangeLog] = []
    tracked_keys = ["policy", "pct", "rua", "ruf", "aspf", "adkim", "fo", "sp"]

    for key in tracked_keys:
        old_val = str(old_details.get(key, "")) if old_details.get(key) is not None else ""
        new_val = str(new_details.get(key, "")) if new_details.get(key) is not None else ""
        if old_val != new_val:
            severity = _dmarc_detail_severity(key, old_val, new_val)
            changes.append(
                _make_entry(
                    domain_id,
                    "dmarc",
                    f"dmarc_{key}",
                    old_val or None,
                    new_val or None,
                    severity,
                )
            )

    return changes


def _dmarc_detail_severity(key: str, old_val: str, new_val: str) -> str:
    """Severity for individual DMARC detail field changes."""
    if key == "policy":
        old_rank = _DMARC_POLICY_RANK.get(old_val, -1)
        new_rank = _DMARC_POLICY_RANK.get(new_val, -1)
        if new_rank < old_rank:
            return "critical"
        return "info"
    if key == "sp":
        old_rank = _DMARC_POLICY_RANK.get(old_val, -1)
        new_rank = _DMARC_POLICY_RANK.get(new_val, -1)
        if new_rank < old_rank:
            return "warning"
        return "info"
    if key in ("aspf", "adkim"):
        # Relaxed (r) to strict (s) = info; strict to relaxed = warning
        if old_val == "s" and new_val == "r":
            return "warning"
        return "info"
    return "info"


# ---------------------------------------------------------------------------
# DKIM diff
# ---------------------------------------------------------------------------


def _compare_dkim(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    changes: list[ChangeLog] = []

    # Status change
    if old.dkim_status != new.dkim_status:
        severity = _status_change_severity(old.dkim_status, new.dkim_status)
        changes.append(
            _make_entry(domain_id, "dkim", "dkim_status", old.dkim_status, new.dkim_status, severity)
        )

    # Deep key comparison
    old_records = old.get_dkim_records()
    new_records = new.get_dkim_records()
    changes.extend(_compare_dkim_records(domain_id, old_records, new_records))

    return changes


def _compare_dkim_records(
    domain_id: int,
    old_records: list,
    new_records: list,
) -> list[ChangeLog]:
    """Compare DKIM key records for additions, removals, and key changes."""
    changes: list[ChangeLog] = []

    old_by_selector = {r.get("selector", ""): r for r in old_records if isinstance(r, dict)}
    new_by_selector = {r.get("selector", ""): r for r in new_records if isinstance(r, dict)}

    all_selectors = set(old_by_selector.keys()) | set(new_by_selector.keys())

    for selector in sorted(all_selectors):
        old_rec = old_by_selector.get(selector)
        new_rec = new_by_selector.get(selector)

        if old_rec and not new_rec:
            # Key removed / revoked
            changes.append(
                _make_entry(
                    domain_id,
                    "dkim",
                    f"dkim_key_{selector}",
                    json.dumps(old_rec, default=str),
                    None,
                    "critical",
                )
            )
        elif not old_rec and new_rec:
            # New key added
            changes.append(
                _make_entry(
                    domain_id,
                    "dkim",
                    f"dkim_key_{selector}",
                    None,
                    json.dumps(new_rec, default=str),
                    "info",
                )
            )
        elif old_rec and new_rec:
            # Key might have changed
            old_key_len = old_rec.get("key_length", 0)
            new_key_len = new_rec.get("key_length", 0)

            if old_key_len and new_key_len and new_key_len < old_key_len:
                # Key length decreased
                changes.append(
                    _make_entry(
                        domain_id,
                        "dkim",
                        f"dkim_key_length_{selector}",
                        str(old_key_len),
                        str(new_key_len),
                        "critical",
                    )
                )
            elif old_rec.get("public_key") != new_rec.get("public_key"):
                # Key changed but length same or increased
                severity = "info"
                if new_key_len and new_key_len < 1024:
                    severity = "warning"
                changes.append(
                    _make_entry(
                        domain_id,
                        "dkim",
                        f"dkim_key_{selector}",
                        str(old_key_len) if old_key_len else "unknown",
                        str(new_key_len) if new_key_len else "unknown",
                        severity,
                    )
                )

    return changes


# ---------------------------------------------------------------------------
# Reputation diff
# ---------------------------------------------------------------------------


def _compare_reputation(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    changes: list[ChangeLog] = []

    if old.reputation_status != new.reputation_status:
        severity = _status_change_severity(old.reputation_status, new.reputation_status)
        changes.append(
            _make_entry(
                domain_id,
                "reputation",
                "reputation_status",
                old.reputation_status,
                new.reputation_status,
                severity,
            )
        )

    # Compare blocklist changes in reputation details
    old_details = old.get_reputation_details()
    new_details = new.get_reputation_details()

    old_listed = set(old_details.get("listed_on", []) or [])
    new_listed = set(new_details.get("listed_on", []) or [])

    newly_listed = new_listed - old_listed
    delisted = old_listed - new_listed

    if newly_listed:
        changes.append(
            _make_entry(
                domain_id,
                "reputation",
                "blocklist_added",
                None,
                ", ".join(sorted(newly_listed)),
                "critical",
            )
        )
    if delisted:
        changes.append(
            _make_entry(
                domain_id,
                "reputation",
                "blocklist_removed",
                ", ".join(sorted(delisted)),
                None,
                "info",
            )
        )

    return changes


# ---------------------------------------------------------------------------
# MX diff
# ---------------------------------------------------------------------------


def _compare_mx(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    changes: list[ChangeLog] = []

    # MX provider change
    old_provider = old.mx_provider or ""
    new_provider = new.mx_provider or ""
    if old_provider != new_provider and (old_provider or new_provider):
        changes.append(
            _make_entry(
                domain_id,
                "mx",
                "mx_provider",
                old_provider or None,
                new_provider or None,
                "info",
            )
        )

    return changes


# ---------------------------------------------------------------------------
# Registrar diff
# ---------------------------------------------------------------------------


def _compare_registrar(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    changes: list[ChangeLog] = []

    old_registrar = old.registrar or ""
    new_registrar = new.registrar or ""
    if old_registrar != new_registrar and (old_registrar or new_registrar):
        changes.append(
            _make_entry(
                domain_id,
                "registrar",
                "registrar_name",
                old_registrar or None,
                new_registrar or None,
                "info",
            )
        )

    return changes


# ---------------------------------------------------------------------------
# MTA-STS diff
# ---------------------------------------------------------------------------


def _compare_mta_sts(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    changes: list[ChangeLog] = []

    old_status = old.mta_sts_status or ""
    new_status = new.mta_sts_status or ""

    if old_status != new_status and (old_status or new_status):
        severity = _status_change_severity(old.mta_sts_status, new.mta_sts_status)
        changes.append(
            _make_entry(
                domain_id,
                "mta_sts",
                "mta_sts_status",
                old.mta_sts_status,
                new.mta_sts_status,
                severity,
            )
        )

    # Detect policy_mode changes (enforce → testing is a degradation)
    old_details = old.get_mta_sts_details() if hasattr(old, "get_mta_sts_details") else {}
    new_details = new.get_mta_sts_details() if hasattr(new, "get_mta_sts_details") else {}
    old_mode = old_details.get("policy_mode") or ""
    new_mode = new_details.get("policy_mode") or ""

    if old_mode != new_mode and (old_mode or new_mode):
        _MODE_RANK = {"enforce": 2, "testing": 1, "none": 0}
        old_rank = _MODE_RANK.get(old_mode, -1)
        new_rank = _MODE_RANK.get(new_mode, -1)
        severity = "warning" if new_rank < old_rank else "info"
        changes.append(
            _make_entry(
                domain_id,
                "mta_sts",
                "mta_sts_policy_mode",
                old_mode or None,
                new_mode or None,
                severity,
            )
        )

    return changes


# ---------------------------------------------------------------------------
# BIMI diff
# ---------------------------------------------------------------------------


def _compare_bimi(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    changes: list[ChangeLog] = []

    old_status = old.bimi_status or ""
    new_status = new.bimi_status or ""

    if old_status != new_status and (old_status or new_status):
        # Record added or removed
        if not old_status and new_status:
            severity = "info"  # BIMI appeared
        elif old_status and not new_status:
            severity = "info"  # BIMI disappeared
        else:
            severity = _status_change_severity(old.bimi_status, new.bimi_status)

        changes.append(
            _make_entry(
                domain_id,
                "bimi",
                "bimi_status",
                old.bimi_status,
                new.bimi_status,
                severity,
            )
        )

    # Detect record text changes
    if _normalise(old.bimi_record) != _normalise(new.bimi_record):
        if old.bimi_record and new.bimi_record:
            severity = "info"
        elif not old.bimi_record and new.bimi_record:
            severity = "info"
        else:
            severity = "info"
        changes.append(
            _make_entry(
                domain_id,
                "bimi",
                "bimi_record",
                old.bimi_record,
                new.bimi_record,
                severity,
            )
        )

    return changes


# ---------------------------------------------------------------------------
# Overall status diff
# ---------------------------------------------------------------------------


def _compare_overall(
    domain_id: int,
    old: CheckResult,
    new: CheckResult,
) -> list[ChangeLog]:
    if old.overall_status == new.overall_status:
        return []

    severity = _status_change_severity(old.overall_status, new.overall_status)
    return [
        _make_entry(
            domain_id,
            "overall",
            "overall_status",
            old.overall_status,
            new.overall_status,
            severity,
        )
    ]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_STATUS_SEVERITY_RANK: dict[str, int] = {
    "ok": 0,
    "info": 1,
    "warning": 2,
    "critical": 3,
    "error": 4,
}


def _status_change_severity(old_status: str | None, new_status: str | None) -> str:
    """Classify severity when a status field changes value.

    Degradation (higher severity rank) -> warning or critical.
    Improvement (lower severity rank)  -> info.
    """
    old_rank = _STATUS_SEVERITY_RANK.get(old_status or "", 0)
    new_rank = _STATUS_SEVERITY_RANK.get(new_status or "", 0)

    if new_rank > old_rank:
        # Status got worse
        return "critical" if new_rank >= 3 else "warning"
    return "info"


def _normalise(value: str | None) -> str:
    """Normalise a DNS record string for comparison."""
    if not value:
        return ""
    return " ".join(value.lower().split())


def _make_entry(
    domain_id: int,
    check_type: str,
    field_changed: str,
    old_value: str | None,
    new_value: str | None,
    severity: str,
) -> ChangeLog:
    """Create a ChangeLog entry (not yet added to session)."""
    return ChangeLog(
        domain_id=domain_id,
        check_type=check_type,
        field_changed=field_changed,
        old_value=_truncate(old_value, 2000),
        new_value=_truncate(new_value, 2000),
        severity=severity,
    )


def _truncate(value: str | None, max_len: int) -> str | None:
    """Truncate a string value to *max_len* characters."""
    if value is None:
        return None
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."
