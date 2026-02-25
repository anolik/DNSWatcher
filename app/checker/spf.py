"""
F10 - SPF record validation.

Validates SPF (Sender Policy Framework) records for a domain:
- Presence and uniqueness of the v=spf1 record
- Mechanism parsing (ip4, ip6, include, a, mx, ptr, exists, redirect, all)
- DNS lookup count enforcement (max 10 per RFC 7208)
- Policy qualifier detection (-all, ~all, ?all, +all)
- Uses checkdmarc library with fallback to manual parsing
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.checker.resolver import query_dns
from app.models import DnsSettings

logger = logging.getLogger(__name__)

# Mechanisms that require DNS lookups per RFC 7208 Section 4.6.4
_DNS_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}

# Qualifier mapping for the "all" mechanism
_ALL_QUALIFIERS: dict[str, tuple[str, str]] = {
    "-all": ("hard_fail", "ok"),
    "~all": ("soft_fail", "warning"),
    "?all": ("neutral", "warning"),
    "+all": ("pass_all", "critical"),
}


def check_spf(domain: str, settings: DnsSettings | None = None) -> dict[str, Any]:
    """Validate the SPF record for *domain*.

    Args:
        domain: The domain name to check.
        settings: Optional DnsSettings; loaded from DB if not provided.

    Returns:
        A dict with keys: status, record, policy, mechanisms, lookup_count,
        warnings, valid.
    """
    result: dict[str, Any] = {
        "status": "ok",
        "record": None,
        "policy": None,
        "mechanisms": [],
        "lookup_count": 0,
        "warnings": [],
        "valid": False,
    }

    # Try checkdmarc library first
    try:
        spf_result = _check_spf_with_checkdmarc(domain)
        if spf_result is not None:
            return spf_result
    except Exception as exc:
        logger.debug("checkdmarc SPF failed for %s, falling back to manual: %s", domain, exc)

    # Manual parsing fallback
    return _check_spf_manual(domain, settings, result)


def _check_spf_with_checkdmarc(domain: str) -> dict[str, Any] | None:
    """Attempt SPF validation using the checkdmarc library.

    Returns a result dict if successful, None if the library fails.
    """
    try:
        import checkdmarc.spf as checkdmarc_spf

        spf_data = checkdmarc_spf.check_spf(domain)
    except ImportError:
        logger.debug("checkdmarc.spf not available")
        return None
    except Exception as exc:
        logger.debug("checkdmarc SPF check raised: %s", exc)
        return None

    if not isinstance(spf_data, dict):
        return None

    record_str = spf_data.get("record", "")
    if not record_str:
        return None

    warnings: list[str] = []
    parsed = spf_data.get("parsed", {})
    all_val = parsed.get("all", "")

    # Determine policy from checkdmarc output
    policy: str | None = None
    status = "ok"
    if all_val == "fail":
        policy = "hard_fail"
        status = "ok"
    elif all_val == "softfail":
        policy = "soft_fail"
        status = "warning"
    elif all_val == "neutral":
        policy = "neutral"
        status = "warning"
    elif all_val == "pass":
        policy = "pass_all"
        status = "critical"
        warnings.append("SPF uses +all which allows any sender")
    else:
        policy = _extract_policy_from_record(record_str)
        status = _status_for_policy(policy)
        if policy == "missing":
            warnings.append("No 'all' mechanism found in SPF record")
        if policy == "pass_all":
            warnings.append("SPF uses +all which allows any sender")

    # Extract mechanism list and count DNS lookups
    mechanisms = _parse_mechanisms(record_str)
    lookup_count = sum(1 for m in mechanisms if m.get("type") in _DNS_LOOKUP_MECHANISMS)

    if lookup_count > 10:
        warnings.append(f"SPF exceeds 10 DNS lookup limit ({lookup_count} lookups)")
        if status == "ok":
            status = "warning"

    for w in spf_data.get("warnings", []):
        warnings.append(str(w))

    return {
        "status": status,
        "record": record_str,
        "policy": policy,
        "mechanisms": mechanisms,
        "lookup_count": lookup_count,
        "warnings": warnings,
        "valid": status != "critical",
    }


def _check_spf_manual(
    domain: str,
    settings: DnsSettings | None,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Manually parse and validate SPF records via DNS TXT queries.

    Args:
        domain: The domain name to check.
        settings: Optional DnsSettings for resolver configuration.
        result: The result dict to populate.

    Returns:
        The populated result dict.
    """
    dns_result = query_dns(domain, "TXT", settings)

    if not dns_result["success"]:
        result["status"] = "critical"
        result["warnings"].append(
            f"DNS query failed: {dns_result.get('error_message', 'unknown error')}"
        )
        return result

    # Filter for SPF records
    spf_records: list[str] = []
    for record in dns_result["records"]:
        stripped = record.strip()
        if stripped.lower().startswith("v=spf1"):
            spf_records.append(stripped)

    # Validate record count
    if len(spf_records) == 0:
        result["status"] = "critical"
        result["warnings"].append("No SPF record found")
        return result

    if len(spf_records) > 1:
        result["status"] = "critical"
        result["warnings"].append(
            f"Multiple SPF records found ({len(spf_records)}); RFC 7208 requires exactly one"
        )
        # Analyze the first record anyway for informational purposes
        # but mark as invalid

    spf_record = spf_records[0]
    result["record"] = spf_record

    # Parse mechanisms
    mechanisms = _parse_mechanisms(spf_record)
    result["mechanisms"] = mechanisms

    # Count DNS lookups
    lookup_count = sum(1 for m in mechanisms if m.get("type") in _DNS_LOOKUP_MECHANISMS)
    result["lookup_count"] = lookup_count

    if lookup_count > 10:
        result["warnings"].append(
            f"SPF exceeds 10 DNS lookup limit ({lookup_count} lookups)"
        )

    # Determine policy from "all" mechanism
    policy = _extract_policy_from_record(spf_record)
    result["policy"] = policy
    policy_status = _status_for_policy(policy)

    if policy == "missing":
        result["warnings"].append("No 'all' mechanism found in SPF record")
    elif policy == "pass_all":
        result["warnings"].append("SPF uses +all which allows any sender")
    elif policy == "soft_fail":
        result["warnings"].append("SPF uses ~all (soft fail); consider upgrading to -all (hard fail)")
    elif policy == "neutral":
        result["warnings"].append("SPF uses ?all (neutral); this provides no protection")

    # Set overall status: worst of existing status and policy status
    result["status"] = _worst_status(result["status"], policy_status)

    # If multiple records were found, override to critical
    if len(spf_records) > 1:
        result["status"] = "critical"

    # If lookup count exceeded, ensure at least warning
    if lookup_count > 10 and result["status"] == "ok":
        result["status"] = "warning"

    result["valid"] = result["status"] != "critical"
    return result


def _parse_mechanisms(spf_record: str) -> list[dict[str, str]]:
    """Parse an SPF record string into a list of mechanism dicts.

    Each mechanism dict has keys: qualifier, type, value.
    """
    mechanisms: list[dict[str, str]] = []
    # Remove the v=spf1 prefix
    parts = spf_record.strip().split()
    if parts and parts[0].lower().startswith("v=spf1"):
        parts = parts[1:]

    for part in parts:
        part = part.strip()
        if not part:
            continue

        # Extract qualifier
        qualifier = "+"
        if part[0] in "+-~?":
            qualifier = part[0]
            part = part[1:]

        # Determine mechanism type and value
        mech_type = ""
        value = ""

        if "=" in part:
            # redirect=, exp=
            key, _, val = part.partition("=")
            mech_type = key.lower()
            value = val
        elif ":" in part:
            # include:domain, ip4:range, a:domain, mx:domain
            key, _, val = part.partition(":")
            mech_type = key.lower()
            value = val
        elif "/" in part:
            # a/24, mx/24
            key, _, val = part.partition("/")
            mech_type = key.lower()
            value = f"/{val}"
        else:
            mech_type = part.lower()
            value = ""

        mechanisms.append({
            "qualifier": qualifier,
            "type": mech_type,
            "value": value,
        })

    return mechanisms


def _extract_policy_from_record(spf_record: str) -> str:
    """Determine the SPF policy from the 'all' mechanism qualifier.

    Returns one of: hard_fail, soft_fail, neutral, pass_all, missing.
    """
    # Find the "all" mechanism (should be last, but search all parts)
    parts = spf_record.strip().split()
    for part in reversed(parts):
        part_stripped = part.strip().lower()
        # Match patterns like -all, ~all, ?all, +all, all
        match = re.match(r'^([+\-~?])?all$', part_stripped)
        if match:
            qualifier = match.group(1) or "+"
            qualifier_all = f"{qualifier}all"
            if qualifier_all in _ALL_QUALIFIERS:
                return _ALL_QUALIFIERS[qualifier_all][0]
            return "pass_all"

    return "missing"


def _status_for_policy(policy: str) -> str:
    """Map an SPF policy string to a status level."""
    policy_status_map: dict[str, str] = {
        "hard_fail": "ok",
        "soft_fail": "warning",
        "neutral": "warning",
        "pass_all": "critical",
        "missing": "critical",
    }
    return policy_status_map.get(policy, "warning")


def _worst_status(status_a: str, status_b: str) -> str:
    """Return the worse of two status values.

    Severity order: ok < warning < critical < error.
    """
    severity = {"ok": 0, "warning": 1, "critical": 2, "error": 3}
    if severity.get(status_a, 0) >= severity.get(status_b, 0):
        return status_a
    return status_b
