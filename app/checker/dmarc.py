"""
F11 - DMARC record validation.

Validates DMARC (Domain-based Message Authentication, Reporting and
Conformance) records for a domain:
- Queries _dmarc.{domain} TXT record
- Parses all tag=value pairs (p, sp, rua, ruf, pct, aspf, adkim, fo)
- Validates policy settings and reports warnings
- Uses checkdmarc library with fallback to manual parsing
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.checker.resolver import query_dns
from app.models import DnsSettings

logger = logging.getLogger(__name__)


def check_dmarc(domain: str, settings: DnsSettings | None = None) -> dict[str, Any]:
    """Validate the DMARC record for *domain*.

    Args:
        domain: The domain name to check.
        settings: Optional DnsSettings; loaded from DB if not provided.

    Returns:
        A dict with keys: status, record, p, sp, rua, ruf, pct, aspf,
        adkim, fo, warnings, valid.
    """
    result: dict[str, Any] = {
        "status": "ok",
        "record": None,
        "p": None,
        "sp": None,
        "rua": [],
        "ruf": [],
        "pct": None,
        "aspf": None,
        "adkim": None,
        "fo": None,
        "warnings": [],
        "valid": False,
    }

    # Try checkdmarc library first
    try:
        dmarc_result = _check_dmarc_with_checkdmarc(domain)
        if dmarc_result is not None:
            return dmarc_result
    except Exception as exc:
        logger.debug("checkdmarc DMARC failed for %s, falling back to manual: %s", domain, exc)

    # Manual parsing fallback
    return _check_dmarc_manual(domain, settings, result)


def _check_dmarc_with_checkdmarc(domain: str) -> dict[str, Any] | None:
    """Attempt DMARC validation using the checkdmarc library.

    Returns a result dict if successful, None if the library fails.
    """
    try:
        import checkdmarc.dmarc as checkdmarc_dmarc

        dmarc_data = checkdmarc_dmarc.check_dmarc(domain)
    except ImportError:
        logger.debug("checkdmarc.dmarc not available")
        return None
    except Exception as exc:
        logger.debug("checkdmarc DMARC check raised: %s", exc)
        return None

    if not isinstance(dmarc_data, dict):
        return None

    record_str = dmarc_data.get("record", "")
    if not record_str:
        return None

    # Parse the raw record for full tag extraction
    tags = _parse_dmarc_tags(record_str)
    warnings: list[str] = []

    p_value = tags.get("p")
    sp_value = tags.get("sp")
    rua_list = _extract_uris(tags.get("rua", ""))
    ruf_list = _extract_uris(tags.get("ruf", ""))
    pct_value = _parse_pct(tags.get("pct"))
    aspf_value = tags.get("aspf")
    adkim_value = tags.get("adkim")
    fo_value = tags.get("fo")

    # Determine status from policy
    status = _evaluate_policy(p_value, sp_value, rua_list, ruf_list, pct_value, warnings)

    # Include checkdmarc warnings
    for w in dmarc_data.get("warnings", []):
        warnings.append(str(w))

    return {
        "status": status,
        "record": record_str,
        "p": p_value,
        "sp": sp_value,
        "rua": rua_list,
        "ruf": ruf_list,
        "pct": pct_value,
        "aspf": aspf_value,
        "adkim": adkim_value,
        "fo": fo_value,
        "warnings": warnings,
        "valid": status != "critical",
    }


def _check_dmarc_manual(
    domain: str,
    settings: DnsSettings | None,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Manually query and parse the DMARC record for *domain*.

    Args:
        domain: The domain name to check.
        settings: Optional DnsSettings for resolver configuration.
        result: The result dict to populate.

    Returns:
        The populated result dict.
    """
    dmarc_domain = f"_dmarc.{domain}"
    dns_result = query_dns(dmarc_domain, "TXT", settings)

    if not dns_result["success"]:
        result["status"] = "critical"
        result["warnings"].append(
            f"DNS query for {dmarc_domain} failed: "
            f"{dns_result.get('error_message', 'unknown error')}"
        )
        return result

    # Filter for DMARC records
    dmarc_records: list[str] = []
    for record in dns_result["records"]:
        stripped = record.strip()
        if stripped.lower().startswith("v=dmarc1"):
            dmarc_records.append(stripped)

    if len(dmarc_records) == 0:
        result["status"] = "critical"
        result["warnings"].append("No DMARC record found")
        return result

    if len(dmarc_records) > 1:
        result["warnings"].append(
            f"Multiple DMARC records found ({len(dmarc_records)}); only one is allowed"
        )

    dmarc_record = dmarc_records[0]
    result["record"] = dmarc_record

    # Parse tag=value pairs
    tags = _parse_dmarc_tags(dmarc_record)

    # Extract all fields
    result["p"] = tags.get("p")
    result["sp"] = tags.get("sp")
    result["rua"] = _extract_uris(tags.get("rua", ""))
    result["ruf"] = _extract_uris(tags.get("ruf", ""))
    result["pct"] = _parse_pct(tags.get("pct"))
    result["aspf"] = tags.get("aspf")
    result["adkim"] = tags.get("adkim")
    result["fo"] = tags.get("fo")

    # Evaluate policy and generate warnings
    result["status"] = _evaluate_policy(
        result["p"],
        result["sp"],
        result["rua"],
        result["ruf"],
        result["pct"],
        result["warnings"],
    )

    result["valid"] = result["status"] != "critical"
    return result


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    """Parse a DMARC record string into a dict of tag=value pairs.

    Tags are separated by semicolons. Whitespace around tags and values
    is stripped. The v=DMARC1 tag is included in the output.
    """
    tags: dict[str, str] = {}
    parts = record.split(";")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
        else:
            # Some records have bare tokens; store as-is
            tags[part.lower()] = ""
    return tags


def _extract_uris(value: str) -> list[str]:
    """Extract mailto: URIs from a DMARC rua/ruf tag value.

    Values are comma-separated URIs, potentially with size limits
    (e.g., mailto:user@example.com!10m).
    """
    if not value:
        return []
    uris: list[str] = []
    for item in value.split(","):
        item = item.strip()
        if item:
            # Extract the mailto: URI, stripping any size qualifier
            match = re.match(r'(mailto:[^\s!]+)', item, re.IGNORECASE)
            if match:
                uris.append(match.group(1))
            else:
                uris.append(item)
    return uris


def _parse_pct(pct_str: str | None) -> int | None:
    """Parse the pct= tag value as an integer, returning None if invalid."""
    if pct_str is None:
        return None
    try:
        value = int(pct_str)
        if 0 <= value <= 100:
            return value
        return None
    except (ValueError, TypeError):
        return None


def _evaluate_policy(
    p_value: str | None,
    sp_value: str | None,
    rua_list: list[str],
    ruf_list: list[str],
    pct_value: int | None,
    warnings: list[str],
) -> str:
    """Evaluate DMARC policy settings and populate warnings.

    Args:
        p_value: The p= tag value.
        sp_value: The sp= tag value.
        rua_list: List of rua mailto URIs.
        ruf_list: List of ruf mailto URIs.
        pct_value: The pct= tag value.
        warnings: List to append warning messages to.

    Returns:
        A status string: "ok", "warning", or "critical".
    """
    status = "ok"

    # Validate p= (required)
    if p_value is None:
        status = "critical"
        warnings.append("DMARC policy (p=) is missing; this is a required tag")
    elif p_value.lower() == "none":
        status = "warning"
        warnings.append("DMARC policy is p=none (monitoring only); consider p=quarantine or p=reject")
    elif p_value.lower() == "quarantine":
        pass  # ok
    elif p_value.lower() == "reject":
        pass  # ok
    else:
        status = "warning"
        warnings.append(f"Unknown DMARC policy value: p={p_value}")

    # Validate sp= (defaults to p if absent)
    if sp_value is not None:
        if sp_value.lower() == "none":
            if status == "ok":
                status = "warning"
            warnings.append("Subdomain policy is sp=none; subdomains are not protected")

    # Validate rua/ruf
    if not rua_list:
        warnings.append("No rua= aggregate report URI specified; you will not receive DMARC reports")
    if ruf_list and not rua_list:
        warnings.append("ruf= (forensic reports) is set but rua= (aggregate reports) is missing")

    # Validate pct=
    if pct_value is not None and pct_value < 100:
        warnings.append(
            f"pct={pct_value} means only {pct_value}% of messages are subject to the DMARC policy"
        )
        if status == "ok":
            status = "warning"

    return status
