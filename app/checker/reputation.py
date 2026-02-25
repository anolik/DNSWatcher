"""
F13 - Domain reputation checking via DNSBL (DNS-based Blocklists).

Checks whether a domain is listed on common URI-based blocklists:
- dbl.spamhaus.org (Spamhaus Domain Block List)
- multi.uribl.com (URIBL multi list)
- multi.surbl.org (SURBL multi list)

A domain is queried by resolving {domain}.{dnsbl} as an A record.
A successful resolution means the domain is listed (blocklisted).
"""

from __future__ import annotations

import logging
from typing import Any

from app.checker.resolver import query_dns
from app.models import DnsSettings

logger = logging.getLogger(__name__)

# URI-based DNS blocklists to check
_DNSBL_LIST: list[str] = [
    "dbl.spamhaus.org",
    "multi.uribl.com",
    "multi.surbl.org",
]


def check_reputation(
    domain: str,
    settings: DnsSettings | None = None,
) -> dict[str, Any]:
    """Check *domain* against known DNS blocklists.

    Args:
        domain: The domain name to check.
        settings: Optional DnsSettings; loaded from DB if not provided.

    Returns:
        A dict with keys: status, listed_on, clean_on, errors.
    """
    result: dict[str, Any] = {
        "status": "ok",
        "listed_on": [],
        "clean_on": [],
        "errors": [],
    }

    for dnsbl in _DNSBL_LIST:
        check_result = _check_single_dnsbl(domain, dnsbl, settings)

        if check_result["listed"]:
            result["listed_on"].append(dnsbl)
        elif check_result["clean"]:
            result["clean_on"].append(dnsbl)
        elif check_result["error"]:
            result["errors"].append(
                f"{dnsbl}: {check_result.get('error_message', 'unknown error')}"
            )

    # Determine overall status
    if result["listed_on"]:
        result["status"] = "warning"
    else:
        result["status"] = "ok"

    logger.info(
        "Reputation check for %s: listed_on=%s, clean_on=%s, errors=%d",
        domain,
        result["listed_on"],
        result["clean_on"],
        len(result["errors"]),
    )

    return result


def _check_single_dnsbl(
    domain: str,
    dnsbl: str,
    settings: DnsSettings | None,
) -> dict[str, Any]:
    """Check a single DNSBL for *domain*.

    Args:
        domain: The domain name to check.
        dnsbl: The DNSBL hostname (e.g., "dbl.spamhaus.org").
        settings: Optional DnsSettings for resolver configuration.

    Returns:
        A dict with keys: dnsbl, listed (bool), clean (bool), error (bool),
        error_message (str|None), response (str|None).
    """
    query_domain = f"{domain}.{dnsbl}"

    dns_result = query_dns(query_domain, "A", settings)

    if dns_result["success"] and dns_result["records"]:
        # A record resolved -> domain is listed on this blocklist
        logger.warning("Domain %s is listed on %s (response: %s)", domain, dnsbl, dns_result["records"])
        return {
            "dnsbl": dnsbl,
            "listed": True,
            "clean": False,
            "error": False,
            "error_message": None,
            "response": dns_result["records"][0] if dns_result["records"] else None,
        }

    error_type = dns_result.get("error_type")

    if error_type == "NXDOMAIN" or error_type == "NO_ANSWER":
        # NXDOMAIN or NoAnswer means the domain is NOT listed
        return {
            "dnsbl": dnsbl,
            "listed": False,
            "clean": True,
            "error": False,
            "error_message": None,
            "response": None,
        }

    if error_type == "TIMEOUT":
        # Timeout is treated as an error (cannot determine listing status)
        logger.warning("Timeout checking %s on %s", domain, dnsbl)
        return {
            "dnsbl": dnsbl,
            "listed": False,
            "clean": False,
            "error": True,
            "error_message": f"Timeout querying {query_domain}",
            "response": None,
        }

    # Any other DNS error
    return {
        "dnsbl": dnsbl,
        "listed": False,
        "clean": False,
        "error": True,
        "error_message": dns_result.get("error_message", f"DNS error for {query_domain}"),
        "response": None,
    }
