"""
F13 - Domain reputation checking via DNSBL (DNS-based Blocklists).

Checks whether a domain is listed on common URI-based blocklists:
- dbl.spamhaus.org (Spamhaus Domain Block List)
- multi.uribl.com (URIBL multi list)
- multi.surbl.org (SURBL multi list)

A domain is queried by resolving {domain}.{dnsbl} as an A record.
A successful resolution means the domain is listed (blocklisted).

Cooldown logic: when a DNSBL provider refuses queries 3 consecutive times
(returning 127.0.0.1 or 127.255.255.x), it is put on a 24-hour cooldown
to avoid flooding the provider with requests that will be denied anyway.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app import db
from app.checker.resolver import query_dns
from app.models import DnsSettings, DnsblCooldown

logger = logging.getLogger(__name__)

# URI-based DNS blocklists to check
_DNSBL_LIST: list[str] = [
    "dbl.spamhaus.org",
    "multi.uribl.com",
    "multi.surbl.org",
]

# Response codes that mean "query refused" or "not a real listing".
# Public/shared DNS resolvers (Cloudflare, Google, etc.) trigger these
# because DNSBL providers block high-volume forwarders.
# 127.0.0.1 is returned by URIBL and SURBL when the query is refused.
# 127.255.255.254/255 are Spamhaus error/test responses.
_QUERY_REFUSED_RESPONSES: frozenset[str] = frozenset({
    "127.0.0.1",
    "127.255.255.254",
    "127.255.255.255",
})


def check_reputation(
    domain: str,
    settings: DnsSettings | None = None,
) -> dict[str, Any]:
    """Check *domain* against known DNS blocklists.

    Args:
        domain: The domain name to check.
        settings: Optional DnsSettings; loaded from DB if not provided.

    Returns:
        A dict with keys: status, listed_on, clean_on, errors, skipped.
    """
    result: dict[str, Any] = {
        "status": "ok",
        "listed_on": [],
        "clean_on": [],
        "errors": [],
        "skipped": [],
    }

    for dnsbl in _DNSBL_LIST:
        # --- Cooldown gate: skip providers that are on cooldown ---
        if _is_provider_on_cooldown(dnsbl):
            logger.info(
                "Skipping DNSBL %s for %s (on cooldown after repeated refusals)",
                dnsbl, domain,
            )
            result["skipped"].append(dnsbl)
            continue

        check_result = _check_single_dnsbl(domain, dnsbl, settings)

        if check_result["listed"]:
            result["listed_on"].append(dnsbl)
            _record_dnsbl_success(dnsbl)
        elif check_result["clean"]:
            result["clean_on"].append(dnsbl)
            _record_dnsbl_success(dnsbl)
        elif check_result["error"]:
            result["errors"].append(
                f"{dnsbl}: {check_result.get('error_message', 'unknown error')}"
            )
            # Track query-refused responses for cooldown
            if check_result.get("query_refused"):
                _record_dnsbl_refusal(dnsbl)

    # Determine overall status
    if result["listed_on"]:
        result["status"] = "warning"
    else:
        result["status"] = "ok"

    logger.info(
        "Reputation check for %s: listed_on=%s, clean_on=%s, errors=%d, skipped=%s",
        domain,
        result["listed_on"],
        result["clean_on"],
        len(result["errors"]),
        result["skipped"],
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
        error_message (str|None), response (str|None), query_refused (bool).
    """
    query_domain = f"{domain}.{dnsbl}"

    dns_result = query_dns(query_domain, "A", settings)

    if dns_result["success"] and dns_result["records"]:
        response_ip = dns_result["records"][0] if dns_result["records"] else None

        # Some DNSBL providers return 127.0.0.1 to mean "query refused"
        # (not a real listing). This happens when queries go through
        # public DNS resolvers like Cloudflare or Google DNS.
        if response_ip in _QUERY_REFUSED_RESPONSES:
            logger.info(
                "DNSBL %s returned %s for %s (query refused, not a listing)",
                dnsbl, response_ip, domain,
            )
            return {
                "dnsbl": dnsbl,
                "listed": False,
                "clean": False,
                "error": True,
                "error_message": (
                    f"{dnsbl} refused the query ({response_ip}). "
                    "This typically means your DNS resolver is a public "
                    "forwarder. Use a private/local resolver for accurate results."
                ),
                "response": response_ip,
                "query_refused": True,
            }

        # A record resolved with a real listing code
        logger.warning("Domain %s is listed on %s (response: %s)", domain, dnsbl, dns_result["records"])
        return {
            "dnsbl": dnsbl,
            "listed": True,
            "clean": False,
            "error": False,
            "error_message": None,
            "response": response_ip,
            "query_refused": False,
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
            "query_refused": False,
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
            "query_refused": False,
        }

    # Any other DNS error
    return {
        "dnsbl": dnsbl,
        "listed": False,
        "clean": False,
        "error": True,
        "error_message": dns_result.get("error_message", f"DNS error for {query_domain}"),
        "response": None,
        "query_refused": False,
    }


# ---------------------------------------------------------------------------
# Cooldown management
# ---------------------------------------------------------------------------


def _get_or_create_cooldown(dnsbl: str) -> DnsblCooldown:
    """Fetch or create the DnsblCooldown row for *dnsbl*."""
    row = db.session.execute(
        db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == dnsbl)
    ).scalars().first()

    if row is None:
        row = DnsblCooldown(dnsbl=dnsbl, consecutive_refusals=0)
        db.session.add(row)
        db.session.flush()

    return row


def _is_provider_on_cooldown(dnsbl: str) -> bool:
    """Return True if *dnsbl* is currently on cooldown and should be skipped."""
    row = db.session.execute(
        db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == dnsbl)
    ).scalars().first()

    if row is None:
        return False

    if row.is_on_cooldown():
        return True

    # Cooldown has expired — reset the state so the provider gets retried
    if row.cooldown_until is not None:
        row.consecutive_refusals = 0
        row.cooldown_until = None
        # No commit here; the caller (engine.py) commits at the end

    return False


def _record_dnsbl_refusal(dnsbl: str) -> None:
    """Record a query-refused response and activate cooldown if threshold reached."""
    row = _get_or_create_cooldown(dnsbl)
    now = datetime.now(timezone.utc)

    row.consecutive_refusals += 1
    row.last_refused_at = now

    if row.consecutive_refusals >= DnsblCooldown.COOLDOWN_THRESHOLD:
        row.cooldown_until = now + timedelta(hours=DnsblCooldown.COOLDOWN_HOURS)
        logger.warning(
            "DNSBL %s put on %d-hour cooldown after %d consecutive refusals (until %s)",
            dnsbl,
            DnsblCooldown.COOLDOWN_HOURS,
            row.consecutive_refusals,
            row.cooldown_until.isoformat(),
        )


def _record_dnsbl_success(dnsbl: str) -> None:
    """Reset the refusal counter on a successful (listed or clean) response."""
    row = db.session.execute(
        db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == dnsbl)
    ).scalars().first()

    if row is not None and row.consecutive_refusals > 0:
        row.consecutive_refusals = 0
        row.cooldown_until = None
