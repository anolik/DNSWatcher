"""
F09 - Robust DNS resolver wrapper.

Provides thread-safe DNS resolution with configurable nameservers,
timeouts, retries, and comprehensive error handling for NXDOMAIN,
SERVFAIL, timeouts, and truncated responses.
"""

from __future__ import annotations

import logging
from typing import Any

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

from app.models import DnsSettings

logger = logging.getLogger(__name__)


def _load_settings() -> DnsSettings:
    """Load global DnsSettings from database.

    Returns a DnsSettings instance, falling back to a transient default
    if no row exists in the database.  This is only used as a safety net
    when no settings object is passed by the caller (the normal path in
    run_domain_check already loads per-org settings).
    """
    from app.utils.tenant import get_org_settings  # noqa: PLC0415
    return get_org_settings(None)


def create_resolver(settings: DnsSettings) -> dns.resolver.Resolver:
    """Create a fresh dns.resolver.Resolver configured from *settings*.

    A new instance is created every time to ensure thread safety.

    Args:
        settings: DnsSettings instance containing resolver config.

    Returns:
        A configured dns.resolver.Resolver instance.
    """
    resolver = dns.resolver.Resolver(configure=False)

    nameservers = settings.get_resolvers()
    if nameservers:
        resolver.nameservers = nameservers
    else:
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    resolver.timeout = float(settings.timeout_seconds)
    resolver.lifetime = float(settings.timeout_seconds * settings.retries)
    resolver.retry_servfail = True

    return resolver


def query_dns(
    domain: str,
    rdtype: str,
    settings: DnsSettings | None = None,
) -> dict[str, Any]:
    """Execute a DNS query with robust error handling.

    Args:
        domain: The domain name to query.
        rdtype: DNS record type string (e.g. "TXT", "A", "CNAME").
        settings: Optional DnsSettings; loaded from DB if not provided.

    Returns:
        A dict with keys:
            success (bool): Whether the query returned records.
            records (list[str]): The resolved record strings.
            error_type (str|None): Category of error if failed.
            error_message (str|None): Human-readable error description.
    """
    if settings is None:
        settings = _load_settings()

    resolver = create_resolver(settings)

    try:
        answer = resolver.resolve(domain, rdtype)
        records: list[str] = []
        for rdata in answer:
            # TXT records come as multiple byte strings that need joining
            if rdtype.upper() == "TXT":
                txt_value = b"".join(rdata.strings).decode("utf-8", errors="replace")
                records.append(txt_value)
            else:
                records.append(rdata.to_text())

        logger.debug("DNS query %s/%s returned %d records", domain, rdtype, len(records))
        return {
            "success": True,
            "records": records,
            "error_type": None,
            "error_message": None,
        }

    except dns.resolver.NXDOMAIN:
        logger.info("NXDOMAIN for %s/%s", domain, rdtype)
        return {
            "success": False,
            "records": [],
            "error_type": "NXDOMAIN",
            "error_message": f"Domain {domain} does not exist (NXDOMAIN)",
        }

    except dns.resolver.NoAnswer:
        logger.info("NoAnswer for %s/%s", domain, rdtype)
        return {
            "success": False,
            "records": [],
            "error_type": "NO_ANSWER",
            "error_message": f"No {rdtype} records found for {domain}",
        }

    except dns.resolver.NoNameservers:
        logger.warning("NoNameservers for %s/%s", domain, rdtype)
        return {
            "success": False,
            "records": [],
            "error_type": "DNS_ERROR",
            "error_message": f"No nameservers available for {domain} (SERVFAIL or all failed)",
        }

    except dns.resolver.Timeout:
        logger.warning("Timeout for %s/%s", domain, rdtype)
        return {
            "success": False,
            "records": [],
            "error_type": "TIMEOUT",
            "error_message": f"DNS query timed out for {domain}/{rdtype}",
        }

    except dns.exception.DNSException as exc:
        logger.error("DNSException for %s/%s: %s", domain, rdtype, exc)
        return {
            "success": False,
            "records": [],
            "error_type": "DNS_ERROR",
            "error_message": f"DNS error for {domain}/{rdtype}: {exc}",
        }

    except Exception as exc:
        logger.exception("Unexpected error querying %s/%s", domain, rdtype)
        return {
            "success": False,
            "records": [],
            "error_type": "DNS_ERROR",
            "error_message": f"Unexpected error for {domain}/{rdtype}: {exc}",
        }
