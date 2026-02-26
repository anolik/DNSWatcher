"""
MX record checker — resolves MX records and identifies the email provider.

Uses the existing query_dns() wrapper so that resolver settings (nameservers,
timeouts) are applied consistently.  The provider identification is based on
a static suffix map of well-known MX hostnames.
"""

from __future__ import annotations

import logging
from typing import Any

from app.checker.resolver import query_dns
from app.models import DnsSettings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider identification map
# ---------------------------------------------------------------------------

# Maps MX hostname suffixes (lowercased) to friendly provider names.
# Checked in order; first match wins.
_MX_PROVIDER_MAP: list[tuple[str, str]] = [
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"),
    ("protection.outlook.com", "Microsoft 365"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("amazonses.com", "Amazon SES"),
    ("protonmail.ch", "ProtonMail"),
    ("pm.me", "ProtonMail"),
    ("ovh.net", "OVH"),
    ("secureserver.net", "GoDaddy"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("messagelabs.com", "Broadcom (Symantec)"),
    ("barracudanetworks.com", "Barracuda"),
    ("emailsrvr.com", "Rackspace"),
    ("pair.com", "pair Networks"),
    ("registrar-servers.com", "Namecheap"),
    ("hover.com", "Hover"),
    ("fastmail.com", "Fastmail"),
    ("icloud.com", "Apple iCloud"),
    ("yahoodns.net", "Yahoo Mail"),
    ("yandex.net", "Yandex Mail"),
    ("migadu.com", "Migadu"),
    ("titan.email", "Titan"),
]


# Maps provider names to their known DKIM selectors.
# Used to auto-select the correct selectors once MX provider is identified.
PROVIDER_DKIM_SELECTORS: dict[str, list[str]] = {
    "Google Workspace": ["google"],
    "Microsoft 365": ["selector1", "selector2"],
    "ProtonMail": ["protonmail", "protonmail2", "protonmail3"],
    "Zoho Mail": ["zoho", "default", "zoho1"],
    "Amazon SES": ["amazonses", "ses", "k1"],
    "Mimecast": ["mimecast20190104", "mimecast"],
    "Proofpoint": ["s1", "s2", "proofpoint"],
    "OVH": ["ovhmo", "default", "mail"],
    "GoDaddy": ["default", "k1"],
    "Mailgun": ["smtp", "k1", "krs", "mail"],
    "SendGrid": ["s1", "s2", "smtpapi"],
    "Apple iCloud": ["sig1"],
    "Yahoo Mail": ["s1024", "s2048"],
    "Yandex Mail": ["mail"],
    "Fastmail": ["fm1", "fm2", "fm3"],
    "Migadu": ["key1", "key2", "key3"],
    "Titan": ["titan", "default"],
    "Rackspace": ["s1", "s2"],
    "Barracuda": ["s1", "s2"],
}


def identify_mx_provider(exchange: str) -> str:
    """Return a friendly provider name based on the MX exchange hostname.

    Args:
        exchange: The MX exchange hostname (e.g. "alt1.aspmx.l.google.com.").

    Returns:
        The provider name, or the raw exchange hostname if no match is found.
    """
    exchange_lower = exchange.rstrip(".").lower()

    for suffix, provider_name in _MX_PROVIDER_MAP:
        if exchange_lower.endswith(suffix):
            return provider_name

    return exchange_lower


def check_mx(
    domain: str,
    settings: DnsSettings | None = None,
) -> dict[str, Any]:
    """Resolve MX records for *domain* and identify the mail provider.

    Args:
        domain: The domain name to query.
        settings: Optional DnsSettings; loaded from DB if not provided.

    Returns:
        A dict with keys:
            records (list[dict]): Sorted list of {priority: int, exchange: str}.
            provider (str): Friendly name of the primary MX provider.
            raw_records (list[str]): Raw MX record strings from DNS.
            error (str|None): Error message if the query failed.
    """
    result = query_dns(domain, "MX", settings)

    if not result["success"]:
        return {
            "records": [],
            "provider": None,
            "raw_records": [],
            "error": result.get("error_message"),
        }

    records: list[dict[str, Any]] = []
    for raw in result["records"]:
        parts = raw.split(None, 1)
        if len(parts) == 2:
            try:
                priority = int(parts[0])
            except ValueError:
                priority = 99
            exchange = parts[1].rstrip(".")
            records.append({"priority": priority, "exchange": exchange})

    # Sort by priority (lower = preferred)
    records.sort(key=lambda r: r["priority"])

    # Identify provider from the lowest-priority (most preferred) MX
    provider = None
    if records:
        provider = identify_mx_provider(records[0]["exchange"])

    return {
        "records": records,
        "provider": provider,
        "raw_records": result["records"],
        "error": None,
    }
