"""
MX server IP geolocation and Quebec Law 25 compliance assessment.

Resolves MX exchange hostnames to IP addresses, then queries the ip-api.com
GeoIP service to determine the *physical* server location (not the ASN
registration country).  Results are classified against Quebec Law 25 data
residency requirements.

Uses the existing query_dns() wrapper so that resolver settings
(nameservers, timeouts) are applied consistently.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.request
import urllib.error
from typing import Any

from app.checker.resolver import query_dns
from app.models import DnsSettings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GeoIP API configuration
# ---------------------------------------------------------------------------

_GEOIP_API_URL: str = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org"
_GEOIP_TIMEOUT_SECONDS: int = 10

# ---------------------------------------------------------------------------
# Cloud provider compliance notes for Quebec Law 25
# ---------------------------------------------------------------------------

_CLOUD_PROVIDER_NOTES: dict[str, str] = {
    "Microsoft 365": (
        "Microsoft 365 Canadian tenants may store data in CA regions. "
        "Verify tenant data residency settings."
    ),
    "Google Workspace": (
        "Google Workspace offers Canadian data residency. "
        "Verify organizational settings."
    ),
    "Amazon SES": (
        "Amazon SES region must be configured for ca-central-1 "
        "for Canadian data residency."
    ),
    "ProtonMail": (
        "ProtonMail stores data in Switzerland. "
        "Review adequacy decision for Quebec Law 25."
    ),
    "OVH": (
        "OVH offers Canadian data centres (BHS). "
        "Verify that the mail service is hosted in the CA region."
    ),
    "Rackspace": (
        "Rackspace may host data outside Canada. "
        "Confirm the hosting region with your account representative."
    ),
    "Mimecast": (
        "Mimecast processes email through regional data centres. "
        "Verify the data processing region in your Mimecast contract."
    ),
    "Proofpoint": (
        "Proofpoint may route email through US or EU data centres. "
        "Confirm data residency with your Proofpoint account settings."
    ),
}

# ---------------------------------------------------------------------------
# MX hostname suffix to provider name mapping (for compliance note lookup)
# ---------------------------------------------------------------------------

_MX_SUFFIX_TO_PROVIDER: list[tuple[str, str]] = [
    ("protection.outlook.com", "Microsoft 365"),
    ("outlook.com", "Microsoft 365"),
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("amazonses.com", "Amazon SES"),
    ("protonmail.ch", "ProtonMail"),
    ("pm.me", "ProtonMail"),
    ("ovh.net", "OVH"),
    ("emailsrvr.com", "Rackspace"),
]


def _identify_provider(exchange: str) -> str | None:
    """Return a cloud provider name for *exchange*, or None if unrecognised.

    Args:
        exchange: MX exchange hostname (e.g. "mail.protection.outlook.com").

    Returns:
        Provider name string or None.
    """
    exchange_lower = exchange.rstrip(".").lower()
    for suffix, provider in _MX_SUFFIX_TO_PROVIDER:
        if exchange_lower.endswith(suffix):
            return provider
    return None


# ---------------------------------------------------------------------------
# GeoIP lookup via ip-api.com
# ---------------------------------------------------------------------------


def _is_private_ip(ip_address: str) -> bool:
    """Return True if *ip_address* is a private or reserved address.

    Args:
        ip_address: An IPv4 or IPv6 address string.

    Returns:
        True for private/reserved/loopback addresses, False otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip_address)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        return False


def _lookup_ip_country(ip_address: str) -> dict[str, Any]:
    """Query ip-api.com for the physical geolocation of *ip_address*.

    Returns the actual server location (data-centre country), not the
    ASN registration country.  Private/reserved IPs are detected locally
    without making an API call.

    Args:
        ip_address: An IPv4 or IPv6 address string.

    Returns:
        A dict with keys: country_code, country_name, description, error.
    """
    # Fast path for private/reserved IPs — no API call needed
    if _is_private_ip(ip_address):
        logger.info("IP %s is a private/reserved address; skipping geolocation", ip_address)
        return {
            "country_code": None,
            "country_name": None,
            "description": "Private/reserved IP address",
            "error": "Private or reserved IP address",
        }

    try:
        url = _GEOIP_API_URL.format(ip=ip_address)
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_GEOIP_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("status") != "success":
            msg = data.get("message", "Unknown error from ip-api.com")
            logger.warning("ip-api.com returned failure for %s: %s", ip_address, msg)
            return {
                "country_code": None,
                "country_name": None,
                "description": None,
                "error": msg,
            }

        country_code = data.get("countryCode")
        country_name = data.get("country")
        city = data.get("city", "")
        org = data.get("org", "")
        isp = data.get("isp", "")

        # Build a short description: "Microsoft Azure Cloud (canadacentral), Toronto"
        description_parts = [p for p in [org or isp, city] if p]
        description = ", ".join(description_parts) if description_parts else None

        return {
            "country_code": country_code,
            "country_name": country_name,
            "description": description,
            "error": None,
        }

    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        logger.warning("ip-api.com request failed for %s: %s", ip_address, exc)
        return {
            "country_code": None,
            "country_name": None,
            "description": None,
            "error": str(exc),
        }

    except Exception as exc:
        logger.warning("GeoIP lookup failed for %s: %s", ip_address, exc)
        return {
            "country_code": None,
            "country_name": None,
            "description": None,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Law 25 classification
# ---------------------------------------------------------------------------


def _classify_law25(
    servers: list[dict[str, Any]],
    exchanges: list[str],
) -> tuple[str, str]:
    """Determine Quebec Law 25 compliance status from geolocation results.

    Args:
        servers: List of server dicts with country_code and exchange fields.
        exchanges: Original MX exchange hostnames (for provider note lookup).

    Returns:
        A (status, details) tuple where status is one of:
            "compliant"     - All MX IPs resolve to CA (Canada).
            "review_needed" - MX IPs resolve to non-CA countries.
            "unknown"       - Could not determine location for any server.
    """
    resolved_countries: list[str] = [
        s["country_code"] for s in servers if s.get("country_code") is not None
    ]

    if not resolved_countries:
        return (
            "unknown",
            "Could not determine the geographic location of any mail server. "
            "Manual verification is required for Quebec Law 25 compliance.",
        )

    unique_countries = sorted(set(resolved_countries))
    all_canadian = all(cc == "CA" for cc in resolved_countries)

    if all_canadian:
        return (
            "compliant",
            "All mail servers are located in Canada (CA). "
            "This configuration is consistent with Quebec Law 25 data residency requirements.",
        )

    # Build a detailed message listing non-CA countries and provider notes
    non_ca = sorted({cc for cc in unique_countries if cc != "CA"})
    country_labels = []
    for cc in non_ca:
        name = next(
            (s.get("country_name") for s in servers if s.get("country_code") == cc and s.get("country_name")),
            cc,
        )
        country_labels.append(f"{cc} ({name})")

    details_parts: list[str] = [
        f"Mail servers detected in: {', '.join(country_labels)}. "
        "Quebec Law 25 requires that personal information of Quebec residents "
        "be protected with equivalent safeguards when transferred outside Quebec."
    ]

    # Append cloud provider specific notes if applicable
    seen_providers: set[str] = set()
    for exchange in exchanges:
        provider = _identify_provider(exchange)
        if provider and provider not in seen_providers:
            note = _CLOUD_PROVIDER_NOTES.get(provider)
            if note:
                details_parts.append(f"{provider}: {note}")
                seen_providers.add(provider)

    return ("review_needed", " ".join(details_parts))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_geolocation(
    mx_records: list[dict[str, Any]],
    settings: DnsSettings | None = None,
) -> dict[str, Any]:
    """Resolve MX server IPs and determine their physical geographic location.

    For each MX exchange hostname, resolves to IP address(es) via DNS,
    then queries ip-api.com to identify the actual data-centre country.
    Results are cached per IP within the check run to avoid duplicate
    lookups.

    Args:
        mx_records: List of MX record dicts as returned by ``check_mx()``,
            each with keys ``priority`` (int) and ``exchange`` (str).
        settings: Optional DnsSettings for resolver configuration;
            loaded from DB if not provided.

    Returns:
        A dict with keys:
            servers (list[dict]): Per-server geolocation details.
            countries (list[str]): Unique country codes found.
            law25_status (str): "compliant", "review_needed", or "unknown".
            law25_details (str): Human-readable compliance assessment.
            error (str|None): Top-level error message, if any.
    """
    if not mx_records:
        return {
            "servers": [],
            "countries": [],
            "law25_status": "unknown",
            "law25_details": "No MX records provided; cannot assess geolocation.",
            "error": "No MX records to process",
        }

    servers: list[dict[str, Any]] = []
    exchanges: list[str] = []
    ip_cache: dict[str, dict[str, Any]] = {}

    for mx in mx_records:
        exchange = mx.get("exchange", "")
        if not exchange:
            continue

        exchanges.append(exchange)

        # Resolve the MX exchange hostname to IP addresses
        dns_result = query_dns(exchange, "A", settings)

        if not dns_result["success"] or not dns_result["records"]:
            logger.info(
                "Could not resolve A record for MX exchange %s: %s",
                exchange,
                dns_result.get("error_message", "no records"),
            )
            servers.append({
                "exchange": exchange,
                "ip": None,
                "country_code": None,
                "country_name": None,
                "description": None,
                "error": dns_result.get("error_message", "No A record found"),
            })
            continue

        # Use the first A record for geolocation
        ip_address = dns_result["records"][0]

        # Check the per-run cache to avoid duplicate API calls
        if ip_address in ip_cache:
            geo = ip_cache[ip_address]
            logger.debug("Using cached geolocation for IP %s (exchange %s)", ip_address, exchange)
        else:
            geo = _lookup_ip_country(ip_address)
            ip_cache[ip_address] = geo

        servers.append({
            "exchange": exchange,
            "ip": ip_address,
            "country_code": geo["country_code"],
            "country_name": geo["country_name"],
            "description": geo["description"],
            "error": geo.get("error"),
        })

    # Collect unique country codes (excluding None)
    countries = sorted({
        s["country_code"] for s in servers
        if s.get("country_code") is not None
    })

    # Classify Law 25 compliance
    law25_status, law25_details = _classify_law25(servers, exchanges)

    logger.info(
        "Geolocation check: %d servers, countries=%s, law25_status=%s",
        len(servers),
        countries,
        law25_status,
    )

    return {
        "servers": servers,
        "countries": countries,
        "law25_status": law25_status,
        "law25_details": law25_details,
        "error": None,
    }
