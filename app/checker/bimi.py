"""
BIMI checker — Brand Indicators for Message Identification (RFC 9051).

BIMI allows brands to display their logo in email clients by publishing a
DNS TXT record at default._bimi.{domain}.  A Verified Mark Certificate (VMC)
strengthens trust but is not required for the record to be present.

This check is purely informational: its status is stored but never included
in the overall_status calculation.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.models import DnsSettings

logger = logging.getLogger(__name__)


def check_bimi(domain: str, settings: "DnsSettings | None") -> dict[str, Any]:
    """Check BIMI DNS configuration for *domain*.

    Args:
        domain: The domain name to check (e.g., "example.com").
        settings: DnsSettings instance for resolver configuration, or None.

    Returns:
        A dict with keys:
            status (str|None): "ok", "warning", "info", "error", or None.
            record (str|None): Raw TXT record at default._bimi.domain.
            version (str|None): "BIMI1" if present.
            logo_url (str|None): Value of the l= tag (SVG logo URL).
            authority_url (str|None): Value of the a= tag (VMC URL).
            has_vmc (bool): True if a= tag is present and non-empty.
            warnings (list[str]): Non-fatal issues detected.
    """
    bimi_name = f"default._bimi.{domain}"
    records = _query_txt(bimi_name, settings)

    if records is None:
        # DNS error
        return {
            "status": "error",
            "record": None,
            "version": None,
            "logo_url": None,
            "authority_url": None,
            "has_vmc": False,
            "warnings": [],
        }

    bimi_record = _find_bimi_record(records)

    if not bimi_record:
        # No BIMI record — legitimate absence
        return {
            "status": None,
            "record": None,
            "version": None,
            "logo_url": None,
            "authority_url": None,
            "has_vmc": False,
            "warnings": [],
        }

    # ---- Parse tags ----
    tags = _parse_tags(bimi_record)
    warnings: list[str] = []

    version = tags.get("v")
    if version and version.upper() != "BIMI1":
        warnings.append(f"Unexpected BIMI version: {version!r}")

    logo_url = tags.get("l") or None
    authority_url = tags.get("a") or None
    has_vmc = bool(authority_url)

    # ---- Validate logo URL ----
    if logo_url:
        lo = logo_url.lower()
        if not (lo.startswith("https://") and (lo.endswith(".svg") or lo.endswith(".svgz"))):
            warnings.append(
                f"BIMI logo URL should be an HTTPS SVG link; got: {logo_url!r}"
            )
    else:
        warnings.append("BIMI record has no logo URL (l= tag missing or empty)")

    # ---- Determine status ----
    status = _compute_status(logo_url, has_vmc, warnings)

    return {
        "status": status,
        "record": bimi_record,
        "version": version,
        "logo_url": logo_url,
        "authority_url": authority_url,
        "has_vmc": has_vmc,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _query_txt(name: str, settings: "DnsSettings | None") -> list[str] | None:
    """Query TXT records for *name*, returning None on DNS error."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        if settings:
            try:
                resolver.nameservers = settings.get_resolvers()
                resolver.timeout = settings.timeout_seconds
                resolver.lifetime = settings.timeout_seconds * settings.retries
            except Exception:
                pass

        answers = resolver.resolve(name, "TXT")
        results: list[str] = []
        for rdata in answers:
            txt = "".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
            results.append(txt)
        return results
    except Exception as exc:
        # Treat NXDOMAIN and NoAnswer as legitimate absence of record
        exc_type = type(exc).__name__
        if exc_type in ("NXDOMAIN", "NoAnswer"):
            return []
        err_str = str(exc).lower()
        if "nxdomain" in err_str or "no answer" in err_str or "nodomain" in err_str:
            return []  # Legitimate absence
        logger.debug("DNS TXT query failed for %s: %s", name, exc)
        return None  # True DNS error


def _find_bimi_record(records: list[str]) -> str | None:
    """Return the first record that looks like a BIMI TXT entry."""
    for rec in records:
        if rec.lower().startswith("v=bimi1"):
            return rec
    return None


def _parse_tags(record: str) -> dict[str, str]:
    """Parse semicolon-separated tag=value pairs from a DNS TXT record."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


def _compute_status(
    logo_url: str | None,
    has_vmc: bool,
    warnings: list[str],
) -> str:
    """Determine the BIMI status string."""
    if not logo_url:
        return "info"  # Record present but no logo
    if has_vmc and not warnings:
        return "ok"    # Logo + VMC, no issues
    if has_vmc:
        return "warning"  # Logo + VMC but with warnings
    if logo_url and not warnings:
        return "warning"  # Logo without VMC is acceptable but not ideal
    return "info"
