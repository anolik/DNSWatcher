"""
Domain registrar checker — retrieves WHOIS information for a domain.

Uses the ``python-whois`` library with graceful fallback if the package
is not installed.  WHOIS failures never affect the domain check pipeline;
they are purely informational.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def check_registrar(domain: str) -> dict[str, Any]:
    """Query WHOIS for *domain* and return registrar information.

    Args:
        domain: The domain name to look up.

    Returns:
        A dict with keys:
            registrar (str|None): The domain registrar name.
            creation_date (str|None): Domain creation date (ISO format).
            expiration_date (str|None): Domain expiration date (ISO format).
            name_servers (list[str]): List of authoritative name servers.
            error (str|None): Error message if the lookup failed.
    """
    try:
        import whois
    except ImportError:
        logger.warning("python-whois not installed; skipping registrar lookup")
        return {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
            "error": "python-whois package not installed",
        }

    try:
        w = whois.whois(domain, timeout=10)
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
            "error": f"WHOIS lookup failed: {exc}",
        }

    return {
        "registrar": w.registrar if w.registrar else None,
        "creation_date": _normalize_date(w.creation_date),
        "expiration_date": _normalize_date(w.expiration_date),
        "name_servers": _normalize_name_servers(w.name_servers),
        "error": None,
    }


def _normalize_date(value: Any) -> str | None:
    """Normalize a WHOIS date field to an ISO-format string.

    Some TLDs return a list of dates; we take the first one.
    """
    if value is None:
        return None

    if isinstance(value, list):
        value = value[0] if value else None
        if value is None:
            return None

    if isinstance(value, datetime):
        return value.isoformat()

    return str(value)


def _normalize_name_servers(value: Any) -> list[str]:
    """Normalize WHOIS name_servers to a sorted, deduplicated lowercase list."""
    if value is None:
        return []

    if isinstance(value, str):
        value = [value]

    if not isinstance(value, (list, tuple, set)):
        return []

    return sorted({ns.lower().rstrip(".") for ns in value if isinstance(ns, str)})
