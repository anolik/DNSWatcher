"""
Domain registrar checker — retrieves WHOIS information for a domain.

Uses the ``python-whois`` library with graceful fallback if the package
is not installed.  WHOIS failures never affect the domain check pipeline;
they are purely informational.

A hard 15-second thread-based timeout guards against the ``python-whois``
library hanging on recursive WHOIS referral chains (each sub-query gets
its own socket timeout, so the library's ``timeout`` parameter does not
bound total wall-clock time).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# Hard wall-clock limit for the entire WHOIS lookup (seconds).
_WHOIS_HARD_TIMEOUT: int = 15

# Module-level single-thread executor reused across calls to avoid the
# overhead of creating a new thread per lookup.
_whois_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="whois")

_EMPTY_RESULT: dict[str, Any] = {
    "registrar": None,
    "creation_date": None,
    "expiration_date": None,
    "name_servers": [],
}


def check_registrar(domain: str) -> dict[str, Any]:
    """Query WHOIS for *domain* and return registrar information.

    The lookup runs inside a thread with a hard timeout so that a
    hanging WHOIS server cannot block the entire check pipeline.

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
        import whois  # noqa: PLC0415
    except ImportError:
        logger.warning("python-whois not installed; skipping registrar lookup")
        return {**_EMPTY_RESULT, "error": "python-whois package not installed"}

    future = _whois_executor.submit(_do_whois_lookup, whois, domain)
    try:
        return future.result(timeout=_WHOIS_HARD_TIMEOUT)
    except FuturesTimeoutError:
        logger.warning(
            "WHOIS lookup timed out for %s after %ds", domain, _WHOIS_HARD_TIMEOUT
        )
        future.cancel()
        return {**_EMPTY_RESULT, "error": f"WHOIS lookup timed out after {_WHOIS_HARD_TIMEOUT}s"}
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {**_EMPTY_RESULT, "error": f"WHOIS lookup failed: {exc}"}


def _do_whois_lookup(whois_module: Any, domain: str) -> dict[str, Any]:
    """Run the actual whois query (called inside the executor thread)."""
    try:
        w = whois_module.whois(domain, timeout=8)
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {**_EMPTY_RESULT, "error": f"WHOIS lookup failed: {exc}"}

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
