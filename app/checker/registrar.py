"""
Domain registrar checker — RDAP primary with WHOIS fallback.

Uses the IANA RDAP Bootstrap (RFC 7484) to resolve each domain's TLD to
its authoritative RDAP server, bypassing the rdap.org redirector that
aggressively rate-limits shared IPs.  Falls back to user-configured servers
(round-robin), then to ``python-whois`` when all RDAP paths fail.

Failures never affect the domain check pipeline; registrar data is purely
informational.

A hard 20-second thread-based timeout guards against either lookup path
hanging indefinitely.  RDAP gets an internal 8-second sub-timeout so that
WHOIS always has time to run as fallback.
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Default minimum delay (seconds) between consecutive RDAP requests.
_DEFAULT_THROTTLE_DELAY: float = 2.0
_throttle_lock = threading.Lock()
_last_request_time: float = 0.0

# Hard wall-clock limit for the entire RDAP + WHOIS attempt (seconds).
_LOOKUP_HARD_TIMEOUT: int = 20

# Internal timeout for each RDAP HTTP request (seconds).
_RDAP_REQUEST_TIMEOUT: int = 8

# Module-level single-thread executor reused across calls.
_lookup_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="registrar")

_EMPTY_RESULT: dict[str, Any] = {
    "registrar": None,
    "creation_date": None,
    "expiration_date": None,
    "name_servers": [],
}

_DEFAULT_RDAP_SERVERS: list[str] = ["https://rdap.org"]

# Atomic counter for round-robin server selection (thread-safe).
_rdap_counter = itertools.count()

# ---------------------------------------------------------------------------
# IANA RDAP Bootstrap (RFC 7484)
# ---------------------------------------------------------------------------

_IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_IANA_BOOTSTRAP_TIMEOUT = 10  # seconds

# Thread-safe cache: TLD → authoritative RDAP base URL.
_bootstrap_lock = threading.Lock()
_bootstrap_cache: dict[str, str] = {}
_bootstrap_loaded: bool = False


def _load_bootstrap() -> None:
    """Fetch the IANA RDAP bootstrap file and populate ``_bootstrap_cache``.

    Called lazily on first RDAP lookup.  On failure the cache stays empty
    and the code falls back to configured servers / WHOIS.
    """
    global _bootstrap_loaded
    with _bootstrap_lock:
        if _bootstrap_loaded:
            return
        try:
            resp = requests.get(
                _IANA_BOOTSTRAP_URL,
                timeout=_IANA_BOOTSTRAP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("services", []):
                if len(entry) < 2:
                    continue
                tlds, urls = entry[0], entry[1]
                if not urls:
                    continue
                server_url = urls[0].rstrip("/")
                for tld in tlds:
                    _bootstrap_cache[tld.lower()] = server_url
            logger.info(
                "IANA RDAP bootstrap loaded: %d TLD mappings",
                len(_bootstrap_cache),
            )
        except Exception as exc:
            logger.warning(
                "Failed to load IANA RDAP bootstrap (%s); "
                "will fall back to configured servers",
                exc,
            )
        _bootstrap_loaded = True


def _get_bootstrap_server(domain: str) -> str | None:
    """Return the authoritative RDAP server for *domain*'s TLD, or ``None``.

    Extracts the TLD (rightmost label) from the domain name and looks it
    up in the cached IANA bootstrap data.
    """
    if not _bootstrap_loaded:
        _load_bootstrap()
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else None
    if tld:
        return _bootstrap_cache.get(tld)
    return None


# ---------------------------------------------------------------------------
# RDAP round-robin server selection
# ---------------------------------------------------------------------------


def _pick_rdap_server(servers: list[str]) -> str:
    """Return the next RDAP server URL via round-robin rotation."""
    idx = next(_rdap_counter) % len(servers)
    return servers[idx]


def _throttle_wait(delay: float) -> None:
    """Ensure at least *delay* seconds between consecutive RDAP requests.

    Uses a module-level lock so that concurrent threads (e.g. during
    "check all") queue up and fire RDAP requests with a guaranteed gap,
    preventing rate-limit (403) responses from rdap.org.
    """
    global _last_request_time
    with _throttle_lock:
        now = time.monotonic()
        elapsed = now - _last_request_time
        if elapsed < delay:
            wait_time = delay - elapsed
            logger.debug("RDAP throttle: waiting %.1fs", wait_time)
            time.sleep(wait_time)
        _last_request_time = time.monotonic()


# ---------------------------------------------------------------------------
# RDAP lookup (direct HTTPS)
# ---------------------------------------------------------------------------


def _do_single_rdap_request(domain: str, server: str) -> dict[str, Any] | None:
    """Send one RDAP request to *server* for *domain*.

    Returns:
        A normalized result dict on success, or ``None`` on failure.
    """
    url = f"{server.rstrip('/')}/domain/{domain}"
    try:
        resp = requests.get(
            url,
            headers={"Accept": "application/rdap+json"},
            timeout=_RDAP_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.info(
            "RDAP lookup for %s via %s failed (%s)",
            domain, server, exc,
        )
        return None
    except (ValueError, KeyError) as exc:
        logger.info(
            "RDAP JSON parse error for %s via %s (%s)",
            domain, server, exc,
        )
        return None

    return _parse_rdap_response(data)


def _do_rdap_lookup(domain: str, servers: list[str]) -> dict[str, Any] | None:
    """Attempt an RDAP lookup for *domain*.

    Strategy (in order):
    1. **IANA Bootstrap** — query the authoritative RDAP server for the
       domain's TLD directly (bypasses rdap.org rate limits).
    2. **Configured servers** — round-robin through user-configured servers.

    Returns:
        A normalized result dict on success, or ``None`` if all RDAP
        attempts fail (triggering WHOIS fallback).
    """
    # 1) Try the IANA bootstrap server (authoritative for this TLD).
    bootstrap_server = _get_bootstrap_server(domain)
    if bootstrap_server:
        result = _do_single_rdap_request(domain, bootstrap_server)
        if result is not None:
            return result
        # Bootstrap server failed — fall through to configured servers.

    # 2) Try user-configured servers (round-robin).
    if not servers:
        return None

    server = _pick_rdap_server(servers)
    # Skip if it's the same server we already tried via bootstrap.
    if bootstrap_server and server.rstrip("/") == bootstrap_server:
        logger.info(
            "RDAP: skipping configured server %s (same as bootstrap); "
            "falling back to WHOIS for %s",
            server, domain,
        )
        return None

    result = _do_single_rdap_request(domain, server)
    if result is not None:
        return result

    logger.info("All RDAP attempts failed for %s; falling back to WHOIS", domain)
    return None


def _parse_rdap_response(data: dict[str, Any]) -> dict[str, Any]:
    """Extract registrar, dates, and nameservers from an RFC 9083 response.

    RFC 9083 structure:
    - ``entities[].roles`` containing ``"registrar"`` → registrar name
    - ``events[].eventAction`` → ``"registration"`` / ``"expiration"``
    - ``nameservers[].ldhName`` → authoritative name servers
    """
    # --- Registrar ---
    registrar = None
    for entity in data.get("entities") or []:
        roles = entity.get("roles") or []
        if "registrar" in roles:
            # Try vcardArray first, then handle/fn
            vcard = entity.get("vcardArray")
            if vcard and isinstance(vcard, list) and len(vcard) > 1:
                for prop in vcard[1]:
                    if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                        registrar = prop[3]
                        break
            if not registrar:
                registrar = entity.get("handle")
            break

    # --- Dates ---
    creation_date = None
    expiration_date = None
    for event in data.get("events") or []:
        action = event.get("eventAction")
        date_str = event.get("eventDate")
        if action == "registration" and date_str:
            creation_date = date_str
        elif action == "expiration" and date_str:
            expiration_date = date_str

    # --- Name servers ---
    raw_ns = [
        ns.get("ldhName")
        for ns in (data.get("nameservers") or [])
        if ns.get("ldhName")
    ]

    return {
        "registrar": registrar,
        "creation_date": _normalize_date(creation_date),
        "expiration_date": _normalize_date(expiration_date),
        "name_servers": _normalize_name_servers(raw_ns),
        "lookup_method": "rdap",
        "error": None,
    }


# ---------------------------------------------------------------------------
# WHOIS lookup (fallback)
# ---------------------------------------------------------------------------


def _do_whois_lookup(domain: str) -> dict[str, Any]:
    """Run a WHOIS query for *domain* using ``python-whois``.

    Returns:
        A normalized result dict.  On failure the ``error`` key is set
        and all data fields are ``None``.
    """
    try:
        import whois  # noqa: PLC0415
    except ImportError:
        logger.warning("python-whois not installed; skipping WHOIS fallback")
        return {**_EMPTY_RESULT, "lookup_method": "whois", "error": "python-whois package not installed"}

    try:
        w = whois.whois(domain, timeout=8)
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {**_EMPTY_RESULT, "lookup_method": "whois", "error": f"WHOIS lookup failed: {exc}"}

    return {
        "registrar": w.registrar if w.registrar else None,
        "creation_date": _normalize_date(w.creation_date),
        "expiration_date": _normalize_date(w.expiration_date),
        "name_servers": _normalize_name_servers(w.name_servers),
        "lookup_method": "whois",
        "error": None,
    }


# ---------------------------------------------------------------------------
# Combined lookup (RDAP first, WHOIS fallback)
# ---------------------------------------------------------------------------


def _do_combined_lookup(domain: str, rdap_servers: list[str]) -> dict[str, Any]:
    """Try RDAP first, then fall back to WHOIS.

    Called inside the executor thread.
    """
    rdap_result = _do_rdap_lookup(domain, rdap_servers)
    if rdap_result is not None:
        return rdap_result

    return _do_whois_lookup(domain)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_registrar(
    domain: str,
    rdap_servers: list[str] | None = None,
    throttle_delay: float | None = None,
) -> dict[str, Any]:
    """Query registrar information for *domain* (RDAP primary, WHOIS fallback).

    The lookup runs inside a thread with a hard timeout so that a
    hanging server cannot block the entire check pipeline.

    Args:
        domain: The domain name to look up.
        rdap_servers: List of RDAP server base URLs.  Rotated round-robin.
            Defaults to ``["https://rdap.org"]`` if not provided.
        throttle_delay: Minimum seconds between consecutive RDAP requests.
            Prevents rate-limiting during batch operations.  Defaults to
            ``_DEFAULT_THROTTLE_DELAY`` (2.0s) when ``None``.  Set to 0
            to disable throttling.

    Returns:
        A dict with keys:
            registrar (str|None): The domain registrar name.
            creation_date (str|None): Domain creation date (ISO format).
            expiration_date (str|None): Domain expiration date (ISO format).
            name_servers (list[str]): List of authoritative name servers.
            lookup_method (str): "rdap" or "whois".
            error (str|None): Error message if the lookup failed.
    """
    servers = rdap_servers if rdap_servers is not None else _DEFAULT_RDAP_SERVERS
    delay = throttle_delay if throttle_delay is not None else _DEFAULT_THROTTLE_DELAY
    if delay > 0:
        _throttle_wait(delay)
    future = _lookup_executor.submit(_do_combined_lookup, domain, servers)
    try:
        return future.result(timeout=_LOOKUP_HARD_TIMEOUT)
    except FuturesTimeoutError:
        logger.warning(
            "Registrar lookup timed out for %s after %ds", domain, _LOOKUP_HARD_TIMEOUT
        )
        future.cancel()
        return {
            **_EMPTY_RESULT,
            "lookup_method": "timeout",
            "error": f"Registrar lookup timed out after {_LOOKUP_HARD_TIMEOUT}s",
        }
    except Exception as exc:
        logger.warning("Registrar lookup failed for %s: %s", domain, exc)
        return {
            **_EMPTY_RESULT,
            "lookup_method": "error",
            "error": f"Registrar lookup failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Helpers (shared by both RDAP and WHOIS paths)
# ---------------------------------------------------------------------------


def _normalize_date(value: Any) -> str | None:
    """Normalize a date field to an ISO-format string.

    Some sources return a list of dates; we take the first one.
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
    """Normalize name servers to a sorted, deduplicated lowercase list."""
    if value is None:
        return []

    if isinstance(value, str):
        value = [value]

    if not isinstance(value, (list, tuple, set)):
        return []

    return sorted({ns.lower().rstrip(".") for ns in value if isinstance(ns, str)})
