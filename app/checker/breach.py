"""
HIBP (Have I Been Pwned) v3 API client — domain breach search.

Queries the HIBP v3 API to find data breaches associated with a given
domain.  Results are purely informational and never affect the core
DNS check pipeline.

Rate limiting is enforced via a module-level lock and monotonic clock,
matching the throttle pattern used in ``app/checker/registrar.py``.
HIBP allows roughly 10 requests per minute; the default 6-second delay
between calls stays comfortably within that limit.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HIBP_BASE_URL: str = "https://haveibeenpwned.com/api/v3"
_HIBP_USER_AGENT: str = "SPF-DMARC-DKIM-Watcher"

# Default minimum delay (seconds) between consecutive HIBP requests.
_DEFAULT_THROTTLE_DELAY: float = 6.0

# Hard timeout for a single HIBP HTTP request (seconds).
_REQUEST_TIMEOUT: int = 30

# Maximum retries on 429 (Too Many Requests) responses.
_MAX_RETRIES: int = 3

# Base wait (seconds) for exponential backoff on 429 responses.
_BACKOFF_BASE: float = 2.0

# ---------------------------------------------------------------------------
# Thread-safe throttle state
# ---------------------------------------------------------------------------

_throttle_lock = threading.Lock()
_last_request_time: float = 0.0

_EMPTY_RESULT: dict[str, Any] = {
    "breaches": [],
    "total_breaches": 0,
    "error": None,
}


# ---------------------------------------------------------------------------
# Throttle
# ---------------------------------------------------------------------------


def _throttle_wait(delay: float) -> None:
    """Ensure at least *delay* seconds between consecutive HIBP requests.

    Uses a module-level lock so that concurrent threads queue up and fire
    HIBP requests with a guaranteed gap, preventing 429 responses.
    """
    global _last_request_time
    with _throttle_lock:
        now = time.monotonic()
        elapsed = now - _last_request_time
        if elapsed < delay:
            wait_time = delay - elapsed
            logger.debug("HIBP throttle: waiting %.1fs", wait_time)
            time.sleep(wait_time)
        _last_request_time = time.monotonic()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_headers(api_key: str) -> dict[str, str]:
    """Build the HTTP headers required by the HIBP v3 API."""
    return {
        "hibp-api-key": api_key,
        "User-Agent": _HIBP_USER_AGENT,
        "Accept": "application/json",
    }


def _parse_breach(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a single breach object from the HIBP response.

    Extracts only the fields relevant to domain monitoring, discarding
    internal HIBP metadata.
    """
    return {
        "name": raw.get("Name", ""),
        "date": raw.get("BreachDate", ""),
        "data_classes": raw.get("DataClasses", []),
        "pwn_count": raw.get("PwnCount", 0),
        "description": raw.get("Description", ""),
    }


def _do_hibp_request(domain: str, api_key: str) -> dict[str, Any]:
    """Execute the HIBP domain breach lookup with retry on 429.

    Uses the ``/breaches?domain={domain}`` endpoint which returns all
    breaches associated with the given domain.

    Returns:
        A result dict with ``breaches``, ``total_breaches``, and ``error``.
    """
    url = f"{_HIBP_BASE_URL}/breaches"
    headers = _build_headers(api_key)
    params = {"domain": domain}

    last_error: str | None = None

    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=_REQUEST_TIMEOUT,
            )

            # --- 401: invalid API key ---
            if resp.status_code == 401:
                logger.warning("HIBP API key invalid or missing for %s", domain)
                return {**_EMPTY_RESULT, "error": "Invalid or missing HIBP API key"}

            # --- 404: no breaches found (not an error) ---
            if resp.status_code == 404:
                logger.info("HIBP: no breaches found for %s", domain)
                return {**_EMPTY_RESULT}

            # --- 429: rate limited, retry with exponential backoff ---
            if resp.status_code == 429:
                retry_after = _BACKOFF_BASE * (2 ** attempt)
                # Honour Retry-After header if present.
                raw_retry = resp.headers.get("Retry-After")
                if raw_retry:
                    try:
                        retry_after = max(float(raw_retry), retry_after)
                    except (ValueError, TypeError):
                        pass
                if attempt < _MAX_RETRIES:
                    logger.info(
                        "HIBP rate limited for %s; retrying in %.1fs (attempt %d/%d)",
                        domain, retry_after, attempt + 1, _MAX_RETRIES,
                    )
                    time.sleep(retry_after)
                    continue
                else:
                    logger.warning(
                        "HIBP rate limited for %s; max retries (%d) exhausted",
                        domain, _MAX_RETRIES,
                    )
                    return {
                        **_EMPTY_RESULT,
                        "error": f"HIBP rate limit exceeded after {_MAX_RETRIES} retries",
                    }

            # --- Other non-2xx status codes ---
            resp.raise_for_status()

            # --- Success: parse the breach list ---
            data = resp.json()
            if not isinstance(data, list):
                data = []

            breaches = [_parse_breach(b) for b in data]
            return {
                "breaches": breaches,
                "total_breaches": len(breaches),
                "error": None,
            }

        except requests.Timeout:
            last_error = f"HIBP request timed out after {_REQUEST_TIMEOUT}s"
            logger.warning("HIBP timeout for %s: %s", domain, last_error)
            break  # No retry on timeout — respect the hard limit.

        except requests.RequestException as exc:
            last_error = f"HIBP request failed: {exc}"
            logger.warning("HIBP request error for %s: %s", domain, exc)
            break  # Network errors are unlikely to self-resolve on retry.

        except (ValueError, KeyError) as exc:
            last_error = f"HIBP response parse error: {exc}"
            logger.warning("HIBP JSON parse error for %s: %s", domain, exc)
            break

    return {**_EMPTY_RESULT, "error": last_error}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_breaches(
    domain: str,
    api_key: str,
    throttle_delay: float = 6.0,
) -> dict[str, Any]:
    """Check a domain for data breaches via the HIBP v3 API.

    Queries ``GET /breaches?domain={domain}`` and returns a normalized
    result.  Thread-safe throttling prevents exceeding the HIBP rate
    limit (~10 req/min).

    Args:
        domain: The domain name to check (e.g. ``"example.com"``).
        api_key: A valid HIBP v3 API key (``hibp-api-key`` header).
        throttle_delay: Minimum seconds between consecutive HIBP
            requests.  Defaults to 6.0 (safe for the ~10 req/min
            limit).  Set to 0 to disable throttling.

    Returns:
        A dict with keys:
            breaches (list[dict]): List of breach dicts, each containing
                ``name``, ``date``, ``data_classes``, ``pwn_count``, and
                ``description``.
            total_breaches (int): Number of breaches found.
            error (str|None): Error message if the lookup failed,
                ``None`` on success.
    """
    if not api_key:
        logger.warning("HIBP check skipped for %s: no API key provided", domain)
        return {**_EMPTY_RESULT, "error": "No HIBP API key provided"}

    if throttle_delay > 0:
        _throttle_wait(throttle_delay)

    try:
        return _do_hibp_request(domain, api_key)
    except Exception as exc:
        logger.error(
            "Unexpected error during HIBP check for %s: %s",
            domain, exc, exc_info=True,
        )
        return {**_EMPTY_RESULT, "error": f"Unexpected error: {exc}"}
