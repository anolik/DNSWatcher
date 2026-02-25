"""
F33 - Simple in-memory rate limiter for MVP.

Tracks the last time a check was triggered per domain ID using a plain dict.
No external dependencies (no Redis, no Celery) - intentionally lightweight
for a single-process PythonAnywhere deployment.

Thread safety note:
  PythonAnywhere free/hacker plans run one Python worker process.  A plain
  dict is therefore safe.  If the application is ever scaled to multiple
  workers, replace this module with a shared cache (e.g. Redis or a database
  table) and the public interface can stay the same.

Usage:
    from app.utils.rate_limit import is_rate_limited

    # Inside a Flask route:
    if is_rate_limited("domain", domain_id):
        flash("Please wait before checking this domain again.", "warning")
        return redirect(...)

    if is_rate_limited("all", 0):
        flash("Please wait before running a full check.", "warning")
        return redirect(...)
"""

from __future__ import annotations

import logging
import time
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum seconds that must elapse between two checks of the same target.
_RATE_LIMIT_SECONDS: Final[int] = 60

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

# Keys are (scope, entity_id) tuples; values are the monotonic timestamp of
# the last allowed request.
#
# Example entries:
#   ("domain", 42) -> 1_700_000_000.0
#   ("all",     0) -> 1_700_000_100.0
_last_check_times: dict[tuple[str, int], float] = {}


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def is_rate_limited(scope: str, entity_id: int) -> bool:
    """Return True if the caller should be rate-limited (i.e. too soon).

    When the caller is *not* rate-limited this function also records the
    current time as the new "last allowed" timestamp.

    Args:
        scope:     Logical grouping key (e.g. "domain" or "all").
        entity_id: Numeric entity identifier (domain PK, or 0 for global).

    Returns:
        True  - the last check was within the rate-limit window; block it.
        False - enough time has passed; the check is allowed.
    """
    key = (scope, entity_id)
    now = time.monotonic()

    last = _last_check_times.get(key)
    if last is not None:
        elapsed = now - last
        if elapsed < _RATE_LIMIT_SECONDS:
            remaining = int(_RATE_LIMIT_SECONDS - elapsed)
            logger.warning(
                "Rate limit active: scope=%r entity_id=%d elapsed=%.1fs remaining=%ds",
                scope,
                entity_id,
                elapsed,
                remaining,
            )
            return True

    # Allow - update the stored timestamp.
    _last_check_times[key] = now
    return False


def reset_rate_limit(scope: str, entity_id: int) -> None:
    """Clear the rate-limit record for a specific target.

    Primarily useful in tests to avoid cross-test interference.

    Args:
        scope:     Same scope string used in is_rate_limited().
        entity_id: Same entity id used in is_rate_limited().
    """
    _last_check_times.pop((scope, entity_id), None)


def clear_all_rate_limits() -> None:
    """Remove all rate-limit records.

    Useful in tests or when a server restarts (the dict is already empty
    after a process restart, so this is mainly for test isolation).
    """
    _last_check_times.clear()
