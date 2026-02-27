"""
F15 - Anti-flap logic for DNS check results.

Prevents transient DNS errors from immediately triggering critical alerts.
When a check fails, consecutive_failures is incremented. The raw critical
status is capped to "warning" until the failure count reaches the
configured flap_threshold (from DnsSettings). Once the threshold is met,
the full critical status is allowed through.

On success, the counter resets to zero.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app import db
from app.models import DnsSettings, FlapState

logger = logging.getLogger(__name__)


def apply_flap_logic(
    domain_id: int,
    check_type: str,
    raw_status: str,
    settings: DnsSettings | None = None,
) -> str:
    """Apply anti-flap logic to a check result.

    Args:
        domain_id: The domain ID the check was performed on.
        check_type: The type of check ("spf", "dmarc", "dkim", "reputation").
        raw_status: The raw status from the checker ("ok", "warning", "critical", "error").
        settings: Optional DnsSettings instance to read the flap_threshold from.
            When provided, avoids an extra database query.  When None, falls
            back to loading the global settings via ``get_org_settings(None)``.

    Returns:
        The adjusted status after applying flap logic. A "critical" or "error"
        status is capped to "warning" until consecutive failures reach the
        configured flap_threshold.
    """
    now = datetime.now(timezone.utc)

    # Load or create FlapState for this domain/check_type
    flap_state = FlapState.query.filter_by(
        domain_id=domain_id,
        check_type=check_type,
    ).first()

    if flap_state is None:
        flap_state = FlapState(
            domain_id=domain_id,
            check_type=check_type,
            consecutive_failures=0,
        )
        db.session.add(flap_state)

    # Load threshold from DnsSettings (prefer caller-provided settings)
    if settings is None:
        from app.utils.tenant import get_org_settings  # noqa: PLC0415
        settings = get_org_settings(None)
    threshold = settings.flap_threshold if settings else 2

    # Determine if this is a success or failure
    if raw_status in ("ok", "warning"):
        # Success path: reset failure counter
        if flap_state.consecutive_failures > 0:
            logger.info(
                "Anti-flap reset for domain_id=%d check_type=%s "
                "(was at %d consecutive failures)",
                domain_id,
                check_type,
                flap_state.consecutive_failures,
            )
        flap_state.consecutive_failures = 0
        flap_state.last_success_at = now
        return raw_status

    # Failure path: critical or error
    flap_state.consecutive_failures += 1
    flap_state.last_failure_at = now

    if flap_state.consecutive_failures < threshold:
        logger.info(
            "Anti-flap cap for domain_id=%d check_type=%s: "
            "raw_status=%s capped to warning (failures=%d/%d)",
            domain_id,
            check_type,
            raw_status,
            flap_state.consecutive_failures,
            threshold,
        )
        return "warning"

    # Threshold reached or exceeded: allow full status through
    logger.warning(
        "Anti-flap threshold reached for domain_id=%d check_type=%s: "
        "consecutive_failures=%d >= threshold=%d, returning raw_status=%s",
        domain_id,
        check_type,
        flap_state.consecutive_failures,
        threshold,
        raw_status,
    )
    return raw_status
