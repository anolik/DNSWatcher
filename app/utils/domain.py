"""Shared domain creation utility."""
from __future__ import annotations

from app import db
from app.models import DkimSelector, Domain

DEFAULT_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "dkim",
    "mail",
    "s1",
    "s2",
    "protonmail",
]


def create_domain_with_selectors(
    hostname: str, user_id: int | None, org_id: int | None
) -> Domain:
    """Create a Domain row plus default DkimSelector rows.

    Args:
        hostname: The domain hostname to create.
        user_id: The ID of the user creating this domain.
        org_id: The organization ID to assign this domain to.

    Returns:
        The newly created Domain instance.
    """
    domain = Domain(
        hostname=hostname, added_by=user_id, org_id=org_id, current_status="pending"
    )
    db.session.add(domain)
    db.session.flush()

    for sel_name in DEFAULT_SELECTORS:
        db.session.add(
            DkimSelector(domain_id=domain.id, selector=sel_name, is_active=True)
        )

    return domain
