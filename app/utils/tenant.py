"""
F47 - Tenant context middleware.

Sets g.current_org from the authenticated user's organization.
Provides helper functions for accessing the current tenant context.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from flask import g, session
from flask_login import current_user

if TYPE_CHECKING:
    from app.models import DnsSettings, Organization

logger = logging.getLogger(__name__)

# Routes that should bypass tenant context (unauthenticated or system routes)
_BYPASS_ENDPOINTS = (
    "auth.login",
    "auth.logout",
    "auth.forgot_password",
    "auth.reset_password",
    "api.health",
    "static",
)


def set_current_org() -> None:
    """before_request hook: set g.current_org from current_user.org.

    Skips tenant context for auth routes, static files, and
    unauthenticated requests.
    Superadmin can override via session['admin_org_override'].
    """
    g.current_org = None
    g.current_org_id = None

    if not current_user.is_authenticated:
        return

    from flask import request

    # Skip for bypass endpoints
    if request.endpoint and any(
        request.endpoint.startswith(ep) for ep in _BYPASS_ENDPOINTS
    ):
        return

    # Superadmin org override
    if hasattr(current_user, "is_superadmin") and current_user.is_superadmin:
        override_org_id = session.get("admin_org_override")
        if override_org_id:
            from app import db
            from app.models import Organization

            org = db.session.get(Organization, override_org_id)
            if org:
                g.current_org = org
                g.current_org_id = org.id
                return

    # Standard: use user's own org
    if current_user.org_id:
        from app import db
        from app.models import Organization

        org = db.session.get(Organization, current_user.org_id)
        if org:
            g.current_org = org
            g.current_org_id = org.id


def get_current_org() -> Organization | None:
    """Get current organization from Flask g."""
    return getattr(g, "current_org", None)


def get_current_org_id() -> int | None:
    """Get current org_id from Flask g."""
    return getattr(g, "current_org_id", None)


def get_org_settings(org_id: int | None = None) -> DnsSettings:
    """Get per-org DnsSettings, falling back to global (org_id=NULL).

    Lookup order:
      1. If *org_id* is not None, try to find a DnsSettings row with that org_id.
      2. If no org-specific row exists (or org_id is None), return the global
         row where org_id IS NULL.
      3. If no global row exists either, return a detached DnsSettings instance
         with default values (caller should add to session if persistence is needed).

    Args:
        org_id: Organization id to look up settings for.  When called from a
                request context, pass ``get_current_org_id()``.  When called
                from the checker engine, pass ``domain.org_id``.

    Returns:
        A DnsSettings instance (may be transient if no rows exist yet).
    """
    from app import db
    from app.models import DnsSettings

    # 1. Try org-specific settings
    if org_id is not None:
        org_settings = db.session.execute(
            db.select(DnsSettings).where(DnsSettings.org_id == org_id)
        ).scalars().first()
        if org_settings is not None:
            return org_settings

    # 2. Fall back to global default (org_id IS NULL)
    global_settings = db.session.execute(
        db.select(DnsSettings).where(DnsSettings.org_id.is_(None))
    ).scalars().first()
    if global_settings is not None:
        return global_settings

    # 3. No rows at all - return transient defaults
    return DnsSettings()
