"""
F39 - Role-based access control decorators.

Provides decorators to restrict route access based on user roles:
  @superadmin_required  - superadmin only
  @admin_required       - superadmin + admin
  @editor_required      - superadmin + admin + editor
  @login_required       - all authenticated users (existing Flask-Login)
"""

from __future__ import annotations

from functools import wraps
from typing import Callable

from flask import abort
from flask_login import current_user, login_required


def superadmin_required(f: Callable) -> Callable:
    """Restrict access to superadmin users only."""
    @wraps(f)
    @login_required
    def decorated_view(*args, **kwargs):
        if not current_user.is_superadmin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_view


def admin_required(f: Callable) -> Callable:
    """Restrict access to admin and superadmin users."""
    @wraps(f)
    @login_required
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_view


def editor_required(f: Callable) -> Callable:
    """Restrict access to editor, admin, and superadmin users."""
    @wraps(f)
    @login_required
    def decorated_view(*args, **kwargs):
        if not current_user.is_editor:
            abort(403)
        return f(*args, **kwargs)
    return decorated_view
