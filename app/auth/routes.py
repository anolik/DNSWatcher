"""
F05 - Routes for the authentication blueprint.

Handles user login / logout and registers the Flask-Login user_loader.
"""

from __future__ import annotations

import logging

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db, login_manager
from app.auth import bp
from app.auth.forms import LoginForm
from app.models import User

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Flask-Login user loader
# ---------------------------------------------------------------------------


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    """Load a User by primary key; returns None if not found or inactive."""
    try:
        uid = int(user_id)
    except (ValueError, TypeError):
        return None
    user = db.session.get(User, uid)
    if user is None or not user.is_active:
        return None
    return user


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Render the login page and authenticate submitted credentials."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        # Log the username only - never log the password.
        submitted_username = form.username.data or ""
        user: User | None = (
            db.session.execute(
                db.select(User).where(User.username == submitted_username)
            )
            .scalars()
            .first()
        )
        if user is not None and user.is_active and user.check_password(form.password.data):
            login_user(user, remember=False)
            logger.info("Login successful: username=%r ip=%s", submitted_username, request.remote_addr)
            next_page: str | None = request.args.get("next")
            # Basic open-redirect guard: only follow relative paths.
            if next_page and not next_page.startswith("/"):
                next_page = None
            return redirect(next_page or url_for("dashboard.index"))

        logger.warning(
            "Login failed: username=%r ip=%s (bad credentials or inactive account)",
            submitted_username,
            request.remote_addr,
        )
        flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html", form=form)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@bp.route("/logout")
@login_required
def logout():
    """Log the current user out and redirect to the login page."""
    logger.info("Logout: username=%r ip=%s", current_user.username, request.remote_addr)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
