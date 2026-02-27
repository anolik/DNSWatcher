"""
F05 - Routes for the authentication blueprint.

Handles user login / logout / profile and registers the Flask-Login user_loader.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db, login_manager
from app.auth import bp
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.auth.forms import ChangePasswordForm, ForgotPasswordForm, LoginForm, ProfileForm, ResetPasswordForm
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
            user.last_login_at = datetime.now(timezone.utc)
            db.session.commit()
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


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """View and edit user profile."""
    form = ProfileForm(obj=current_user)
    password_form = ChangePasswordForm()

    if form.validate_on_submit():
        # Check email uniqueness
        existing = db.session.execute(
            db.select(User).where(User.email == form.email.data, User.id != current_user.id)
        ).scalars().first()
        if existing:
            flash("This email is already in use.", "danger")
        else:
            current_user.full_name = form.full_name.data
            current_user.email = form.email.data
            current_user.language = form.language.data
            current_user.updated_at = datetime.now(timezone.utc)
            db.session.commit()
            flash("Profile updated successfully.", "success")
            return redirect(url_for("auth.profile"))

    return render_template("auth/profile.html", form=form, password_form=password_form)


@bp.route("/profile/change-password", methods=["POST"])
@login_required
def change_password():
    """Change the current user's password."""
    password_form = ChangePasswordForm()

    if password_form.validate_on_submit():
        if not current_user.check_password(password_form.current_password.data):
            flash("Current password is incorrect.", "danger")
        else:
            current_user.set_password(password_form.new_password.data)
            current_user.updated_at = datetime.now(timezone.utc)
            db.session.commit()
            logger.info("Password changed: username=%r ip=%s", current_user.username, request.remote_addr)

            # F44: Send password change confirmation email
            if current_user.email:
                from app.utils.email import send_email

                sent = send_email(
                    to=current_user.email,
                    subject="Password Changed - DNS Watcher",
                    html_body=render_template(
                        "email/password_changed.html", user=current_user,
                    ),
                    text_body=render_template(
                        "email/password_changed.txt", user=current_user,
                    ),
                )
                if sent:
                    logger.info("Password change email sent to %r for user %r", current_user.email, current_user.username)
                else:
                    logger.warning("Password change email not sent to %r for user %r", current_user.email, current_user.username)

            flash("Password changed successfully.", "success")
            return redirect(url_for("auth.profile"))
    else:
        for field, errors in password_form.errors.items():
            for error in errors:
                flash(error, "danger")

    form = ProfileForm(obj=current_user)
    return render_template("auth/profile.html", form=form, password_form=password_form)


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


def _get_reset_serializer() -> URLSafeTimedSerializer:
    """Get the timed serializer for password reset tokens."""
    from flask import current_app

    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Request a password reset email."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        # Rate limit: one reset request per email per 60 seconds
        from app.utils.rate_limit import is_rate_limited

        rate_key = hash(email) % 1_000_000
        if is_rate_limited("reset", rate_key):
            logger.warning(
                "Password reset rate limited: email=%r ip=%s",
                email, request.remote_addr,
            )
        else:
            user = db.session.execute(
                db.select(User).where(User.email == email, User.is_active == True)  # noqa: E712
            ).scalars().first()

            if user:
                # Generate token
                s = _get_reset_serializer()
                token = s.dumps(
                    {"user_id": user.id, "purpose": "reset"},
                    salt="password-reset",
                )
                reset_url = url_for("auth.reset_password", token=token, _external=True)

                logger.info(
                    "Password reset requested: email=%r user_id=%d ip=%s",
                    email, user.id, request.remote_addr,
                )

                # Try to send email
                from app.utils.email import send_email

                sent = send_email(
                    to=user.email,
                    subject="Password Reset - DNS Watcher",
                    html_body=render_template(
                        "email/reset_password.html", user=user, reset_url=reset_url,
                    ),
                    text_body=render_template(
                        "email/reset_password.txt", user=user, reset_url=reset_url,
                    ),
                )

                if not sent:
                    # Dev mode: show the URL in a flash message
                    flash(f"[DEV] Reset URL: {reset_url}", "info")
            else:
                logger.info(
                    "Password reset for unknown email: email=%r ip=%s",
                    email, request.remote_addr,
                )

        # Always show generic success message (prevent email enumeration)
        flash(
            "If an account with that email exists, a reset link has been sent.",
            "info",
        )
        return redirect(url_for("auth.forgot_password"))

    return render_template("auth/forgot_password.html", form=form)


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    """Validate token and allow setting a new password."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    s = _get_reset_serializer()
    try:
        data = s.loads(token, salt="password-reset", max_age=3600)
    except SignatureExpired:
        flash("This reset link has expired. Please request a new one.", "warning")
        return redirect(url_for("auth.forgot_password"))
    except BadSignature:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("auth.forgot_password"))

    user = db.session.get(User, data.get("user_id"))
    if user is None or not user.is_active:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("auth.forgot_password"))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        user.set_password(form.new_password.data)
        user.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(
            "Password reset completed: user_id=%d ip=%s",
            user.id, request.remote_addr,
        )
        flash("Your password has been reset. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", form=form, token=token)
