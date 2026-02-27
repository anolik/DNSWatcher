"""Admin blueprint routes for user and organization management."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from werkzeug.security import generate_password_hash

from app import db
from app.admin import bp
from app.admin.forms import CreateOrgForm, CreateUserForm, EditOrgForm, EditUserForm
from app.models import Domain, Organization, User
from app.utils.auth import admin_required, superadmin_required

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Slug helper
# ---------------------------------------------------------------------------

def _slugify(text: str) -> str:
    """Convert a human-readable name into a URL-safe slug.

    Lowercases the text, replaces whitespace and non-alphanumeric characters
    with hyphens, collapses consecutive hyphens, and strips leading/trailing
    hyphens.

    Args:
        text: The input string to slugify.

    Returns:
        A lowercase slug suitable for URL paths.
    """
    slug = text.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")


# ===================================================================
# User Management Routes
# ===================================================================


@bp.route("/users")
@admin_required
def users():
    """List users - scoped by org for admin, all for superadmin."""
    if current_user.is_superadmin:
        user_list = db.session.execute(
            db.select(User).order_by(User.username)
        ).scalars().all()
    else:
        user_list = db.session.execute(
            db.select(User).where(User.org_id == current_user.org_id).order_by(User.username)
        ).scalars().all()

    return render_template("admin/users.html", users=user_list)


@bp.route("/users/new", methods=["GET", "POST"])
@admin_required
def create_user():
    """Create a new user."""
    form = CreateUserForm()
    _populate_org_choices(form)

    # Non-superadmin can only create viewer/editor roles in own org
    if not current_user.is_superadmin:
        form.role.choices = [("viewer", "Viewer"), ("editor", "Editor")]
        form.org_id.data = current_user.org_id

    if form.validate_on_submit():
        # Check uniqueness
        if db.session.execute(db.select(User).where(User.username == form.username.data)).scalars().first():
            flash("Username already exists.", "danger")
        elif db.session.execute(db.select(User).where(User.email == form.email.data)).scalars().first():
            flash("Email already in use.", "danger")
        else:
            # Non-superadmin forced to own org
            org_id = form.org_id.data if current_user.is_superadmin else current_user.org_id

            user = User(
                username=form.username.data,
                password_hash=generate_password_hash(form.password.data),
                email=form.email.data,
                full_name=form.full_name.data or None,
                role=form.role.data,
                org_id=org_id if org_id else None,
                is_active=True,
            )
            db.session.add(user)
            db.session.commit()
            logger.info("User created: username=%r role=%r by=%r", user.username, user.role, current_user.username)

            # F44: Send welcome email if user has an email address
            if user.email:
                from app.utils.email import send_email

                login_url = url_for("auth.login", _external=True)
                sent = send_email(
                    to=user.email,
                    subject="Welcome to DNS Watcher",
                    html_body=render_template(
                        "email/welcome.html", user=user, login_url=login_url,
                    ),
                    text_body=render_template(
                        "email/welcome.txt", user=user, login_url=login_url,
                    ),
                )
                if sent:
                    logger.info("Welcome email sent to %r for user %r", user.email, user.username)
                else:
                    logger.warning("Welcome email not sent to %r for user %r", user.email, user.username)

            flash(f"User '{user.username}' created successfully.", "success")
            return redirect(url_for("admin.users"))

    return render_template("admin/user_form.html", form=form, is_edit=False)


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_user(user_id: int):
    """Edit an existing user."""
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)

    # Org-admin can only edit users in own org
    if not current_user.is_superadmin and user.org_id != current_user.org_id:
        abort(403)

    form = EditUserForm(obj=user)
    _populate_org_choices(form)

    if not current_user.is_superadmin:
        form.role.choices = [("viewer", "Viewer"), ("editor", "Editor")]

    if form.validate_on_submit():
        # Check email uniqueness
        existing = db.session.execute(
            db.select(User).where(User.email == form.email.data, User.id != user.id)
        ).scalars().first()
        if existing:
            flash("Email already in use.", "danger")
        else:
            # Safety: cannot downgrade own role
            if user.id == current_user.id and form.role.data != current_user.role:
                flash("You cannot change your own role.", "warning")
            else:
                # Safety: cannot deactivate last superadmin
                if user.role == "superadmin" and not form.is_active.data:
                    superadmin_count = db.session.execute(
                        db.select(db.func.count(User.id)).where(
                            User.role == "superadmin", User.is_active == True, User.id != user.id  # noqa: E712
                        )
                    ).scalar()
                    if superadmin_count == 0:
                        flash("Cannot deactivate the last superadmin.", "danger")
                        return render_template("admin/user_form.html", form=form, is_edit=True, user=user)

                user.email = form.email.data
                user.full_name = form.full_name.data or None
                user.role = form.role.data if current_user.is_superadmin or form.role.data in ("viewer", "editor") else user.role
                user.org_id = form.org_id.data if current_user.is_superadmin and form.org_id.data else user.org_id
                user.is_active = form.is_active.data
                user.updated_at = datetime.now(timezone.utc)
                db.session.commit()
                logger.info("User edited: username=%r by=%r", user.username, current_user.username)
                flash(f"User '{user.username}' updated.", "success")
                return redirect(url_for("admin.users"))

    return render_template("admin/user_form.html", form=form, is_edit=True, user=user)


@bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_user_active(user_id: int):
    """Toggle user active status."""
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)

    if not current_user.is_superadmin and user.org_id != current_user.org_id:
        abort(403)

    # Cannot deactivate self
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("admin.users"))

    # Cannot deactivate last superadmin
    if user.role == "superadmin" and user.is_active:
        superadmin_count = db.session.execute(
            db.select(db.func.count(User.id)).where(
                User.role == "superadmin", User.is_active == True, User.id != user.id  # noqa: E712
            )
        ).scalar()
        if superadmin_count == 0:
            flash("Cannot deactivate the last superadmin.", "danger")
            return redirect(url_for("admin.users"))

    user.is_active = not user.is_active
    user.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    state = "activated" if user.is_active else "deactivated"
    logger.info("User %s: username=%r by=%r", state, user.username, current_user.username)

    # F44: Send deactivation email notification
    if not user.is_active and user.email:
        from app.utils.email import send_email

        sent = send_email(
            to=user.email,
            subject="Account Deactivated - DNS Watcher",
            html_body=render_template("email/account_deactivated.html", user=user),
            text_body=render_template("email/account_deactivated.txt", user=user),
        )
        if sent:
            logger.info("Deactivation email sent to %r for user %r", user.email, user.username)
        else:
            logger.warning("Deactivation email not sent to %r for user %r", user.email, user.username)

    flash(f"User '{user.username}' has been {state}.", "info")
    return redirect(url_for("admin.users"))


def _populate_org_choices(form):
    """Populate org_id choices for the form."""
    orgs = db.session.execute(
        db.select(Organization).where(Organization.is_active == True).order_by(Organization.name)  # noqa: E712
    ).scalars().all()
    form.org_id.choices = [(0, "\u2014 No Organization \u2014")] + [(o.id, o.name) for o in orgs]


# ===================================================================
# Organization Management Routes (superadmin only)
# ===================================================================


@bp.route("/orgs")
@superadmin_required
def orgs():
    """List all organizations with user and domain counts."""
    org_list = db.session.execute(
        db.select(Organization).order_by(Organization.name)
    ).scalars().all()

    # Build user and domain counts per org
    org_stats: dict[int, dict[str, int]] = {}
    for org in org_list:
        user_count = db.session.execute(
            db.select(db.func.count(User.id)).where(User.org_id == org.id)
        ).scalar() or 0
        domain_count = db.session.execute(
            db.select(db.func.count(Domain.id)).where(Domain.org_id == org.id)
        ).scalar() or 0
        org_stats[org.id] = {"users": user_count, "domains": domain_count}

    return render_template("admin/orgs.html", orgs=org_list, org_stats=org_stats)


@bp.route("/orgs/new", methods=["GET", "POST"])
@superadmin_required
def create_org():
    """Create a new organization."""
    form = CreateOrgForm()

    if request.method == "GET" and not form.slug.data:
        form.slug.data = ""

    if form.validate_on_submit():
        slug = form.slug.data.strip()
        if not slug:
            slug = _slugify(form.name.data)
        else:
            slug = _slugify(slug)

        # Check name uniqueness
        if db.session.execute(
            db.select(Organization).where(Organization.name == form.name.data)
        ).scalars().first():
            flash("An organization with this name already exists.", "danger")
        elif db.session.execute(
            db.select(Organization).where(Organization.slug == slug)
        ).scalars().first():
            flash(f"The slug '{slug}' is already in use.", "danger")
        else:
            org = Organization(
                name=form.name.data.strip(),
                slug=slug,
                max_domains=form.max_domains.data,
                notes=form.notes.data or None,
                is_active=True,
                created_by=current_user.id,
            )
            db.session.add(org)
            db.session.commit()
            logger.info(
                "Organization created: name=%r slug=%r by=%r",
                org.name, org.slug, current_user.username,
            )
            flash(f"Organization '{org.name}' created successfully.", "success")
            return redirect(url_for("admin.orgs"))

    return render_template("admin/org_form.html", form=form, is_edit=False)


@bp.route("/orgs/<int:org_id>/edit", methods=["GET", "POST"])
@superadmin_required
def edit_org(org_id: int):
    """Edit an existing organization."""
    org = db.session.get(Organization, org_id)
    if org is None:
        abort(404)

    form = EditOrgForm(obj=org)

    if form.validate_on_submit():
        # Safety: cannot deactivate the Default organization
        if org.slug == "default" and not form.is_active.data:
            flash("The Default organization cannot be deactivated.", "danger")
            return render_template("admin/org_form.html", form=form, is_edit=True, org=org)

        # Check name uniqueness (excluding self)
        existing_name = db.session.execute(
            db.select(Organization).where(
                Organization.name == form.name.data, Organization.id != org.id
            )
        ).scalars().first()
        if existing_name:
            flash("An organization with this name already exists.", "danger")
        else:
            org.name = form.name.data.strip()
            org.max_domains = form.max_domains.data
            org.notes = form.notes.data or None
            org.is_active = form.is_active.data
            db.session.commit()
            logger.info(
                "Organization edited: name=%r slug=%r by=%r",
                org.name, org.slug, current_user.username,
            )
            flash(f"Organization '{org.name}' updated.", "success")
            return redirect(url_for("admin.orgs"))

    return render_template("admin/org_form.html", form=form, is_edit=True, org=org)


@bp.route("/orgs/<int:org_id>/toggle-active", methods=["POST"])
@superadmin_required
def toggle_org_active(org_id: int):
    """Toggle organization active status."""
    org = db.session.get(Organization, org_id)
    if org is None:
        abort(404)

    # Safety: cannot deactivate the Default organization
    if org.slug == "default" and org.is_active:
        flash("The Default organization cannot be deactivated.", "danger")
        return redirect(url_for("admin.orgs"))

    org.is_active = not org.is_active
    db.session.commit()

    state = "activated" if org.is_active else "deactivated"
    logger.info("Organization %s: name=%r by=%r", state, org.name, current_user.username)
    flash(f"Organization '{org.name}' has been {state}.", "info")
    return redirect(url_for("admin.orgs"))
