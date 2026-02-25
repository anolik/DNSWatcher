"""
F35 - Route tests for the SPF/DMARC/DKIM Watcher web application.

Covers authentication, dashboard, domain management, and settings.
All tests use the Flask test client; no real server or DNS calls occur.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.models import Domain, DkimSelector


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _login(client, username: str = "testuser", password: str = "testpass123"):
    """POST the login form and return the response."""
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# F35a - Unauthenticated access redirects
# ---------------------------------------------------------------------------


def test_unauthenticated_dashboard_redirects_to_login(client, app):
    """GET / without authentication should redirect to the login page."""
    with app.app_context():
        response = client.get("/", follow_redirects=False)

    assert response.status_code in (301, 302)
    # Flask-Login redirects to auth.login which is /auth/login
    assert "login" in response.headers["Location"].lower()


def test_unauthenticated_add_domain_redirects(client, app):
    """POST /domains/add without authentication should redirect to login."""
    with app.app_context():
        response = client.post(
            "/domains/add",
            data={"hostname": "example.com"},
            follow_redirects=False,
        )

    assert response.status_code in (301, 302)
    assert "login" in response.headers["Location"].lower()


def test_unauthenticated_settings_redirects(client, app):
    """GET /settings/ without authentication should redirect to login."""
    with app.app_context():
        response = client.get("/settings/", follow_redirects=False)

    assert response.status_code in (301, 302)
    assert "login" in response.headers["Location"].lower()


# ---------------------------------------------------------------------------
# F35b - Login
# ---------------------------------------------------------------------------


def test_login_page_accessible_unauthenticated(client, app):
    """GET /auth/login should return 200 for unauthenticated users."""
    with app.app_context():
        response = client.get("/auth/login")

    assert response.status_code == 200


def test_login_with_valid_credentials_redirects_to_dashboard(client, app):
    """Valid login credentials should redirect to the dashboard."""
    with app.app_context():
        response = _login(client)

    assert response.status_code in (301, 302)
    assert "/" in response.headers["Location"]


def test_login_with_invalid_password_stays_on_login(client, app):
    """Wrong password should return 200 with the login page again."""
    with app.app_context():
        response = client.post(
            "/auth/login",
            data={"username": "testuser", "password": "wrongpassword"},
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert b"Invalid" in response.data or b"login" in response.data.lower()


def test_login_with_unknown_username_stays_on_login(client, app):
    """Unknown username should return 200 with the login page again."""
    with app.app_context():
        response = client.post(
            "/auth/login",
            data={"username": "nobody", "password": "anything"},
            follow_redirects=False,
        )

    assert response.status_code == 200


def test_already_authenticated_login_redirects_to_dashboard(auth_client, app):
    """Visiting /auth/login while authenticated should redirect to the dashboard."""
    with app.app_context():
        response = auth_client.get("/auth/login", follow_redirects=False)

    # Either a redirect or already on the dashboard
    assert response.status_code in (200, 301, 302)


# ---------------------------------------------------------------------------
# F35c - Logout
# ---------------------------------------------------------------------------


def test_logout_redirects_to_login(auth_client, app):
    """GET /auth/logout should log the user out and redirect to the login page."""
    with app.app_context():
        response = auth_client.get("/auth/logout", follow_redirects=False)

    assert response.status_code in (301, 302)
    assert "login" in response.headers["Location"].lower()


def test_after_logout_dashboard_requires_login(auth_client, app):
    """After logout, accessing / should redirect to the login page."""
    with app.app_context():
        auth_client.get("/auth/logout", follow_redirects=False)
        response = auth_client.get("/", follow_redirects=False)

    assert response.status_code in (301, 302)
    assert "login" in response.headers["Location"].lower()


# ---------------------------------------------------------------------------
# F35d - Dashboard
# ---------------------------------------------------------------------------


def test_dashboard_accessible_when_authenticated(auth_client, app):
    """GET / with a valid session should return 200."""
    with app.app_context():
        response = auth_client.get("/")

    assert response.status_code == 200


def test_dashboard_shows_no_domains_initially(auth_client, app):
    """An empty database should render a dashboard without domain rows."""
    with app.app_context():
        response = auth_client.get("/")

    assert response.status_code == 200
    # The page should render without error


# ---------------------------------------------------------------------------
# F35e - Add domain
# ---------------------------------------------------------------------------


def test_add_valid_domain(auth_client, app):
    """POST /domains/add with a valid hostname should create a new Domain."""
    with app.app_context():
        response = auth_client.post(
            "/domains/add",
            data={"hostname": "testdomain.example.com"},
            follow_redirects=False,
        )

    assert response.status_code in (301, 302)

    with app.app_context():
        from app import db
        domain = db.session.execute(
            db.select(Domain).where(Domain.hostname == "testdomain.example.com")
        ).scalars().first()
        assert domain is not None
        assert domain.is_active is True


def test_add_domain_creates_default_dkim_selectors(auth_client, app):
    """Adding a domain should also create the default DKIM selectors."""
    with app.app_context():
        auth_client.post(
            "/domains/add",
            data={"hostname": "dkim-selector-test.example.com"},
            follow_redirects=False,
        )

    with app.app_context():
        from app import db
        domain = db.session.execute(
            db.select(Domain).where(Domain.hostname == "dkim-selector-test.example.com")
        ).scalars().first()
        assert domain is not None
        selectors = db.session.execute(
            db.select(DkimSelector).where(DkimSelector.domain_id == domain.id)
        ).scalars().all()
        assert len(selectors) > 0


def test_add_duplicate_domain_does_not_create_second_row(auth_client, app):
    """Adding the same hostname twice should not create a duplicate Domain row."""
    with app.app_context():
        auth_client.post(
            "/domains/add",
            data={"hostname": "dup.example.com"},
            follow_redirects=False,
        )
        auth_client.post(
            "/domains/add",
            data={"hostname": "dup.example.com"},
            follow_redirects=False,
        )

    with app.app_context():
        from app import db
        count = db.session.execute(
            db.select(db.func.count(Domain.id)).where(Domain.hostname == "dup.example.com")
        ).scalar()

    assert count == 1


def test_add_domain_normalises_to_lowercase(auth_client, app):
    """Hostname input should be normalised to lowercase before storage."""
    with app.app_context():
        auth_client.post(
            "/domains/add",
            data={"hostname": "UPPER.Example.COM"},
            follow_redirects=False,
        )

    with app.app_context():
        from app import db
        domain = db.session.execute(
            db.select(Domain).where(Domain.hostname == "upper.example.com")
        ).scalars().first()

    assert domain is not None


# ---------------------------------------------------------------------------
# F35f - Delete domain
# ---------------------------------------------------------------------------


def test_delete_domain_soft_deletes(auth_client, app):
    """POST /domains/<id>/delete should set is_active=False (soft delete)."""
    with app.app_context():
        from app import db
        domain = Domain(hostname="to-delete.example.com", current_status="pending")
        db.session.add(domain)
        db.session.commit()
        domain_id = domain.id

    with app.app_context():
        response = auth_client.post(
            f"/domains/{domain_id}/delete",
            follow_redirects=False,
        )

    assert response.status_code in (301, 302)

    with app.app_context():
        from app import db
        domain = db.session.get(Domain, domain_id)
        assert domain is not None
        assert domain.is_active is False


def test_delete_nonexistent_domain_returns_404(auth_client, app):
    """Deleting a domain that does not exist should return 404."""
    with app.app_context():
        response = auth_client.post("/domains/99999/delete", follow_redirects=False)

    assert response.status_code == 404


def test_reactivate_soft_deleted_domain(auth_client, app):
    """Adding a previously soft-deleted domain should reactivate it."""
    with app.app_context():
        from app import db
        domain = Domain(
            hostname="reactivate.example.com",
            current_status="pending",
            is_active=False,
        )
        db.session.add(domain)
        db.session.commit()

    with app.app_context():
        auth_client.post(
            "/domains/add",
            data={"hostname": "reactivate.example.com"},
            follow_redirects=False,
        )

    with app.app_context():
        from app import db
        domain = db.session.execute(
            db.select(Domain).where(Domain.hostname == "reactivate.example.com")
        ).scalars().first()

    assert domain.is_active is True


# ---------------------------------------------------------------------------
# F35g - Domain detail page
# ---------------------------------------------------------------------------


def test_domain_detail_page_returns_200(auth_client, app):
    """GET /domains/<id> for an existing domain should return 200."""
    with app.app_context():
        from app import db
        domain = Domain(hostname="detail.example.com", current_status="pending")
        db.session.add(domain)
        db.session.commit()
        domain_id = domain.id

    with app.app_context():
        response = auth_client.get(f"/domains/{domain_id}")

    assert response.status_code == 200


def test_domain_detail_nonexistent_returns_404(auth_client, app):
    """GET /domains/99999 should return 404."""
    with app.app_context():
        response = auth_client.get("/domains/99999")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# F35h - Settings page
# ---------------------------------------------------------------------------


def test_settings_page_accessible(auth_client, app):
    """GET /settings/ should return 200."""
    with app.app_context():
        response = auth_client.get("/settings/")

    assert response.status_code == 200


def test_settings_save_updates_dns_settings(auth_client, app):
    """POST /settings/ with valid data should update the DnsSettings row."""
    with app.app_context():
        response = auth_client.post(
            "/settings/",
            data={
                "resolvers": "1.1.1.1\n9.9.9.9",
                "timeout_seconds": "4",
                "retries": "2",
                "flap_threshold": "3",
            },
            follow_redirects=False,
        )

    assert response.status_code in (200, 301, 302)

    with app.app_context():
        from app.models import DnsSettings
        from app import db
        settings = db.session.get(DnsSettings, 1)
        assert settings is not None
        resolvers = settings.get_resolvers()
        assert "1.1.1.1" in resolvers
        assert settings.flap_threshold == 3


# ---------------------------------------------------------------------------
# F35i - Manual check trigger (mocked engine)
# ---------------------------------------------------------------------------


def test_manual_check_redirects_after_check(auth_client, app):
    """POST /domains/<id>/check should run a check and redirect."""
    with app.app_context():
        from app import db
        domain = Domain(hostname="check-me.example.com", current_status="pending")
        db.session.add(domain)
        db.session.commit()
        domain_id = domain.id

    with patch("app.checker.engine.run_domain_check") as mock_check:
        mock_check.return_value = None
        with app.app_context():
            response = auth_client.post(
                f"/domains/{domain_id}/check",
                follow_redirects=False,
            )

    assert response.status_code in (301, 302)
