"""
F34 - Unit tests for app/checker/anti_flap.py

Verifies that the anti-flap logic correctly caps critical status to warning
until the configured threshold is reached, and resets on success.
"""

from __future__ import annotations

import pytest

from app.models import DnsSettings, Domain, FlapState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_domain(db, hostname: str = "flap-test.example.com") -> Domain:
    """Insert and return a minimal Domain row."""
    domain = Domain(hostname=hostname, current_status="pending")
    db.session.add(domain)
    db.session.flush()
    return domain


# ---------------------------------------------------------------------------
# Tests - first failure (below threshold)
# ---------------------------------------------------------------------------


def test_first_failure_capped_to_warning(app):
    """A single critical failure (below threshold=2) should be returned as warning."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic
        result = apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()

    assert result == "warning"


def test_first_error_capped_to_warning(app):
    """The 'error' status below threshold is also capped to 'warning'."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic
        result = apply_flap_logic(domain.id, "dmarc", "error")
        db.session.commit()

    assert result == "warning"


# ---------------------------------------------------------------------------
# Tests - consecutive failures reaching threshold
# ---------------------------------------------------------------------------


def test_second_failure_allows_critical_when_threshold_is_2(app):
    """On the second consecutive failure (threshold=2), critical is allowed through."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic

        # First failure - capped
        result1 = apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()
        assert result1 == "warning"

        # Second failure - threshold reached, full status through
        result2 = apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()

    assert result2 == "critical"


def test_third_failure_also_allows_critical(app):
    """Beyond the threshold, critical remains critical."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic

        apply_flap_logic(domain.id, "dkim", "critical")
        db.session.commit()
        apply_flap_logic(domain.id, "dkim", "critical")
        db.session.commit()
        result3 = apply_flap_logic(domain.id, "dkim", "critical")
        db.session.commit()

    assert result3 == "critical"


def test_consecutive_failures_counter_increments(app):
    """FlapState.consecutive_failures increments with each failure."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic

        apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()
        apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()

        flap = FlapState.query.filter_by(
            domain_id=domain.id, check_type="spf"
        ).first()

    assert flap is not None
    assert flap.consecutive_failures == 2


# ---------------------------------------------------------------------------
# Tests - success resets counter
# ---------------------------------------------------------------------------


def test_success_resets_consecutive_failures_to_zero(app):
    """An 'ok' result after failures should reset consecutive_failures to 0."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic

        # Build up two failures
        apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()
        apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()

        # Recovery
        result_ok = apply_flap_logic(domain.id, "spf", "ok")
        db.session.commit()

        flap = FlapState.query.filter_by(
            domain_id=domain.id, check_type="spf"
        ).first()

    assert result_ok == "ok"
    assert flap.consecutive_failures == 0


def test_warning_success_also_resets_counter(app):
    """A 'warning' status is treated as a success and resets the counter."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic

        apply_flap_logic(domain.id, "dmarc", "critical")
        db.session.commit()
        result = apply_flap_logic(domain.id, "dmarc", "warning")
        db.session.commit()

        flap = FlapState.query.filter_by(
            domain_id=domain.id, check_type="dmarc"
        ).first()

    assert result == "warning"
    assert flap.consecutive_failures == 0


def test_failure_after_success_starts_counter_again(app):
    """After a reset, a new failure should start the counter from 1."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic

        # Two failures -> threshold -> reset -> one new failure
        apply_flap_logic(domain.id, "dkim", "critical")
        db.session.commit()
        apply_flap_logic(domain.id, "dkim", "critical")
        db.session.commit()
        apply_flap_logic(domain.id, "dkim", "ok")
        db.session.commit()

        # New failure should be capped (counter back to 1, below threshold=2)
        result = apply_flap_logic(domain.id, "dkim", "critical")
        db.session.commit()

        flap = FlapState.query.filter_by(
            domain_id=domain.id, check_type="dkim"
        ).first()

    assert result == "warning"
    assert flap.consecutive_failures == 1


# ---------------------------------------------------------------------------
# Tests - threshold from DnsSettings
# ---------------------------------------------------------------------------


def test_threshold_loaded_from_dns_settings(app):
    """The flap_threshold from DnsSettings controls when critical is allowed."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        # Change threshold to 3
        settings = DnsSettings.query.get(1)
        settings.flap_threshold = 3
        db.session.commit()

        from app.checker.anti_flap import apply_flap_logic

        r1 = apply_flap_logic(domain.id, "reputation", "critical")
        db.session.commit()
        r2 = apply_flap_logic(domain.id, "reputation", "critical")
        db.session.commit()
        r3 = apply_flap_logic(domain.id, "reputation", "critical")
        db.session.commit()

    # With threshold=3: r1 and r2 should be capped, r3 allowed
    assert r1 == "warning"
    assert r2 == "warning"
    assert r3 == "critical"


def test_threshold_of_one_allows_critical_immediately(app):
    """With flap_threshold=1, the very first failure passes critical through."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        settings = DnsSettings.query.get(1)
        settings.flap_threshold = 1
        db.session.commit()

        from app.checker.anti_flap import apply_flap_logic
        result = apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()

    assert result == "critical"


# ---------------------------------------------------------------------------
# Tests - check_type isolation
# ---------------------------------------------------------------------------


def test_different_check_types_have_independent_counters(app):
    """SPF and DMARC failures are tracked independently per domain."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic

        # Two SPF failures -> threshold reached
        apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()
        spf_result = apply_flap_logic(domain.id, "spf", "critical")
        db.session.commit()

        # First DMARC failure -> still capped
        dmarc_result = apply_flap_logic(domain.id, "dmarc", "critical")
        db.session.commit()

    assert spf_result == "critical"   # spf threshold reached
    assert dmarc_result == "warning"  # dmarc counter still at 1


# ---------------------------------------------------------------------------
# Tests - ok status passthrough
# ---------------------------------------------------------------------------


def test_ok_status_always_returns_ok(app):
    """An 'ok' status is never modified by flap logic."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        from app.checker.anti_flap import apply_flap_logic
        result = apply_flap_logic(domain.id, "spf", "ok")
        db.session.commit()

    assert result == "ok"


def test_flap_state_created_on_first_call(app):
    """A FlapState row is automatically created when none exists for the domain."""
    with app.app_context():
        from app import db
        domain = _make_domain(db)

        # No FlapState should exist yet
        pre = FlapState.query.filter_by(
            domain_id=domain.id, check_type="spf"
        ).first()
        assert pre is None

        from app.checker.anti_flap import apply_flap_logic
        apply_flap_logic(domain.id, "spf", "ok")
        db.session.commit()

        post = FlapState.query.filter_by(
            domain_id=domain.id, check_type="spf"
        ).first()

    assert post is not None
