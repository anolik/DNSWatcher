"""
F36 - Unit tests for app/checker/diff_engine.py

Verifies that changes between consecutive CheckResult rows are correctly
detected and classified, and that ChangeLog entries have the right severity.

IMPORTANT: All ORM attribute accesses must happen inside the app context so
that SQLAlchemy does not raise DetachedInstanceError when accessing lazy-
loaded columns after the session has been closed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.models import ChangeLog, CheckResult, Domain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_domain(db, hostname: str = "diff-test.example.com") -> Domain:
    domain = Domain(hostname=hostname, current_status="pending")
    db.session.add(domain)
    db.session.flush()
    return domain


def _make_result(
    db,
    domain_id: int,
    *,
    spf_status: str = "ok",
    spf_record: str | None = None,
    spf_details: dict | None = None,
    dmarc_status: str = "ok",
    dmarc_record: str | None = None,
    dmarc_details: dict | None = None,
    dkim_status: str = "ok",
    dkim_records: list | None = None,
    reputation_status: str = "ok",
    reputation_details: dict | None = None,
    mx_provider: str | None = None,
    mx_records: list | None = None,
    registrar: str | None = None,
    registrar_details: dict | None = None,
    overall_status: str = "ok",
    offset_seconds: int = 0,
) -> CheckResult:
    """Create and flush a CheckResult with the given parameters."""
    checked_at = _utcnow() + timedelta(seconds=offset_seconds)
    result = CheckResult(
        domain_id=domain_id,
        trigger_type="scheduled",
        checked_at=checked_at,
        overall_status=overall_status,
        spf_status=spf_status,
        spf_record=spf_record,
        spf_details=json.dumps(spf_details) if spf_details else None,
        dmarc_status=dmarc_status,
        dmarc_record=dmarc_record,
        dmarc_details=json.dumps(dmarc_details) if dmarc_details else None,
        dkim_status=dkim_status,
        dkim_records=json.dumps(dkim_records) if dkim_records else None,
        reputation_status=reputation_status,
        reputation_details=(
            json.dumps(reputation_details) if reputation_details else None
        ),
        mx_provider=mx_provider,
        mx_records=json.dumps(mx_records) if mx_records else None,
        registrar=registrar,
        registrar_details=(
            json.dumps(registrar_details) if registrar_details else None
        ),
    )
    db.session.add(result)
    db.session.flush()
    return result


def _snapshot_changes(changes: list) -> list[dict]:
    """Eagerly convert ChangeLog objects to plain dicts while in session scope."""
    return [
        {
            "check_type": c.check_type,
            "field_changed": c.field_changed,
            "severity": c.severity,
            "old_value": c.old_value,
            "new_value": c.new_value,
        }
        for c in changes
    ]


# ---------------------------------------------------------------------------
# Tests - first check produces no changes
# ---------------------------------------------------------------------------


def test_first_check_creates_no_changelog(app):
    """When there is no previous CheckResult, detect_changes returns []."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        result = _make_result(
            db,
            domain.id,
            spf_record="v=spf1 -all",
            dmarc_record="v=DMARC1; p=reject",
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, result)
        db.session.commit()

        change_count = db.session.execute(
            db.select(db.func.count(ChangeLog.id))
        ).scalar()

    assert changes == []
    assert change_count == 0


# ---------------------------------------------------------------------------
# Tests - SPF record change
# ---------------------------------------------------------------------------


def test_spf_record_change_detected(app):
    """Changing the SPF record text should create a ChangeLog entry."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, spf_record="v=spf1 -all", offset_seconds=0)
        new = _make_result(db, domain.id, spf_record="v=spf1 ~all", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    spf_changes = [
        c for c in snapshots
        if c["check_type"] == "spf" and c["field_changed"] == "spf_record"
    ]
    assert len(spf_changes) >= 1
    assert spf_changes[0]["old_value"] is not None
    assert spf_changes[0]["new_value"] is not None


def test_spf_unchanged_record_no_changelog(app):
    """When the SPF record does not change, no SPF ChangeLog is created."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, spf_record="v=spf1 -all", offset_seconds=0)
        new = _make_result(db, domain.id, spf_record="v=spf1 -all", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    spf_changes = [c for c in snapshots if c["check_type"] == "spf"]
    assert len(spf_changes) == 0


# ---------------------------------------------------------------------------
# Tests - DMARC policy downgrade (critical)
# ---------------------------------------------------------------------------


def test_dmarc_policy_downgrade_reject_to_none_is_critical(app):
    """Downgrading DMARC from p=reject to p=none should create a critical entry."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(
            db,
            domain.id,
            dmarc_record="v=DMARC1; p=reject; rua=mailto:r@example.com",
            dmarc_details={"policy": "reject"},
            offset_seconds=0,
        )
        new = _make_result(
            db,
            domain.id,
            dmarc_status="warning",
            dmarc_record="v=DMARC1; p=none; rua=mailto:r@example.com",
            dmarc_details={"policy": "none"},
            offset_seconds=1,
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    critical_changes = [c for c in snapshots if c["severity"] == "critical"]
    assert len(critical_changes) >= 1


def test_dmarc_policy_downgrade_reject_to_quarantine_is_critical(app):
    """p=reject -> p=quarantine is a downgrade and should be critical."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(
            db,
            domain.id,
            dmarc_record="v=DMARC1; p=reject",
            dmarc_details={"policy": "reject"},
            offset_seconds=0,
        )
        new = _make_result(
            db,
            domain.id,
            dmarc_record="v=DMARC1; p=quarantine",
            dmarc_details={"policy": "quarantine"},
            offset_seconds=1,
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    dmarc_policy_changes = [
        c for c in snapshots
        if c["check_type"] == "dmarc" and "policy" in c["field_changed"]
    ]
    assert len(dmarc_policy_changes) >= 1
    assert any(c["severity"] == "critical" for c in dmarc_policy_changes)


# ---------------------------------------------------------------------------
# Tests - DMARC policy upgrade (info)
# ---------------------------------------------------------------------------


def test_dmarc_policy_upgrade_none_to_reject_is_info(app):
    """Upgrading DMARC from p=none to p=reject is an improvement; severity='info'."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(
            db,
            domain.id,
            dmarc_status="warning",
            dmarc_record="v=DMARC1; p=none",
            dmarc_details={"policy": "none"},
            offset_seconds=0,
        )
        new = _make_result(
            db,
            domain.id,
            dmarc_record="v=DMARC1; p=reject",
            dmarc_details={"policy": "reject"},
            offset_seconds=1,
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    policy_changes = [
        c for c in snapshots
        if c["check_type"] == "dmarc" and "policy" in c["field_changed"]
    ]
    # All policy improvement changes should be 'info', not 'critical'
    for change in policy_changes:
        assert change["severity"] == "info"


# ---------------------------------------------------------------------------
# Tests - DKIM key change
# ---------------------------------------------------------------------------


def test_dkim_key_removal_detected(app):
    """When a DKIM selector disappears it should be flagged as critical."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        old_records = [
            {"selector": "selector1", "key_length": 2048, "public_key": "ABCDEF"}
        ]
        _make_result(
            db,
            domain.id,
            dkim_records=old_records,
            offset_seconds=0,
        )
        new = _make_result(
            db,
            domain.id,
            dkim_status="warning",
            dkim_records=[],  # key was removed
            offset_seconds=1,
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    dkim_changes = [c for c in snapshots if c["check_type"] == "dkim"]
    assert len(dkim_changes) >= 1
    key_removals = [c for c in dkim_changes if c["severity"] == "critical"]
    assert len(key_removals) >= 1


def test_dkim_key_addition_detected_as_info(app):
    """When a new DKIM selector appears it should be logged as 'info'."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, dkim_records=[], offset_seconds=0)
        new_records = [
            {"selector": "selector1", "key_length": 2048, "public_key": "NEWKEY"}
        ]
        new = _make_result(
            db,
            domain.id,
            dkim_records=new_records,
            offset_seconds=1,
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    dkim_changes = [c for c in snapshots if c["check_type"] == "dkim"]
    key_additions = [c for c in dkim_changes if c["severity"] == "info"]
    assert len(key_additions) >= 1


def test_dkim_key_length_decrease_is_critical(app):
    """A reduction in DKIM key length should be classified as 'critical'."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        old_records = [{"selector": "s1", "key_length": 2048, "public_key": "AAAA"}]
        new_records = [{"selector": "s1", "key_length": 1024, "public_key": "BBBB"}]

        _make_result(db, domain.id, dkim_records=old_records, offset_seconds=0)
        new = _make_result(db, domain.id, dkim_records=new_records, offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    dkim_changes = [c for c in snapshots if c["check_type"] == "dkim"]
    critical_key_changes = [
        c for c in dkim_changes
        if c["severity"] == "critical" and "key_length" in c["field_changed"]
    ]
    assert len(critical_key_changes) >= 1


# ---------------------------------------------------------------------------
# Tests - reputation change
# ---------------------------------------------------------------------------


def test_reputation_new_blocklist_is_critical(app):
    """A domain appearing on a new blocklist should produce a critical change."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(
            db,
            domain.id,
            reputation_status="ok",
            reputation_details={"listed_on": [], "clean_on": ["barracuda"]},
            offset_seconds=0,
        )
        new = _make_result(
            db,
            domain.id,
            reputation_status="critical",
            reputation_details={"listed_on": ["barracuda"], "clean_on": []},
            offset_seconds=1,
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    reputation_changes = [c for c in snapshots if c["check_type"] == "reputation"]
    # At least one critical change (new blocklist listing)
    assert any(c["severity"] == "critical" for c in reputation_changes)


# ---------------------------------------------------------------------------
# Tests - overall status change
# ---------------------------------------------------------------------------


def test_overall_status_improvement_is_info(app):
    """Overall status improvement (warning -> ok) should be classified as 'info'."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, overall_status="warning", offset_seconds=0)
        new = _make_result(db, domain.id, overall_status="ok", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    overall_changes = [c for c in snapshots if c["field_changed"] == "overall_status"]
    assert len(overall_changes) == 1
    assert overall_changes[0]["severity"] == "info"


def test_overall_status_degradation_is_critical(app):
    """Overall status degradation (ok -> critical) should produce 'critical'."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, overall_status="ok", offset_seconds=0)
        new = _make_result(db, domain.id, overall_status="critical", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    overall_changes = [c for c in snapshots if c["field_changed"] == "overall_status"]
    assert len(overall_changes) == 1
    assert overall_changes[0]["severity"] == "critical"


def test_same_overall_status_no_change(app):
    """When overall status does not change, no overall_status ChangeLog is created."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, overall_status="ok", offset_seconds=0)
        new = _make_result(db, domain.id, overall_status="ok", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    overall_changes = [c for c in snapshots if c["field_changed"] == "overall_status"]
    assert len(overall_changes) == 0


# ---------------------------------------------------------------------------
# Tests - change log entries added to session
# ---------------------------------------------------------------------------


def test_detected_changes_are_persisted_after_commit(app):
    """ChangeLog entries added by detect_changes should persist after commit."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, spf_record="v=spf1 -all", offset_seconds=0)
        new = _make_result(db, domain.id, spf_record="v=spf1 ~all", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        detect_changes(domain.id, new)
        db.session.commit()

        count = db.session.execute(
            db.select(db.func.count(ChangeLog.id))
        ).scalar()

    assert count > 0


# ---------------------------------------------------------------------------
# Tests - MX provider change
# ---------------------------------------------------------------------------


def test_mx_provider_change_detected(app):
    """Changing MX provider should create an 'info' ChangeLog entry."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(
            db, domain.id,
            mx_provider="Google Workspace",
            offset_seconds=0,
        )
        new = _make_result(
            db, domain.id,
            mx_provider="Microsoft 365",
            offset_seconds=1,
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    mx_changes = [c for c in snapshots if c["check_type"] == "mx"]
    assert len(mx_changes) == 1
    assert mx_changes[0]["field_changed"] == "mx_provider"
    assert mx_changes[0]["severity"] == "info"
    assert mx_changes[0]["old_value"] == "Google Workspace"
    assert mx_changes[0]["new_value"] == "Microsoft 365"


def test_mx_provider_unchanged_no_changelog(app):
    """When MX provider does not change, no MX ChangeLog is created."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, mx_provider="Google Workspace", offset_seconds=0)
        new = _make_result(db, domain.id, mx_provider="Google Workspace", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    mx_changes = [c for c in snapshots if c["check_type"] == "mx"]
    assert len(mx_changes) == 0


def test_mx_provider_from_none_to_value(app):
    """First MX provider detection (None -> value) should create a change."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, mx_provider=None, offset_seconds=0)
        new = _make_result(db, domain.id, mx_provider="OVH", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    mx_changes = [c for c in snapshots if c["check_type"] == "mx"]
    assert len(mx_changes) == 1
    assert mx_changes[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# Tests - registrar change
# ---------------------------------------------------------------------------


def test_registrar_change_detected(app):
    """Changing registrar should create an 'info' ChangeLog entry."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(
            db, domain.id,
            registrar="GoDaddy.com, LLC",
            offset_seconds=0,
        )
        new = _make_result(
            db, domain.id,
            registrar="Namecheap, Inc.",
            offset_seconds=1,
        )
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    reg_changes = [c for c in snapshots if c["check_type"] == "registrar"]
    assert len(reg_changes) == 1
    assert reg_changes[0]["field_changed"] == "registrar_name"
    assert reg_changes[0]["severity"] == "info"
    assert reg_changes[0]["old_value"] == "GoDaddy.com, LLC"
    assert reg_changes[0]["new_value"] == "Namecheap, Inc."


def test_registrar_unchanged_no_changelog(app):
    """When registrar does not change, no registrar ChangeLog is created."""
    with app.app_context():
        from app import db

        domain = _make_domain(db)

        _make_result(db, domain.id, registrar="GoDaddy.com, LLC", offset_seconds=0)
        new = _make_result(db, domain.id, registrar="GoDaddy.com, LLC", offset_seconds=1)
        db.session.flush()

        from app.checker.diff_engine import detect_changes

        changes = detect_changes(domain.id, new)
        snapshots = _snapshot_changes(changes)
        db.session.commit()

    reg_changes = [c for c in snapshots if c["check_type"] == "registrar"]
    assert len(reg_changes) == 0
