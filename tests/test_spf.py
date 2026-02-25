"""
F34 - Unit tests for app/checker/spf.py

All DNS network calls are mocked via unittest.mock.patch so no real
DNS resolution occurs during the test run.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helper: build a fake query_dns return value
# ---------------------------------------------------------------------------


def _dns_ok(*records: str) -> dict:
    """Return a successful DNS query result containing *records*."""
    return {
        "success": True,
        "records": list(records),
        "error_type": None,
        "error_message": None,
    }


def _dns_fail(error_type: str = "NXDOMAIN", message: str = "Not found") -> dict:
    """Return a failed DNS query result."""
    return {
        "success": False,
        "records": [],
        "error_type": error_type,
        "error_message": message,
    }


# ---------------------------------------------------------------------------
# Module-level patch target
# ---------------------------------------------------------------------------

_PATCH_TARGET = "app.checker.spf.query_dns"
_CHECKDMARC_PATCH = "app.checker.spf._check_spf_with_checkdmarc"


# ---------------------------------------------------------------------------
# Tests - policy qualifiers
# ---------------------------------------------------------------------------


def test_spf_hard_fail_returns_ok(app):
    """SPF record with -all qualifier should report status 'ok'."""
    with app.app_context():
        spf_record = "v=spf1 include:_spf.example.com -all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["status"] == "ok"
    assert result["record"] == spf_record
    assert result["policy"] == "hard_fail"
    assert result["valid"] is True


def test_spf_soft_fail_returns_warning(app):
    """SPF record with ~all qualifier should report status 'warning'."""
    with app.app_context():
        spf_record = "v=spf1 include:_spf.example.com ~all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["status"] == "warning"
    assert result["policy"] == "soft_fail"
    assert result["valid"] is True


def test_spf_neutral_qualifier_returns_warning(app):
    """SPF record with ?all qualifier should report status 'warning'."""
    with app.app_context():
        spf_record = "v=spf1 ip4:192.168.1.0/24 ?all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["status"] == "warning"
    assert result["policy"] == "neutral"
    # A warning-level result is still considered valid (not critical)
    assert result["valid"] is True


def test_spf_pass_all_returns_critical(app):
    """SPF record with +all qualifier should report status 'critical'."""
    with app.app_context():
        spf_record = "v=spf1 +all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["status"] == "critical"
    assert result["policy"] == "pass_all"
    assert result["valid"] is False


def test_spf_bare_all_defaults_to_pass_all(app):
    """A bare 'all' token without qualifier defaults to +all (critical)."""
    with app.app_context():
        spf_record = "v=spf1 all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    # 'all' without qualifier is treated as +all per RFC 7208
    assert result["status"] == "critical"
    assert result["valid"] is False


# ---------------------------------------------------------------------------
# Tests - missing / invalid records
# ---------------------------------------------------------------------------


def test_spf_missing_record_returns_critical(app):
    """No SPF record in DNS should report status 'critical'."""
    with app.app_context():
        # DNS responds with unrelated TXT records only
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok("some-other-txt-record")):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["status"] == "critical"
    assert result["valid"] is False
    assert any("No SPF record" in w for w in result["warnings"])


def test_spf_dns_failure_returns_critical(app):
    """DNS query failure should report status 'critical'."""
    with app.app_context():
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_fail("NXDOMAIN", "NXDOMAIN")):
            from app.checker.spf import check_spf
            result = check_spf("nonexistent.example.com")

    assert result["status"] == "critical"
    assert result["valid"] is False


def test_spf_multiple_records_returns_critical(app):
    """Multiple SPF records violate RFC 7208 and should return 'critical'."""
    with app.app_context():
        rec1 = "v=spf1 -all"
        rec2 = "v=spf1 ~all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(rec1, rec2)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["status"] == "critical"
    assert result["valid"] is False
    assert any("Multiple SPF" in w for w in result["warnings"])


def test_spf_no_all_mechanism_returns_critical(app):
    """SPF record with no 'all' mechanism should report 'critical' (policy=missing)."""
    with app.app_context():
        spf_record = "v=spf1 include:_spf.example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["policy"] == "missing"
    assert result["status"] == "critical"
    assert result["valid"] is False


# ---------------------------------------------------------------------------
# Tests - DNS lookup count
# ---------------------------------------------------------------------------


def test_spf_excessive_lookups_returns_warning(app):
    """SPF record exceeding 10 DNS lookups should at minimum return 'warning'."""
    with app.app_context():
        # Construct a record with 11 include: mechanisms (each costs 1 lookup)
        includes = " ".join(f"include:inc{i}.example.com" for i in range(11))
        spf_record = f"v=spf1 {includes} -all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["lookup_count"] > 10
    assert result["status"] in ("warning", "critical")
    assert any("10 DNS lookup" in w for w in result["warnings"])


def test_spf_within_lookup_limit_no_warning(app):
    """SPF record with 3 DNS lookups should not trigger a lookup-count warning."""
    with app.app_context():
        spf_record = "v=spf1 include:a.example.com include:b.example.com include:c.example.com -all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["lookup_count"] == 3
    assert not any("10 DNS lookup" in w for w in result["warnings"])


# ---------------------------------------------------------------------------
# Tests - mechanism parsing
# ---------------------------------------------------------------------------


def test_spf_mechanism_parsing_captures_all_types(app):
    """Mechanism parser correctly identifies ip4, include, a, mx, and all."""
    with app.app_context():
        spf_record = "v=spf1 ip4:192.168.1.0/24 include:relay.example.com a mx -all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    types = [m["type"] for m in result["mechanisms"]]
    assert "ip4" in types
    assert "include" in types
    assert "a" in types
    assert "mx" in types
    assert "all" in types


def test_spf_mechanism_qualifier_extraction(app):
    """Each mechanism qualifier (-, ~, ?, +) is parsed correctly."""
    with app.app_context():
        spf_record = "v=spf1 +ip4:10.0.0.1 ~ip4:10.0.0.2 -all"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    qualifiers = {m["type"]: m["qualifier"] for m in result["mechanisms"]}
    assert qualifiers.get("all") == "-"


# ---------------------------------------------------------------------------
# Tests - empty DNS response
# ---------------------------------------------------------------------------


def test_spf_empty_dns_response_returns_critical(app):
    """An empty DNS success (no records at all) should return 'critical'."""
    with app.app_context():
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok()):
            from app.checker.spf import check_spf
            result = check_spf("empty.example.com")

    assert result["status"] == "critical"
    assert result["valid"] is False


# ---------------------------------------------------------------------------
# Tests - checkdmarc library path
# ---------------------------------------------------------------------------


def test_spf_checkdmarc_result_returned_when_available(app):
    """If the checkdmarc library path returns a result, it is used directly."""
    fake_result = {
        "status": "ok",
        "record": "v=spf1 -all",
        "policy": "hard_fail",
        "mechanisms": [],
        "lookup_count": 0,
        "warnings": [],
        "valid": True,
    }
    with app.app_context():
        with patch(_CHECKDMARC_PATCH, return_value=fake_result):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["status"] == "ok"
    assert result["policy"] == "hard_fail"


def test_spf_falls_back_to_manual_when_checkdmarc_returns_none(app):
    """Manual DNS path is used when checkdmarc helper returns None."""
    spf_record = "v=spf1 -all"
    with app.app_context():
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(spf_record)):
            from app.checker.spf import check_spf
            result = check_spf("example.com")

    assert result["status"] == "ok"
    assert result["record"] == spf_record
