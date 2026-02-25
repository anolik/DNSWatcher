"""
F34 - Unit tests for app/checker/dmarc.py

All DNS network calls are mocked so no real DNS resolution occurs.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dns_ok(*records: str) -> dict:
    return {
        "success": True,
        "records": list(records),
        "error_type": None,
        "error_message": None,
    }


def _dns_fail(error_type: str = "NXDOMAIN", message: str = "Not found") -> dict:
    return {
        "success": False,
        "records": [],
        "error_type": error_type,
        "error_message": message,
    }


_PATCH_TARGET = "app.checker.dmarc.query_dns"
_CHECKDMARC_PATCH = "app.checker.dmarc._check_dmarc_with_checkdmarc"


# ---------------------------------------------------------------------------
# Tests - DMARC policy levels
# ---------------------------------------------------------------------------


def test_dmarc_reject_policy_returns_ok(app):
    """DMARC p=reject should report status 'ok'."""
    with app.app_context():
        record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["status"] == "ok"
    assert result["p"] == "reject"
    assert result["valid"] is True


def test_dmarc_quarantine_policy_returns_ok(app):
    """DMARC p=quarantine should report status 'ok'."""
    with app.app_context():
        record = "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["status"] == "ok"
    assert result["p"] == "quarantine"
    assert result["valid"] is True


def test_dmarc_none_policy_returns_warning(app):
    """DMARC p=none (monitoring only) should report status 'warning'."""
    with app.app_context():
        record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["status"] == "warning"
    assert result["p"] == "none"
    assert result["valid"] is True
    assert any("p=none" in w for w in result["warnings"])


def test_dmarc_missing_policy_returns_critical(app):
    """DMARC record without p= tag should report status 'critical'."""
    with app.app_context():
        record = "v=DMARC1; rua=mailto:dmarc@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["status"] == "critical"
    assert result["p"] is None
    assert result["valid"] is False
    assert any("p=" in w for w in result["warnings"])


# ---------------------------------------------------------------------------
# Tests - missing DMARC record
# ---------------------------------------------------------------------------


def test_dmarc_no_record_returns_critical(app):
    """No DMARC record in DNS should report status 'critical'."""
    with app.app_context():
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok("v=spf1 -all")):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["status"] == "critical"
    assert result["valid"] is False
    assert any("No DMARC record" in w for w in result["warnings"])


def test_dmarc_dns_failure_returns_critical(app):
    """DNS resolution failure for _dmarc record should report 'critical'."""
    with app.app_context():
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_fail("NXDOMAIN", "Not found")):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["status"] == "critical"
    assert result["valid"] is False


# ---------------------------------------------------------------------------
# Tests - reporting configuration
# ---------------------------------------------------------------------------


def test_dmarc_missing_rua_adds_warning(app):
    """DMARC record without rua= should produce an informational warning."""
    with app.app_context():
        record = "v=DMARC1; p=reject"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert any("rua=" in w for w in result["warnings"])


def test_dmarc_ruf_without_rua_adds_warning(app):
    """DMARC record with ruf= but no rua= should warn about missing aggregate reports."""
    with app.app_context():
        record = "v=DMARC1; p=reject; ruf=mailto:forensic@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    warning_text = " ".join(result["warnings"])
    # Should warn about missing rua AND about ruf without rua
    assert "rua=" in warning_text


def test_dmarc_rua_uri_extracted_correctly(app):
    """rua= URI is correctly parsed and returned in result."""
    with app.app_context():
        record = "v=DMARC1; p=reject; rua=mailto:reports@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert "mailto:reports@example.com" in result["rua"]


# ---------------------------------------------------------------------------
# Tests - pct= tag
# ---------------------------------------------------------------------------


def test_dmarc_pct_less_than_100_adds_warning(app):
    """pct=50 means only half of messages are filtered; this should warn."""
    with app.app_context():
        record = "v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["pct"] == 50
    assert any("50%" in w for w in result["warnings"])
    # pct < 100 degrades status to at least warning
    assert result["status"] in ("warning", "critical")


def test_dmarc_pct_100_no_warning(app):
    """pct=100 is the default; no pct-related warning should appear."""
    with app.app_context():
        record = "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["pct"] == 100
    assert not any("pct=" in w for w in result["warnings"])


def test_dmarc_pct_absent_stored_as_none(app):
    """When pct= is absent, pct in the result should be None."""
    with app.app_context():
        record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["pct"] is None


# ---------------------------------------------------------------------------
# Tests - subdomain policy
# ---------------------------------------------------------------------------


def test_dmarc_sp_none_adds_warning(app):
    """sp=none means subdomains are unprotected; should produce a warning."""
    with app.app_context():
        record = "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com"
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["sp"] == "none"
    assert any("sp=none" in w for w in result["warnings"])


# ---------------------------------------------------------------------------
# Tests - tag extraction
# ---------------------------------------------------------------------------


def test_dmarc_all_tags_extracted(app):
    """All standard DMARC tags are parsed and returned."""
    with app.app_context():
        record = (
            "v=DMARC1; p=quarantine; sp=reject; rua=mailto:rua@example.com; "
            "ruf=mailto:ruf@example.com; pct=80; aspf=s; adkim=s; fo=1"
        )
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["p"] == "quarantine"
    assert result["sp"] == "reject"
    assert result["aspf"] == "s"
    assert result["adkim"] == "s"
    assert result["fo"] == "1"
    assert result["pct"] == 80


# ---------------------------------------------------------------------------
# Tests - checkdmarc library path
# ---------------------------------------------------------------------------


def test_dmarc_checkdmarc_result_used_when_available(app):
    """When the checkdmarc helper succeeds it is used without a DNS fallback."""
    fake_result = {
        "status": "ok",
        "record": "v=DMARC1; p=reject; rua=mailto:r@example.com",
        "p": "reject",
        "sp": None,
        "rua": ["mailto:r@example.com"],
        "ruf": [],
        "pct": None,
        "aspf": None,
        "adkim": None,
        "fo": None,
        "warnings": [],
        "valid": True,
    }
    with app.app_context():
        with patch(_CHECKDMARC_PATCH, return_value=fake_result):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["status"] == "ok"
    assert result["p"] == "reject"


def test_dmarc_falls_back_to_manual_when_checkdmarc_none(app):
    """Manual path is used when checkdmarc helper returns None."""
    record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    with app.app_context():
        with patch(_CHECKDMARC_PATCH, return_value=None), \
             patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dmarc import check_dmarc
            result = check_dmarc("example.com")

    assert result["status"] == "ok"
    assert result["record"] == record
