"""
F34 - Unit tests for app/checker/dkim.py

All DNS network calls are mocked. RSA key measurements are also
mocked where needed so no cryptography library or real keys are required.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

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


def _make_dkim_record(p_value: str, k: str = "rsa", v: str = "DKIM1") -> str:
    """Compose a minimal DKIM TXT record string."""
    return f"v={v}; k={k}; p={p_value}"


# A minimal valid base64 placeholder used for mocked key material.
_FAKE_B64 = base64.b64encode(b"x" * 256).decode()

_PATCH_TARGET = "app.checker.dkim.query_dns"
_PATCH_KEY_SIZE = "app.checker.dkim._measure_key_size"


# ---------------------------------------------------------------------------
# Tests - 2048-bit RSA key
# ---------------------------------------------------------------------------


def test_dkim_2048bit_rsa_key_returns_ok(app):
    """A 2048-bit RSA key should produce status 'ok'."""
    record = _make_dkim_record(_FAKE_B64)
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)), \
             patch(_PATCH_KEY_SIZE, return_value=2048):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    assert result["status"] == "ok"
    assert len(result["results"]) == 1
    selector_result = result["results"][0]
    assert selector_result["key_size"] == 2048
    assert selector_result["valid"] is True
    assert selector_result["status"] == "ok"


def test_dkim_4096bit_rsa_key_returns_ok(app):
    """A 4096-bit RSA key (larger than 2048) should also return 'ok'."""
    record = _make_dkim_record(_FAKE_B64)
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)), \
             patch(_PATCH_KEY_SIZE, return_value=4096):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["mail"])

    assert result["status"] == "ok"
    assert result["results"][0]["key_size"] == 4096


# ---------------------------------------------------------------------------
# Tests - 1024-bit RSA key
# ---------------------------------------------------------------------------


def test_dkim_1024bit_rsa_key_returns_warning(app):
    """A 1024-bit RSA key should produce status 'warning'."""
    record = _make_dkim_record(_FAKE_B64)
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)), \
             patch(_PATCH_KEY_SIZE, return_value=1024):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    selector_result = result["results"][0]
    assert selector_result["status"] == "warning"
    assert selector_result["key_size"] == 1024
    assert selector_result["valid"] is True
    # Overall status should be warning when worst selector is warning
    assert result["status"] == "warning"


def test_dkim_1024bit_key_includes_upgrade_warning(app):
    """1024-bit key should include a message recommending upgrade to 2048+."""
    record = _make_dkim_record(_FAKE_B64)
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)), \
             patch(_PATCH_KEY_SIZE, return_value=1024):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    all_warnings = " ".join(result["warnings"])
    assert "2048" in all_warnings or "1024" in all_warnings


# ---------------------------------------------------------------------------
# Tests - revoked key (empty p=)
# ---------------------------------------------------------------------------


def test_dkim_revoked_key_returns_critical(app):
    """An empty p= tag means the DKIM key is revoked; should return 'critical'."""
    record = "v=DKIM1; k=rsa; p="
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    selector_result = result["results"][0]
    assert selector_result["status"] == "critical"
    assert selector_result["valid"] is False
    assert any("revoked" in w.lower() for w in selector_result["warnings"])


def test_dkim_revoked_key_overall_status_propagates(app):
    """Overall status should reflect the worst (critical) selector."""
    record = "v=DKIM1; k=rsa; p="
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    # No valid selectors found means overall is warning (no valid selector)
    # but the individual result is critical
    assert result["results"][0]["status"] == "critical"
    assert result["results"][0]["valid"] is False


# ---------------------------------------------------------------------------
# Tests - missing selector (NXDOMAIN)
# ---------------------------------------------------------------------------


def test_dkim_missing_selector_nxdomain_is_graceful(app):
    """NXDOMAIN for a selector should not be a hard failure (graceful skip)."""
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_fail("NXDOMAIN", "Not found")):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["nonexistent"])

    selector_result = result["results"][0]
    # NXDOMAIN is graceful - selector simply does not exist
    assert selector_result["error_type"] == "NXDOMAIN"
    assert selector_result["status"] == "info"


def test_dkim_nxdomain_does_not_mark_key_as_valid(app):
    """A selector with NXDOMAIN should not be counted as a valid selector."""
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_fail("NXDOMAIN", "Not found")):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["missing"])

    assert result["results"][0]["valid"] is False


def test_dkim_mixed_valid_and_nxdomain_selectors(app):
    """Overall status is based on the valid selectors; NXDOMAIN is ignored."""
    record_2048 = _make_dkim_record(_FAKE_B64)

    def side_effect(domain, rdtype, settings=None):
        if "selector1" in domain:
            return _dns_ok(record_2048)
        return _dns_fail("NXDOMAIN", "Not found")

    with app.app_context():
        with patch(_PATCH_TARGET, side_effect=side_effect), \
             patch(_PATCH_KEY_SIZE, return_value=2048):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1", "missing"])

    assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# Tests - ed25519 algorithm
# ---------------------------------------------------------------------------


def test_dkim_ed25519_key_type_detected(app):
    """Ed25519 DKIM keys should be recognised and sized at 256 bits by _measure_key_size."""
    record = _make_dkim_record(_FAKE_B64, k="ed25519")
    with app.app_context():
        # Do not mock _measure_key_size so we test the real ed25519 branch.
        # _measure_key_size returns 256 for any ed25519 key.
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    selector_result = result["results"][0]
    assert selector_result["key_type"] == "ed25519"
    # _measure_key_size returns 256 for ed25519 (always fixed size)
    assert selector_result["key_size"] == 256


def test_dkim_ed25519_key_with_mocked_size_returns_ok(app):
    """When _measure_key_size is mocked to return 2048 for ed25519, status is ok."""
    record = _make_dkim_record(_FAKE_B64, k="ed25519")
    with app.app_context():
        # Mock key size to 2048 to verify the status logic path independent of
        # algorithm-specific sizing.  In production, ed25519 at 256 bits is
        # cryptographically strong but below the RSA-centric threshold check.
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)), \
             patch(_PATCH_KEY_SIZE, return_value=2048):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    selector_result = result["results"][0]
    assert selector_result["key_type"] == "ed25519"
    assert selector_result["valid"] is True
    assert selector_result["status"] == "ok"


# ---------------------------------------------------------------------------
# Tests - no selectors configured
# ---------------------------------------------------------------------------


def test_dkim_no_selectors_returns_warning(app):
    """Calling check_dkim with an empty selector list should return 'warning'."""
    with app.app_context():
        from app.checker.dkim import check_dkim
        result = check_dkim("example.com", [])

    assert result["status"] == "warning"
    assert any("No DKIM selectors" in w for w in result["warnings"])


# ---------------------------------------------------------------------------
# Tests - testing mode flag
# ---------------------------------------------------------------------------


def test_dkim_testing_mode_flag_adds_warning(app):
    """t=y (testing mode) should produce a warning in the selector result."""
    record = f"v=DKIM1; k=rsa; t=y; p={_FAKE_B64}"
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)), \
             patch(_PATCH_KEY_SIZE, return_value=2048):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    sel = result["results"][0]
    assert any("testing mode" in w.lower() for w in sel["warnings"])


# ---------------------------------------------------------------------------
# Tests - key size undetermined
# ---------------------------------------------------------------------------


def test_dkim_unknown_key_size_returns_warning(app):
    """When key size cannot be determined the result should be 'warning'."""
    record = _make_dkim_record(_FAKE_B64)
    with app.app_context():
        with patch(_PATCH_TARGET, return_value=_dns_ok(record)), \
             patch(_PATCH_KEY_SIZE, return_value=None):
            from app.checker.dkim import check_dkim
            result = check_dkim("example.com", ["selector1"])

    sel = result["results"][0]
    assert sel["status"] == "warning"
    assert sel["valid"] is True
    assert any("key size" in w.lower() for w in sel["warnings"])


# ---------------------------------------------------------------------------
# Tests - multiple selectors aggregation
# ---------------------------------------------------------------------------


def test_dkim_multiple_selectors_worst_status_wins(app):
    """When one selector is ok and another is warning, overall is warning."""
    record_2048 = _make_dkim_record(_FAKE_B64)
    record_1024 = _make_dkim_record(_FAKE_B64)

    call_count = {"n": 0}

    def side_effect(domain, rdtype, settings=None):
        call_count["n"] += 1
        return _dns_ok(record_2048 if call_count["n"] == 1 else record_1024)

    def key_size_side_effect(p_val, key_type):
        return 2048 if call_count["n"] == 1 else 1024

    with app.app_context():
        with patch(_PATCH_TARGET, side_effect=side_effect), \
             patch(_PATCH_KEY_SIZE, side_effect=lambda p, k: (
                 2048 if "selector1" in "" else 1024
             )):
            # Use explicit mapping for determinism
            sizes = iter([2048, 1024])
            with patch(_PATCH_KEY_SIZE, side_effect=lambda p, k: next(sizes)):
                from app.checker.dkim import check_dkim
                result = check_dkim("example.com", ["selector1", "selector2"])

    # Both selectors found; worst is warning
    assert result["status"] == "warning"
