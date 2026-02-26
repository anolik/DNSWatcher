"""
Unit tests for app/checker/reputation.py

All DNS calls are mocked so no real network activity occurs.
Covers: real listings, clean domains, query-refused false positives,
timeouts, overall status aggregation, and DNSBL provider cooldown logic.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dns_success(records: list[str]) -> dict:
    """Simulate a successful query_dns result."""
    return {
        "success": True,
        "records": records,
        "error_type": None,
        "error_message": None,
    }


def _dns_nxdomain() -> dict:
    """Simulate an NXDOMAIN query_dns result (domain not listed)."""
    return {
        "success": False,
        "records": [],
        "error_type": "NXDOMAIN",
        "error_message": "Domain does not exist",
    }


def _dns_timeout() -> dict:
    """Simulate a timeout query_dns result."""
    return {
        "success": False,
        "records": [],
        "error_type": "TIMEOUT",
        "error_message": "DNS query timed out",
    }


def _clear_cooldown_state(app):
    """Remove all DnsblCooldown rows so tests start fresh."""
    with app.app_context():
        from app import db
        from app.models import DnsblCooldown

        db.session.execute(db.delete(DnsblCooldown))
        db.session.commit()


# ---------------------------------------------------------------------------
# Tests - query refused false positive filtering
# ---------------------------------------------------------------------------


class TestQueryRefusedFiltering:
    """URIBL, SURBL, and Spamhaus return 127.0.0.1 or 127.255.255.x
    when a query comes through a public DNS forwarder.  These must NOT
    be treated as real blacklist listings."""

    @patch("app.checker.reputation.query_dns")
    def test_uribl_127_0_0_1_is_not_a_listing(self, mock_query, app):
        """127.0.0.1 from multi.uribl.com = query refused, not listed."""
        with app.app_context():
            mock_query.return_value = _dns_success(["127.0.0.1"])

            from app.checker.reputation import _check_single_dnsbl

            result = _check_single_dnsbl("example.com", "multi.uribl.com", None)

        assert result["listed"] is False
        assert result["error"] is True
        assert result["query_refused"] is True
        assert "refused" in result["error_message"].lower()

    @patch("app.checker.reputation.query_dns")
    def test_surbl_127_0_0_1_is_not_a_listing(self, mock_query, app):
        """127.0.0.1 from multi.surbl.org = query refused, not listed."""
        with app.app_context():
            mock_query.return_value = _dns_success(["127.0.0.1"])

            from app.checker.reputation import _check_single_dnsbl

            result = _check_single_dnsbl("example.com", "multi.surbl.org", None)

        assert result["listed"] is False
        assert result["error"] is True

    @patch("app.checker.reputation.query_dns")
    def test_spamhaus_127_255_255_254_is_not_a_listing(self, mock_query, app):
        """127.255.255.254 from Spamhaus = error/test, not listed."""
        with app.app_context():
            mock_query.return_value = _dns_success(["127.255.255.254"])

            from app.checker.reputation import _check_single_dnsbl

            result = _check_single_dnsbl("example.com", "dbl.spamhaus.org", None)

        assert result["listed"] is False
        assert result["error"] is True

    @patch("app.checker.reputation.query_dns")
    def test_spamhaus_127_255_255_255_is_not_a_listing(self, mock_query, app):
        """127.255.255.255 from Spamhaus = error/test, not listed."""
        with app.app_context():
            mock_query.return_value = _dns_success(["127.255.255.255"])

            from app.checker.reputation import _check_single_dnsbl

            result = _check_single_dnsbl("example.com", "dbl.spamhaus.org", None)

        assert result["listed"] is False
        assert result["error"] is True

    @patch("app.checker.reputation.query_dns")
    def test_query_refused_does_not_set_warning_status(self, mock_query, app):
        """If all three DNSBLs return 127.0.0.1, overall status stays 'ok'."""
        _clear_cooldown_state(app)
        with app.app_context():
            mock_query.return_value = _dns_success(["127.0.0.1"])

            from app.checker.reputation import check_reputation

            result = check_reputation("example.com")

        assert result["status"] == "ok"
        assert result["listed_on"] == []
        assert len(result["errors"]) == 3  # all three are errors, not listings


# ---------------------------------------------------------------------------
# Tests - real listings
# ---------------------------------------------------------------------------


class TestRealListings:
    """Verify that genuine blacklist responses are correctly detected."""

    @patch("app.checker.reputation.query_dns")
    def test_uribl_black_127_0_0_2_is_a_real_listing(self, mock_query, app):
        """127.0.0.2 from URIBL = URIBL_BLACK (real listing)."""
        with app.app_context():
            mock_query.return_value = _dns_success(["127.0.0.2"])

            from app.checker.reputation import _check_single_dnsbl

            result = _check_single_dnsbl("spam.example.com", "multi.uribl.com", None)

        assert result["listed"] is True
        assert result["error"] is False
        assert result["response"] == "127.0.0.2"

    @patch("app.checker.reputation.query_dns")
    def test_spamhaus_127_0_1_2_is_a_real_listing(self, mock_query, app):
        """127.0.1.2 from Spamhaus DBL = spam domain (real listing)."""
        with app.app_context():
            mock_query.return_value = _dns_success(["127.0.1.2"])

            from app.checker.reputation import _check_single_dnsbl

            result = _check_single_dnsbl("spam.example.com", "dbl.spamhaus.org", None)

        assert result["listed"] is True
        assert result["error"] is False

    @patch("app.checker.reputation.query_dns")
    def test_listing_sets_warning_status(self, mock_query, app):
        """A real listing on any DNSBL should set status to 'warning'."""
        _clear_cooldown_state(app)
        with app.app_context():
            # First two return NXDOMAIN (clean), third returns a real listing
            mock_query.side_effect = [
                _dns_nxdomain(),
                _dns_nxdomain(),
                _dns_success(["127.0.0.2"]),
            ]

            from app.checker.reputation import check_reputation

            result = check_reputation("spam.example.com")

        assert result["status"] == "warning"
        assert len(result["listed_on"]) == 1


# ---------------------------------------------------------------------------
# Tests - clean domains
# ---------------------------------------------------------------------------


class TestCleanDomains:
    """Verify that NXDOMAIN responses are correctly classified as clean."""

    @patch("app.checker.reputation.query_dns")
    def test_nxdomain_means_clean(self, mock_query, app):
        """NXDOMAIN from a DNSBL means the domain is NOT listed."""
        with app.app_context():
            mock_query.return_value = _dns_nxdomain()

            from app.checker.reputation import _check_single_dnsbl

            result = _check_single_dnsbl("clean.example.com", "dbl.spamhaus.org", None)

        assert result["listed"] is False
        assert result["clean"] is True
        assert result["error"] is False

    @patch("app.checker.reputation.query_dns")
    def test_all_clean_returns_ok_status(self, mock_query, app):
        """When all DNSBLs return NXDOMAIN, overall status is 'ok'."""
        _clear_cooldown_state(app)
        with app.app_context():
            mock_query.return_value = _dns_nxdomain()

            from app.checker.reputation import check_reputation

            result = check_reputation("clean.example.com")

        assert result["status"] == "ok"
        assert result["listed_on"] == []
        assert len(result["clean_on"]) == 3


# ---------------------------------------------------------------------------
# Tests - timeouts and errors
# ---------------------------------------------------------------------------


class TestTimeoutsAndErrors:
    """Verify that DNS errors are handled without false listings."""

    @patch("app.checker.reputation.query_dns")
    def test_timeout_is_error_not_listing(self, mock_query, app):
        """A timeout should be classified as error, not a listing."""
        with app.app_context():
            mock_query.return_value = _dns_timeout()

            from app.checker.reputation import _check_single_dnsbl

            result = _check_single_dnsbl("example.com", "multi.uribl.com", None)

        assert result["listed"] is False
        assert result["clean"] is False
        assert result["error"] is True
        assert result["query_refused"] is False

    @patch("app.checker.reputation.query_dns")
    def test_all_timeouts_returns_ok_with_errors(self, mock_query, app):
        """When all DNSBLs time out, status stays 'ok' (no listings)."""
        _clear_cooldown_state(app)
        with app.app_context():
            mock_query.return_value = _dns_timeout()

            from app.checker.reputation import check_reputation

            result = check_reputation("example.com")

        assert result["status"] == "ok"
        assert result["listed_on"] == []
        assert len(result["errors"]) == 3


# ---------------------------------------------------------------------------
# Tests - DNSBL provider cooldown logic
# ---------------------------------------------------------------------------


class TestDnsblCooldown:
    """Verify the 3-strikes / 24-hour cooldown mechanism."""

    @patch("app.checker.reputation.query_dns")
    def test_first_refusal_increments_counter(self, mock_query, app):
        """A single query-refused response should increment the refusal counter."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db
            from app.checker.reputation import _record_dnsbl_refusal
            from app.models import DnsblCooldown

            _record_dnsbl_refusal("multi.uribl.com")
            db.session.commit()

            row = db.session.execute(
                db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == "multi.uribl.com")
            ).scalars().first()

        assert row is not None
        assert row.consecutive_refusals == 1
        assert row.cooldown_until is None

    @patch("app.checker.reputation.query_dns")
    def test_two_refusals_no_cooldown_yet(self, mock_query, app):
        """Two consecutive refusals should not trigger cooldown."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db
            from app.checker.reputation import _record_dnsbl_refusal
            from app.models import DnsblCooldown

            _record_dnsbl_refusal("multi.uribl.com")
            _record_dnsbl_refusal("multi.uribl.com")
            db.session.commit()

            row = db.session.execute(
                db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == "multi.uribl.com")
            ).scalars().first()

        assert row.consecutive_refusals == 2
        assert row.cooldown_until is None

    @patch("app.checker.reputation.query_dns")
    def test_three_refusals_activates_cooldown(self, mock_query, app):
        """Three consecutive refusals should activate a 24-hour cooldown."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db
            from app.checker.reputation import _record_dnsbl_refusal
            from app.models import DnsblCooldown

            _record_dnsbl_refusal("multi.uribl.com")
            _record_dnsbl_refusal("multi.uribl.com")
            _record_dnsbl_refusal("multi.uribl.com")
            db.session.commit()

            row = db.session.execute(
                db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == "multi.uribl.com")
            ).scalars().first()

        assert row.consecutive_refusals == 3
        assert row.cooldown_until is not None
        # Cooldown should be roughly 24 hours from now (compare naive UTC)
        deadline = row.cooldown_until.replace(tzinfo=None) if row.cooldown_until.tzinfo else row.cooldown_until
        assert deadline > datetime.utcnow() + timedelta(hours=23)

    @patch("app.checker.reputation.query_dns")
    def test_provider_on_cooldown_is_skipped(self, mock_query, app):
        """A provider on cooldown should be skipped entirely in check_reputation."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db
            from app.models import DnsblCooldown

            # Manually put multi.uribl.com on cooldown
            cooldown_row = DnsblCooldown(
                dnsbl="multi.uribl.com",
                consecutive_refusals=3,
                cooldown_until=datetime.now(timezone.utc) + timedelta(hours=12),
            )
            db.session.add(cooldown_row)
            db.session.commit()

            # The other two DNSBLs return clean
            mock_query.return_value = _dns_nxdomain()

            from app.checker.reputation import check_reputation

            result = check_reputation("example.com")

        assert "multi.uribl.com" in result["skipped"]
        assert len(result["clean_on"]) == 2  # only the other two providers
        # query_dns should have been called only twice (not three times)
        assert mock_query.call_count == 2

    @patch("app.checker.reputation.query_dns")
    def test_expired_cooldown_allows_retry(self, mock_query, app):
        """A provider whose cooldown has expired should be queried again."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db
            from app.models import DnsblCooldown

            # Put multi.uribl.com on cooldown that expired 1 hour ago
            cooldown_row = DnsblCooldown(
                dnsbl="multi.uribl.com",
                consecutive_refusals=3,
                cooldown_until=datetime.now(timezone.utc) - timedelta(hours=1),
            )
            db.session.add(cooldown_row)
            db.session.commit()

            mock_query.return_value = _dns_nxdomain()

            from app.checker.reputation import check_reputation

            result = check_reputation("example.com")

        assert "multi.uribl.com" not in result["skipped"]
        assert len(result["clean_on"]) == 3  # all three queried
        assert mock_query.call_count == 3

    @patch("app.checker.reputation.query_dns")
    def test_expired_cooldown_resets_counter(self, mock_query, app):
        """When cooldown expires the refusal counter should be reset to 0."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db
            from app.models import DnsblCooldown

            # Expired cooldown
            cooldown_row = DnsblCooldown(
                dnsbl="multi.uribl.com",
                consecutive_refusals=3,
                cooldown_until=datetime.now(timezone.utc) - timedelta(hours=1),
            )
            db.session.add(cooldown_row)
            db.session.commit()

            mock_query.return_value = _dns_nxdomain()

            from app.checker.reputation import check_reputation

            check_reputation("example.com")
            db.session.commit()

            row = db.session.execute(
                db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == "multi.uribl.com")
            ).scalars().first()

        assert row.consecutive_refusals == 0
        assert row.cooldown_until is None

    @patch("app.checker.reputation.query_dns")
    def test_successful_response_resets_refusal_counter(self, mock_query, app):
        """A clean/listed response should reset the refusal counter to 0."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db
            from app.checker.reputation import _record_dnsbl_refusal, _record_dnsbl_success
            from app.models import DnsblCooldown

            # Build up 2 refusals
            _record_dnsbl_refusal("dbl.spamhaus.org")
            _record_dnsbl_refusal("dbl.spamhaus.org")
            db.session.flush()

            row = db.session.execute(
                db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == "dbl.spamhaus.org")
            ).scalars().first()
            assert row.consecutive_refusals == 2

            # Successful response resets
            _record_dnsbl_success("dbl.spamhaus.org")
            db.session.commit()

            row = db.session.execute(
                db.select(DnsblCooldown).where(DnsblCooldown.dnsbl == "dbl.spamhaus.org")
            ).scalars().first()

        assert row.consecutive_refusals == 0
        assert row.cooldown_until is None

    @patch("app.checker.reputation.query_dns")
    def test_cooldown_is_per_provider_not_global(self, mock_query, app):
        """Cooldown on one provider should not affect other providers."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db
            from app.models import DnsblCooldown

            # Only multi.uribl.com is on cooldown
            cooldown_row = DnsblCooldown(
                dnsbl="multi.uribl.com",
                consecutive_refusals=3,
                cooldown_until=datetime.now(timezone.utc) + timedelta(hours=12),
            )
            db.session.add(cooldown_row)
            db.session.commit()

            mock_query.return_value = _dns_nxdomain()

            from app.checker.reputation import check_reputation

            result = check_reputation("example.com")

        # multi.uribl.com skipped, other two queried normally
        assert "multi.uribl.com" in result["skipped"]
        assert "dbl.spamhaus.org" in result["clean_on"]
        assert "multi.surbl.org" in result["clean_on"]

    @patch("app.checker.reputation.query_dns")
    def test_full_flow_three_refused_then_skipped(self, mock_query, app):
        """End-to-end: 3 check_reputation calls with refusals -> 4th skips."""
        _clear_cooldown_state(app)
        with app.app_context():
            from app import db

            mock_query.return_value = _dns_success(["127.0.0.1"])

            from app.checker.reputation import check_reputation

            # First 3 calls: all providers refuse, building up refusal counters
            for _ in range(3):
                result = check_reputation("example.com")
                db.session.commit()
                assert result["status"] == "ok"
                assert len(result["errors"]) == 3

            # 4th call: all three providers should now be on cooldown
            mock_query.reset_mock()
            result = check_reputation("example.com")
            db.session.commit()

        assert len(result["skipped"]) == 3
        assert result["errors"] == []
        assert mock_query.call_count == 0  # no DNS queries made
