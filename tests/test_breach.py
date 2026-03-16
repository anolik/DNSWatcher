"""
F45 - Unit tests for the breach monitoring module.

Tests cover three areas:
  1. HIBP API client (app/checker/breach.py) — all HTTP calls mocked
  2. Breach model helpers (BreachResult, BreachEntry)
  3. Acknowledgment workflow on BreachEntry

All network calls are mocked via unittest.mock.patch so no real HIBP
API requests occur during the test run.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from app import db as _db
from app.models import BreachEntry, BreachResult, Domain, User


# ---------------------------------------------------------------------------
# Patch target
# ---------------------------------------------------------------------------

_PATCH_REQUESTS_GET = "app.checker.breach.requests.get"
_PATCH_THROTTLE = "app.checker.breach._throttle_wait"
_PATCH_SLEEP = "app.checker.breach.time.sleep"


# ---------------------------------------------------------------------------
# Helper: build fake HIBP response objects
# ---------------------------------------------------------------------------


def _mock_response(
    status_code: int = 200,
    json_data: object = None,
    headers: dict | None = None,
    raise_for_status_effect: Exception | None = None,
    text: str = "",
) -> MagicMock:
    """Build a mock ``requests.Response`` with the given attributes."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text

    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("No JSON")

    if raise_for_status_effect:
        resp.raise_for_status.side_effect = raise_for_status_effect
    else:
        resp.raise_for_status.return_value = None

    return resp


def _sample_breach_list() -> list[dict]:
    """Return a realistic HIBP breach payload (two breaches)."""
    return [
        {
            "Name": "AcmeCorp",
            "BreachDate": "2021-03-15",
            "DataClasses": ["Email addresses", "Passwords"],
            "PwnCount": 12345,
            "Description": "Acme Corp suffered a data breach.",
        },
        {
            "Name": "WidgetInc",
            "BreachDate": "2023-07-01",
            "DataClasses": ["Email addresses", "IP addresses"],
            "PwnCount": 67890,
            "Description": "Widget Inc leaked user data.",
        },
    ]


# =========================================================================
# 1. HIBP API Client Tests
# =========================================================================


class TestHibpApiClient:
    """Tests for app.checker.breach.check_breaches (HIBP HTTP client)."""

    def test_successful_domain_lookup_with_breaches(self, app):
        """A 200 response with breach data is parsed into normalised dicts."""
        with app.app_context():
            breaches = _sample_breach_list()
            mock_resp = _mock_response(status_code=200, json_data=breaches)

            with patch(_PATCH_REQUESTS_GET, return_value=mock_resp), \
                 patch(_PATCH_THROTTLE):
                from app.checker.breach import check_breaches

                result = check_breaches("example.com", api_key="test-key", throttle_delay=0)

        assert result["error"] is None
        assert result["total_breaches"] == 2
        assert len(result["breaches"]) == 2

        first = result["breaches"][0]
        assert first["name"] == "AcmeCorp"
        assert first["date"] == "2021-03-15"
        assert "Email addresses" in first["data_classes"]
        assert first["pwn_count"] == 12345

    def test_domain_with_no_breaches(self, app):
        """HIBP returns 404 when no breaches exist — result should be empty."""
        with app.app_context():
            mock_resp = _mock_response(status_code=404)

            with patch(_PATCH_REQUESTS_GET, return_value=mock_resp), \
                 patch(_PATCH_THROTTLE):
                from app.checker.breach import check_breaches

                result = check_breaches("clean-domain.com", api_key="test-key", throttle_delay=0)

        assert result["error"] is None
        assert result["total_breaches"] == 0
        assert result["breaches"] == []

    def test_invalid_api_key_returns_error(self, app):
        """A 401 response sets the error field with a descriptive message."""
        with app.app_context():
            mock_resp = _mock_response(status_code=401)

            with patch(_PATCH_REQUESTS_GET, return_value=mock_resp), \
                 patch(_PATCH_THROTTLE):
                from app.checker.breach import check_breaches

                result = check_breaches("example.com", api_key="bad-key", throttle_delay=0)

        assert result["error"] is not None
        assert "API key" in result["error"].lower() or "invalid" in result["error"].lower()
        assert result["total_breaches"] == 0
        assert result["breaches"] == []

    def test_rate_limit_retry(self, app):
        """A 429 followed by a 200 triggers retry and returns breach data."""
        with app.app_context():
            breaches = _sample_breach_list()
            mock_429 = _mock_response(status_code=429, headers={"Retry-After": "1"})
            mock_200 = _mock_response(status_code=200, json_data=breaches)

            with patch(_PATCH_REQUESTS_GET, side_effect=[mock_429, mock_200]), \
                 patch(_PATCH_THROTTLE), \
                 patch(_PATCH_SLEEP):
                from app.checker.breach import check_breaches

                result = check_breaches("example.com", api_key="test-key", throttle_delay=0)

        assert result["error"] is None
        assert result["total_breaches"] == 2

    def test_rate_limit_exhausted(self, app):
        """Repeated 429 responses exhaust retries and return an error."""
        with app.app_context():
            mock_429 = _mock_response(status_code=429, headers={"Retry-After": "1"})

            with patch(_PATCH_REQUESTS_GET, return_value=mock_429), \
                 patch(_PATCH_THROTTLE), \
                 patch(_PATCH_SLEEP):
                from app.checker.breach import check_breaches

                result = check_breaches("example.com", api_key="test-key", throttle_delay=0)

        assert result["error"] is not None
        assert "rate limit" in result["error"].lower()

    def test_timeout_handling(self, app):
        """A requests.Timeout exception is caught and returns a graceful error."""
        with app.app_context():
            with patch(_PATCH_REQUESTS_GET, side_effect=requests.Timeout("timed out")), \
                 patch(_PATCH_THROTTLE):
                from app.checker.breach import check_breaches

                result = check_breaches("slow-api.com", api_key="test-key", throttle_delay=0)

        assert result["error"] is not None
        assert "timed out" in result["error"].lower() or "timeout" in result["error"].lower()
        assert result["total_breaches"] == 0

    def test_malformed_response(self, app):
        """A 200 with non-list JSON is handled gracefully (returns empty breaches)."""
        with app.app_context():
            # HIBP returns an object instead of a list — should not crash
            mock_resp = _mock_response(status_code=200, json_data={"unexpected": "format"})

            with patch(_PATCH_REQUESTS_GET, return_value=mock_resp), \
                 patch(_PATCH_THROTTLE):
                from app.checker.breach import check_breaches

                result = check_breaches("example.com", api_key="test-key", throttle_delay=0)

        assert result["error"] is None
        assert result["total_breaches"] == 0
        assert result["breaches"] == []

    def test_missing_api_key_returns_error(self, app):
        """Calling check_breaches with an empty API key skips the request."""
        with app.app_context():
            from app.checker.breach import check_breaches

            result = check_breaches("example.com", api_key="", throttle_delay=0)

        assert result["error"] is not None
        assert "api key" in result["error"].lower()
        assert result["total_breaches"] == 0

    def test_network_error_handling(self, app):
        """A generic ConnectionError is caught and returns a graceful error."""
        with app.app_context():
            with patch(
                _PATCH_REQUESTS_GET,
                side_effect=requests.ConnectionError("DNS resolution failed"),
            ), patch(_PATCH_THROTTLE):
                from app.checker.breach import check_breaches

                result = check_breaches("example.com", api_key="test-key", throttle_delay=0)

        assert result["error"] is not None
        assert result["total_breaches"] == 0


# =========================================================================
# 2. Breach Model Tests
# =========================================================================


class TestBreachResultModel:
    """Tests for the BreachResult ORM model and its JSON helpers."""

    def test_breach_result_json_helpers(self, app):
        """get_breaches() and get_emails() deserialise stored JSON correctly."""
        with app.app_context():
            domain = Domain(hostname="model-test.com")
            _db.session.add(domain)
            _db.session.flush()

            breaches_data = [
                {"name": "TestBreach", "date": "2024-01-01", "pwn_count": 100},
            ]
            emails_data = ["alice@model-test.com", "bob@model-test.com"]

            br = BreachResult(
                domain_id=domain.id,
                total_breaches=1,
                total_emails=2,
                breaches_json=json.dumps(breaches_data),
                emails_json=json.dumps(emails_data),
            )
            _db.session.add(br)
            _db.session.commit()

            # Re-fetch from the database
            fetched = _db.session.get(BreachResult, br.id)
            assert fetched.get_breaches() == breaches_data
            assert fetched.get_emails() == emails_data

    def test_breach_result_empty_json_returns_defaults(self, app):
        """Null JSON fields return empty lists, not crashes."""
        with app.app_context():
            domain = Domain(hostname="empty-json.com")
            _db.session.add(domain)
            _db.session.flush()

            br = BreachResult(
                domain_id=domain.id,
                total_breaches=0,
                total_emails=0,
                breaches_json=None,
                emails_json=None,
            )
            _db.session.add(br)
            _db.session.commit()

            fetched = _db.session.get(BreachResult, br.id)
            assert fetched.get_breaches() == []
            assert fetched.get_emails() == []

    def test_breach_result_corrupt_json_returns_defaults(self, app):
        """Corrupt JSON strings return empty lists, not exceptions."""
        with app.app_context():
            domain = Domain(hostname="corrupt-json.com")
            _db.session.add(domain)
            _db.session.flush()

            br = BreachResult(
                domain_id=domain.id,
                total_breaches=0,
                total_emails=0,
                breaches_json="{not valid json",
                emails_json="also broken[",
            )
            _db.session.add(br)
            _db.session.commit()

            fetched = _db.session.get(BreachResult, br.id)
            assert fetched.get_breaches() == []
            assert fetched.get_emails() == []


class TestBreachEntryModel:
    """Tests for the BreachEntry ORM model and its helpers."""

    def test_breach_entry_data_classes_helper(self, app):
        """get_data_classes() deserialises the stored JSON array correctly."""
        with app.app_context():
            domain = Domain(hostname="entry-test.com")
            _db.session.add(domain)
            _db.session.flush()

            data_classes = ["Email addresses", "Passwords", "Phone numbers"]
            entry = BreachEntry(
                domain_id=domain.id,
                breach_name="TestBreach",
                data_classes=json.dumps(data_classes),
                pwn_count=5000,
            )
            _db.session.add(entry)
            _db.session.commit()

            fetched = _db.session.get(BreachEntry, entry.id)
            assert fetched.get_data_classes() == data_classes

    def test_breach_entry_data_classes_null_returns_empty(self, app):
        """get_data_classes() returns empty list when field is NULL."""
        with app.app_context():
            domain = Domain(hostname="null-dc.com")
            _db.session.add(domain)
            _db.session.flush()

            entry = BreachEntry(
                domain_id=domain.id,
                breach_name="NullBreach",
                data_classes=None,
            )
            _db.session.add(entry)
            _db.session.commit()

            fetched = _db.session.get(BreachEntry, entry.id)
            assert fetched.get_data_classes() == []

    def test_breach_entry_unique_constraint(self, app):
        """Inserting two BreachEntry rows with the same domain_id + breach_name fails."""
        with app.app_context():
            domain = Domain(hostname="unique-test.com")
            _db.session.add(domain)
            _db.session.flush()

            entry1 = BreachEntry(
                domain_id=domain.id,
                breach_name="DuplicateBreach",
                pwn_count=100,
            )
            _db.session.add(entry1)
            _db.session.commit()

            entry2 = BreachEntry(
                domain_id=domain.id,
                breach_name="DuplicateBreach",
                pwn_count=200,
            )
            _db.session.add(entry2)

            with pytest.raises(Exception):
                _db.session.commit()

            _db.session.rollback()

    def test_breach_entry_different_domains_same_name_ok(self, app):
        """Same breach_name on different domains should not violate the constraint."""
        with app.app_context():
            d1 = Domain(hostname="domain-one.com")
            d2 = Domain(hostname="domain-two.com")
            _db.session.add_all([d1, d2])
            _db.session.flush()

            e1 = BreachEntry(domain_id=d1.id, breach_name="SharedBreach", pwn_count=10)
            e2 = BreachEntry(domain_id=d2.id, breach_name="SharedBreach", pwn_count=20)
            _db.session.add_all([e1, e2])
            _db.session.commit()

            assert e1.id is not None
            assert e2.id is not None


# =========================================================================
# 3. Acknowledgment Workflow Tests
# =========================================================================


class TestAcknowledgmentWorkflow:
    """Tests for the breach acknowledgment lifecycle on BreachEntry."""

    def test_acknowledge_sets_fields(self, app):
        """Setting acknowledged=True also records the user and timestamp."""
        with app.app_context():
            user = _db.session.execute(
                _db.select(User).filter_by(username="testuser")
            ).scalar_one()

            domain = Domain(hostname="ack-test.com")
            _db.session.add(domain)
            _db.session.flush()

            entry = BreachEntry(
                domain_id=domain.id,
                breach_name="AckBreach",
                pwn_count=500,
            )
            _db.session.add(entry)
            _db.session.commit()

            # Verify initial state
            assert entry.acknowledged is False
            assert entry.acknowledged_by is None
            assert entry.acknowledged_at is None

            # Acknowledge
            now = datetime.now(timezone.utc)
            entry.acknowledged = True
            entry.acknowledged_by = user.id
            entry.acknowledged_at = now
            _db.session.commit()

            fetched = _db.session.get(BreachEntry, entry.id)
            assert fetched.acknowledged is True
            assert fetched.acknowledged_by == user.id
            assert fetched.acknowledged_at is not None

    def test_unacknowledged_count_computation(self, app):
        """Counting unacknowledged entries across a domain returns the correct total."""
        with app.app_context():
            domain = Domain(hostname="count-test.com")
            _db.session.add(domain)
            _db.session.flush()

            # Create 3 unacknowledged + 2 acknowledged entries
            for i in range(3):
                _db.session.add(
                    BreachEntry(
                        domain_id=domain.id,
                        breach_name=f"UnackBreach{i}",
                        pwn_count=i * 100,
                        acknowledged=False,
                    )
                )

            for i in range(2):
                _db.session.add(
                    BreachEntry(
                        domain_id=domain.id,
                        breach_name=f"AckBreach{i}",
                        pwn_count=i * 100,
                        acknowledged=True,
                        acknowledged_at=datetime.now(timezone.utc),
                    )
                )

            _db.session.commit()

            unack_count = _db.session.query(BreachEntry).filter_by(
                domain_id=domain.id,
                acknowledged=False,
            ).count()

            assert unack_count == 3

            total_count = _db.session.query(BreachEntry).filter_by(
                domain_id=domain.id,
            ).count()

            assert total_count == 5

    def test_acknowledge_preserves_other_entries(self, app):
        """Acknowledging one entry does not affect sibling entries on the same domain."""
        with app.app_context():
            user = _db.session.execute(
                _db.select(User).filter_by(username="testuser")
            ).scalar_one()

            domain = Domain(hostname="preserve-test.com")
            _db.session.add(domain)
            _db.session.flush()

            entry_a = BreachEntry(
                domain_id=domain.id,
                breach_name="BreachA",
                pwn_count=100,
            )
            entry_b = BreachEntry(
                domain_id=domain.id,
                breach_name="BreachB",
                pwn_count=200,
            )
            _db.session.add_all([entry_a, entry_b])
            _db.session.commit()

            # Acknowledge only entry_a
            entry_a.acknowledged = True
            entry_a.acknowledged_by = user.id
            entry_a.acknowledged_at = datetime.now(timezone.utc)
            _db.session.commit()

            fetched_a = _db.session.get(BreachEntry, entry_a.id)
            fetched_b = _db.session.get(BreachEntry, entry_b.id)

            assert fetched_a.acknowledged is True
            assert fetched_b.acknowledged is False
            assert fetched_b.acknowledged_by is None
