"""
Unit tests for app/checker/registrar.py

All RDAP and WHOIS calls are mocked so no real network activity occurs.
Covers: RDAP success, round-robin, RDAP-to-WHOIS fallback, RFC 9083 parsing,
WHOIS-only paths, date handling, and name server normalization.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_whois_module():
    """Inject a fake ``whois`` module into sys.modules for tests."""
    mock_module = MagicMock()
    with patch.dict(sys.modules, {"whois": mock_module}):
        yield mock_module


def _make_rdap_response(
    registrar_name: str = "GoDaddy.com, LLC",
    registrar_handle: str = "146",
    registration_date: str = "2020-01-15T00:00:00Z",
    expiration_date: str = "2026-01-15T00:00:00Z",
    nameservers: list[str] | None = None,
) -> dict:
    """Build a minimal RFC 9083 RDAP domain response."""
    if nameservers is None:
        nameservers = ["ns1.example.com", "ns2.example.com"]
    return {
        "objectClassName": "domain",
        "ldhName": "example.com",
        "entities": [
            {
                "objectClassName": "entity",
                "handle": registrar_handle,
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", registrar_name],
                    ],
                ],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": registration_date},
            {"eventAction": "expiration", "eventDate": expiration_date},
        ],
        "nameservers": [
            {"objectClassName": "nameserver", "ldhName": ns}
            for ns in nameservers
        ],
    }


# ---------------------------------------------------------------------------
# Tests – RDAP success (via requests.get)
# ---------------------------------------------------------------------------


class TestRdapSuccess:
    """Test RDAP lookup when requests.get returns valid RFC 9083 JSON."""

    @patch("app.checker.registrar.requests.get")
    def test_basic_rdap_lookup(self, mock_get, app):
        """RDAP response should parse registrar, dates, and nameservers."""
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _make_rdap_response()
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com", rdap_servers=["https://rdap.org"])

        assert result["registrar"] == "GoDaddy.com, LLC"
        assert result["creation_date"] is not None
        assert "2020" in result["creation_date"]
        assert result["expiration_date"] is not None
        assert "2026" in result["expiration_date"]
        assert result["name_servers"] == ["ns1.example.com", "ns2.example.com"]
        assert result["lookup_method"] == "rdap"
        assert result["error"] is None

        # Verify the correct URL was called
        call_url = mock_get.call_args[0][0]
        assert call_url == "https://rdap.org/domain/example.com"

    @patch("app.checker.registrar.requests.get")
    def test_rdap_accept_header(self, mock_get, app):
        """RDAP requests should include the application/rdap+json Accept header."""
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.json.return_value = _make_rdap_response()
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            from app.checker.registrar import check_registrar

            check_registrar("example.com", rdap_servers=["https://rdap.org"])

        headers = mock_get.call_args[1].get("headers", {})
        assert headers.get("Accept") == "application/rdap+json"


# ---------------------------------------------------------------------------
# Tests – RDAP round-robin
# ---------------------------------------------------------------------------


class TestRdapRoundRobin:
    """Test that RDAP requests rotate through server list."""

    @patch("app.checker.registrar.requests.get")
    def test_round_robin_cycles_servers(self, mock_get, app):
        """Consecutive calls should cycle through the server list."""
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.json.return_value = _make_rdap_response()
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            from app.checker.registrar import check_registrar

            servers = ["https://server-a.example", "https://server-b.example"]

            # Call twice to see rotation
            check_registrar("a.com", rdap_servers=servers)
            check_registrar("b.com", rdap_servers=servers)

            urls = [call[0][0] for call in mock_get.call_args_list]
            # Both servers should appear (order depends on counter state)
            server_bases = {url.rsplit("/domain/", 1)[0] for url in urls}
            assert len(server_bases) == 2


# ---------------------------------------------------------------------------
# Tests – RDAP fallback to WHOIS
# ---------------------------------------------------------------------------


class TestRdapFallbackToWhois:
    """Test that WHOIS is called when RDAP fails."""

    @patch("app.checker.registrar.requests.get")
    def test_rdap_http_error_falls_back_to_whois(
        self, mock_get, fake_whois_module, app
    ):
        """When RDAP returns an HTTP error, WHOIS should be used."""
        with app.app_context():
            mock_get.side_effect = requests.HTTPError("429 Too Many Requests")

            fake_whois_module.whois.return_value = SimpleNamespace(
                registrar="Japan Registry Services",
                creation_date=datetime(2018, 5, 10, tzinfo=timezone.utc),
                expiration_date=datetime(2025, 5, 10, tzinfo=timezone.utc),
                name_servers=["ns1.jprs.jp", "ns2.jprs.jp"],
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.jp", rdap_servers=["https://rdap.org"])

        assert result["registrar"] == "Japan Registry Services"
        assert result["lookup_method"] == "whois"
        assert result["error"] is None

    @patch("app.checker.registrar.requests.get")
    def test_rdap_timeout_falls_back_to_whois(
        self, mock_get, fake_whois_module, app
    ):
        """When RDAP times out, WHOIS should be used."""
        with app.app_context():
            mock_get.side_effect = requests.Timeout("Connection timed out")

            fake_whois_module.whois.return_value = SimpleNamespace(
                registrar="Namecheap, Inc.",
                creation_date=datetime(2019, 1, 1, tzinfo=timezone.utc),
                expiration_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
                name_servers=["dns1.registrar-servers.com"],
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com", rdap_servers=["https://rdap.org"])

        assert result["registrar"] == "Namecheap, Inc."
        assert result["lookup_method"] == "whois"

    @patch("app.checker.registrar.requests.get")
    def test_empty_servers_list_goes_to_whois(
        self, mock_get, fake_whois_module, app
    ):
        """When rdap_servers is empty, WHOIS should be used directly."""
        with app.app_context():
            fake_whois_module.whois.return_value = SimpleNamespace(
                registrar="Namecheap, Inc.",
                creation_date=datetime(2019, 1, 1, tzinfo=timezone.utc),
                expiration_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
                name_servers=["dns1.registrar-servers.com"],
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com", rdap_servers=[])

        assert result["registrar"] == "Namecheap, Inc."
        assert result["lookup_method"] == "whois"
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# Tests – RFC 9083 parsing edge cases
# ---------------------------------------------------------------------------


class TestRfc9083Parsing:
    """Test RDAP RFC 9083 response parsing edge cases."""

    def test_no_entities(self, app):
        """Response with no entities should return None registrar."""
        from app.checker.registrar import _parse_rdap_response

        data = {
            "events": [
                {"eventAction": "registration", "eventDate": "2021-03-01T00:00:00Z"},
            ],
            "nameservers": [{"ldhName": "ns1.example.com"}],
        }
        result = _parse_rdap_response(data)
        assert result["registrar"] is None
        assert result["name_servers"] == ["ns1.example.com"]

    def test_registrar_from_handle(self, app):
        """If no vcardArray fn, fall back to entity handle."""
        from app.checker.registrar import _parse_rdap_response

        data = {
            "entities": [
                {
                    "handle": "REG-123",
                    "roles": ["registrar"],
                }
            ],
            "events": [],
            "nameservers": [],
        }
        result = _parse_rdap_response(data)
        assert result["registrar"] == "REG-123"

    def test_multiple_events(self, app):
        """Both registration and expiration events should be extracted."""
        from app.checker.registrar import _parse_rdap_response

        data = {
            "entities": [],
            "events": [
                {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"},
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ],
            "nameservers": [],
        }
        result = _parse_rdap_response(data)
        assert "2020" in result["creation_date"]
        assert "2030" in result["expiration_date"]

    def test_empty_response(self, app):
        """Completely empty response should return safe defaults."""
        from app.checker.registrar import _parse_rdap_response

        result = _parse_rdap_response({})
        assert result["registrar"] is None
        assert result["creation_date"] is None
        assert result["expiration_date"] is None
        assert result["name_servers"] == []
        assert result["lookup_method"] == "rdap"

    def test_non_registrar_entities_skipped(self, app):
        """Entities without 'registrar' role should be ignored."""
        from app.checker.registrar import _parse_rdap_response

        data = {
            "entities": [
                {
                    "handle": "ABUSE-CONTACT",
                    "roles": ["abuse"],
                },
                {
                    "handle": "REG-456",
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [["fn", {}, "text", "Test Registrar"]],
                    ],
                },
            ],
            "events": [],
            "nameservers": [],
        }
        result = _parse_rdap_response(data)
        assert result["registrar"] == "Test Registrar"


# ---------------------------------------------------------------------------
# Tests – successful WHOIS lookup (no RDAP servers)
# ---------------------------------------------------------------------------


class TestCheckRegistrarSuccess:
    """Test check_registrar() with a successful WHOIS response."""

    @patch("app.checker.registrar.requests.get")
    def test_basic_registrar_lookup_whois_only(self, mock_get, fake_whois_module, app):
        """WHOIS-only path when RDAP servers list is empty."""
        with app.app_context():
            fake_whois_module.whois.return_value = SimpleNamespace(
                registrar="GoDaddy.com, LLC",
                creation_date=datetime(2020, 1, 15, tzinfo=timezone.utc),
                expiration_date=datetime(2026, 1, 15, tzinfo=timezone.utc),
                name_servers=["ns1.example.com", "ns2.example.com"],
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com", rdap_servers=[])

        assert result["registrar"] == "GoDaddy.com, LLC"
        assert result["creation_date"] is not None
        assert "2020" in result["creation_date"]
        assert result["expiration_date"] is not None
        assert "2026" in result["expiration_date"]
        assert len(result["name_servers"]) == 2
        assert result["lookup_method"] == "whois"
        assert result["error"] is None
        mock_get.assert_not_called()

    @patch("app.checker.registrar.requests.get")
    def test_date_list_handling(self, mock_get, fake_whois_module, app):
        """Some TLDs return a list of dates; we should take the first one."""
        with app.app_context():
            fake_whois_module.whois.return_value = SimpleNamespace(
                registrar="Namecheap, Inc.",
                creation_date=[
                    datetime(2019, 6, 1, tzinfo=timezone.utc),
                    datetime(2019, 6, 2, tzinfo=timezone.utc),
                ],
                expiration_date=[
                    datetime(2025, 6, 1, tzinfo=timezone.utc),
                ],
                name_servers=["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com", rdap_servers=[])

        assert "2019" in result["creation_date"]
        assert "2025" in result["expiration_date"]
        assert result["error"] is None

    @patch("app.checker.registrar.requests.get")
    def test_name_servers_deduplicated_and_lowered(self, mock_get, fake_whois_module, app):
        """Name servers should be deduplicated, lowercased, and sorted."""
        with app.app_context():
            fake_whois_module.whois.return_value = SimpleNamespace(
                registrar="Test Registrar",
                creation_date=None,
                expiration_date=None,
                name_servers=["NS2.EXAMPLE.COM.", "ns1.example.com", "NS2.EXAMPLE.COM"],
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com", rdap_servers=[])

        assert result["name_servers"] == ["ns1.example.com", "ns2.example.com"]

    @patch("app.checker.registrar.requests.get")
    def test_none_registrar_returns_none(self, mock_get, fake_whois_module, app):
        """If WHOIS returns None for registrar, result should be None."""
        with app.app_context():
            fake_whois_module.whois.return_value = SimpleNamespace(
                registrar=None,
                creation_date=None,
                expiration_date=None,
                name_servers=None,
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com", rdap_servers=[])

        assert result["registrar"] is None
        assert result["name_servers"] == []
        assert result["error"] is None


# ---------------------------------------------------------------------------
# Tests – WHOIS failures
# ---------------------------------------------------------------------------


class TestCheckRegistrarFailure:
    """Test check_registrar() when WHOIS lookups fail."""

    @patch("app.checker.registrar.requests.get")
    def test_whois_exception_returns_error(self, mock_get, fake_whois_module, app):
        """WHOIS exceptions should be caught and returned as error."""
        with app.app_context():
            # RDAP fails too
            mock_get.side_effect = requests.ConnectionError("refused")
            fake_whois_module.whois.side_effect = Exception("Connection timed out")

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com", rdap_servers=["https://rdap.org"])

        assert result["registrar"] is None
        assert result["error"] is not None
        assert "timed out" in result["error"].lower()


# ---------------------------------------------------------------------------
# Tests – ImportError fallback
# ---------------------------------------------------------------------------


class TestCheckRegistrarImportError:
    """Test check_registrar() when whois library is not importable."""

    @patch("app.checker.registrar.requests.get")
    def test_import_error_graceful_fallback(self, mock_get, app):
        """If whois module is not importable, return error gracefully."""
        with app.app_context():
            # RDAP fails
            mock_get.side_effect = requests.ConnectionError("refused")

            import builtins

            original_import = builtins.__import__

            def mock_import(name, *args, **kwargs):
                if name == "whois":
                    raise ImportError(f"No module named '{name}'")
                return original_import(name, *args, **kwargs)

            with patch.object(builtins, "__import__", side_effect=mock_import):
                from app.checker.registrar import check_registrar

                result = check_registrar("example.com", rdap_servers=["https://rdap.org"])

            assert result["registrar"] is None
            assert "not installed" in result["error"].lower()


# ---------------------------------------------------------------------------
# Tests – default servers
# ---------------------------------------------------------------------------


class TestDefaultServers:
    """Test that default servers are used when None is passed."""

    @patch("app.checker.registrar.requests.get")
    def test_none_servers_uses_default(self, mock_get, app):
        """Passing rdap_servers=None should use the default server list."""
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.json.return_value = _make_rdap_response()
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com")

        assert result["lookup_method"] == "rdap"
        call_url = mock_get.call_args[0][0]
        assert "rdap.org" in call_url


# ---------------------------------------------------------------------------
# Tests – RDAP throttle
# ---------------------------------------------------------------------------


class TestRdapThrottle:
    """Test the RDAP request throttling mechanism."""

    @patch("app.checker.registrar.requests.get")
    def test_throttle_enforces_delay(self, mock_get, app):
        """Two rapid calls with throttle_delay should take at least that long."""
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.json.return_value = _make_rdap_response()
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            import app.checker.registrar as reg

            # Reset the module-level last-request timestamp so previous
            # tests don't interfere.
            reg._last_request_time = 0.0

            from app.checker.registrar import check_registrar

            delay = 0.3  # short delay for test speed
            t0 = time.monotonic()
            check_registrar("a.com", rdap_servers=["https://rdap.org"], throttle_delay=delay)
            check_registrar("b.com", rdap_servers=["https://rdap.org"], throttle_delay=delay)
            elapsed = time.monotonic() - t0

        # The second call should have waited ~delay seconds
        assert elapsed >= delay * 0.9, f"Expected >= {delay * 0.9:.2f}s, got {elapsed:.2f}s"

    @patch("app.checker.registrar.requests.get")
    def test_throttle_zero_disables(self, mock_get, app):
        """throttle_delay=0 should add no artificial wait."""
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.json.return_value = _make_rdap_response()
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            import app.checker.registrar as reg

            reg._last_request_time = 0.0

            from app.checker.registrar import check_registrar

            t0 = time.monotonic()
            check_registrar("a.com", rdap_servers=["https://rdap.org"], throttle_delay=0)
            check_registrar("b.com", rdap_servers=["https://rdap.org"], throttle_delay=0)
            elapsed = time.monotonic() - t0

        # Without throttle, both calls should complete very quickly
        assert elapsed < 1.0, f"Expected < 1.0s, got {elapsed:.2f}s"

    @patch("app.checker.registrar.requests.get")
    def test_throttle_none_uses_default(self, mock_get, app):
        """throttle_delay=None should use the module default (2.0s)."""
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.json.return_value = _make_rdap_response()
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            import app.checker.registrar as reg

            # Patch the default to a short value so the test doesn't wait 2s
            original_default = reg._DEFAULT_THROTTLE_DELAY
            reg._DEFAULT_THROTTLE_DELAY = 0.2
            reg._last_request_time = 0.0

            try:
                from app.checker.registrar import check_registrar

                t0 = time.monotonic()
                check_registrar("a.com", rdap_servers=["https://rdap.org"], throttle_delay=None)
                check_registrar("b.com", rdap_servers=["https://rdap.org"], throttle_delay=None)
                elapsed = time.monotonic() - t0
            finally:
                reg._DEFAULT_THROTTLE_DELAY = original_default

        # Should have waited at least the patched default
        assert elapsed >= 0.15, f"Expected >= 0.15s, got {elapsed:.2f}s"
