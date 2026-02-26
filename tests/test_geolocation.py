"""
Unit tests for app/checker/geolocation.py

All DNS and HTTP calls are mocked so no real network activity occurs.
Covers: Canadian-only MX servers (Law 25 compliant), mixed-country scenarios,
all-foreign servers, empty MX input, DNS failures, GeoIP API failures,
private IP handling, IP lookup caching, provider identification,
Law 25 classification logic, and return structure validation.
"""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app_context(app):
    """Provide a Flask application context for tests that don't need the
    full app fixture directly but require an active context for imports
    and database access."""
    with app.app_context():
        yield


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


def _dns_failure(error_type: str = "NXDOMAIN", msg: str = "not found") -> dict:
    """Simulate a failed query_dns result."""
    return {
        "success": False,
        "records": [],
        "error_type": error_type,
        "error_message": msg,
    }


def _geoip_response(
    country_code: str,
    country_name: str,
    city: str = "Toronto",
    org: str = "Example ISP",
    isp: str = "Example ISP",
) -> MagicMock:
    """Build a mock urllib response returning a successful ip-api.com JSON body."""
    data = {
        "status": "success",
        "country": country_name,
        "countryCode": country_code,
        "city": city,
        "isp": isp,
        "org": org,
    }
    body = json.dumps(data).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _geoip_failure_response(message: str = "invalid query") -> MagicMock:
    """Build a mock urllib response returning a failed ip-api.com JSON body."""
    data = {
        "status": "fail",
        "message": message,
    }
    body = json.dumps(data).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# Tests - all servers in Canada (Law 25 compliant)
# ---------------------------------------------------------------------------


class TestAllCanada:
    """When every MX server resolves to a Canadian IP, Law 25 status
    should be 'compliant'."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_all_canada(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """All MX servers in Canada should yield law25_status='compliant'."""
        mock_query_dns.return_value = _dns_success(["1.2.3.4"])
        mock_urlopen.return_value = _geoip_response("CA", "Canada", "Montreal", "Bell Canada")

        mx_records = [
            {"priority": 10, "exchange": "mx1.example.ca"},
            {"priority": 20, "exchange": "mx2.example.ca"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] == "compliant"
        assert len(result["servers"]) == 2
        assert all(s["country_code"] == "CA" for s in result["servers"])
        assert result["countries"] == ["CA"]
        assert result["error"] is None

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_single_canadian_mx(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """A single Canadian MX server should be compliant."""
        mock_query_dns.return_value = _dns_success(["52.101.190.1"])
        mock_urlopen.return_value = _geoip_response(
            "CA", "Canada", "Toronto", "Microsoft Azure Cloud (canadacentral)"
        )

        mx_records = [{"priority": 10, "exchange": "mail.example.ca"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] == "compliant"
        assert result["servers"][0]["country_code"] == "CA"
        assert result["servers"][0]["country_name"] == "Canada"
        assert "Microsoft Azure" in result["servers"][0]["description"]


# ---------------------------------------------------------------------------
# Tests - mixed countries (review needed)
# ---------------------------------------------------------------------------


class TestMixedCountries:
    """When MX servers are spread across Canada and other countries,
    Law 25 status should be 'review_needed'."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_mixed_countries(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Mix of CA and US servers should yield law25_status='review_needed'."""
        mock_query_dns.side_effect = [
            _dns_success(["1.1.1.1"]),
            _dns_success(["2.2.2.2"]),
        ]

        mock_urlopen.side_effect = [
            _geoip_response("CA", "Canada", "Montreal", "Rogers Communications"),
            _geoip_response("US", "United States", "Ashburn", "Google LLC"),
        ]

        mx_records = [
            {"priority": 10, "exchange": "mx1.example.ca"},
            {"priority": 20, "exchange": "mx2.example.com"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] == "review_needed"
        assert len(result["servers"]) == 2
        assert "CA" in result["countries"]
        assert "US" in result["countries"]
        assert result["error"] is None

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_ca_and_de_servers(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Canada + Germany should also be review_needed."""
        mock_query_dns.side_effect = [
            _dns_success(["3.3.3.3"]),
            _dns_success(["4.4.4.4"]),
        ]

        mock_urlopen.side_effect = [
            _geoip_response("CA", "Canada", "Toronto", "Telus"),
            _geoip_response("DE", "Germany", "Falkenstein", "Hetzner"),
        ]

        mx_records = [
            {"priority": 10, "exchange": "mx.canada.ca"},
            {"priority": 20, "exchange": "mx.germany.de"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] == "review_needed"
        assert set(result["countries"]) == {"CA", "DE"}


# ---------------------------------------------------------------------------
# Tests - all foreign (review needed)
# ---------------------------------------------------------------------------


class TestAllForeign:
    """When all MX servers are outside Canada, Law 25 status should be
    'review_needed'."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_all_foreign(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """All US servers should yield law25_status='review_needed'."""
        mock_query_dns.return_value = _dns_success(["5.5.5.5"])
        mock_urlopen.return_value = _geoip_response(
            "US", "United States", "Ashburn", "Amazon AES"
        )

        mx_records = [
            {"priority": 10, "exchange": "mx1.us-east.example.com"},
            {"priority": 20, "exchange": "mx2.us-west.example.com"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] == "review_needed"
        assert all(s["country_code"] == "US" for s in result["servers"])
        assert result["countries"] == ["US"]
        assert "quebec law 25" in result["law25_details"].lower()


# ---------------------------------------------------------------------------
# Tests - empty MX records
# ---------------------------------------------------------------------------


class TestEmptyMx:
    """When no MX records are provided, the result should reflect
    that no geolocation data is available."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_empty_mx(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Empty MX list should return empty servers and law25_status='unknown'."""
        from app.checker.geolocation import check_geolocation

        result = check_geolocation([])

        assert result["servers"] == []
        assert result["countries"] == []
        assert result["law25_status"] == "unknown"
        assert result["error"] is not None  # explains no MX records
        mock_query_dns.assert_not_called()
        mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# Tests - DNS resolution failures
# ---------------------------------------------------------------------------


class TestDnsFailure:
    """When DNS resolution fails for all MX exchanges, the module should
    handle errors gracefully."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_dns_failure_all(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """All DNS failures should yield law25_status='unknown'."""
        mock_query_dns.return_value = _dns_failure("TIMEOUT", "DNS query timed out")

        mx_records = [
            {"priority": 10, "exchange": "mx1.example.com"},
            {"priority": 20, "exchange": "mx2.example.com"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] == "unknown"
        mock_urlopen.assert_not_called()

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_partial_dns_failure(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """When only some DNS lookups fail, resolved servers should still
        be geolocated and contribute to the Law 25 assessment."""
        mock_query_dns.side_effect = [
            _dns_success(["6.6.6.6"]),
            _dns_failure("NXDOMAIN", "not found"),
        ]

        mock_urlopen.return_value = _geoip_response("CA", "Canada", "Quebec", "Videotron")

        mx_records = [
            {"priority": 10, "exchange": "mx1.example.ca"},
            {"priority": 20, "exchange": "mx2.broken.ca"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] in ("compliant", "review_needed")
        assert any(s["country_code"] == "CA" for s in result["servers"])


# ---------------------------------------------------------------------------
# Tests - GeoIP API failures
# ---------------------------------------------------------------------------


class TestGeoipApiFailure:
    """When the ip-api.com request fails or returns an error, the server
    should still appear in results but with country data set to None."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_api_failure_exception(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """urllib exception should be handled gracefully."""
        import urllib.error

        mock_query_dns.return_value = _dns_success(["7.7.7.7"])
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        mx_records = [{"priority": 10, "exchange": "mx.example.com"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert len(result["servers"]) == 1
        assert result["servers"][0]["country_code"] is None
        assert result["law25_status"] == "unknown"

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_api_failure_response(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """ip-api.com returning status='fail' should be handled gracefully."""
        mock_query_dns.return_value = _dns_success(["7.7.7.7"])
        mock_urlopen.return_value = _geoip_failure_response("invalid query")

        mx_records = [{"priority": 10, "exchange": "mx.example.com"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert len(result["servers"]) == 1
        assert result["servers"][0]["country_code"] is None
        assert result["law25_status"] == "unknown"

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_api_failure_partial(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """When one GeoIP lookup fails but another succeeds, the successful
        one should still contribute to the assessment."""
        mock_query_dns.side_effect = [
            _dns_success(["8.8.8.8"]),
            _dns_success(["9.9.9.9"]),
        ]

        import urllib.error

        mock_urlopen.side_effect = [
            _geoip_response("CA", "Canada", "Toronto", "TekSavvy"),
            urllib.error.URLError("Connection refused"),
        ]

        mx_records = [
            {"priority": 10, "exchange": "mx1.example.ca"},
            {"priority": 20, "exchange": "mx2.broken.com"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert len(result["servers"]) == 2
        assert result["servers"][0]["country_code"] == "CA"
        assert result["servers"][1]["country_code"] is None


# ---------------------------------------------------------------------------
# Tests - private / reserved IP addresses
# ---------------------------------------------------------------------------


class TestPrivateIp:
    """Private and reserved IP addresses should be detected locally
    without making an API call."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_private_ip(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Private IP (192.168.x.x) should be handled without API call."""
        mock_query_dns.return_value = _dns_success(["192.168.1.1"])

        mx_records = [{"priority": 10, "exchange": "mx.internal.local"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert len(result["servers"]) == 1
        assert result["servers"][0]["country_code"] is None
        assert result["law25_status"] == "unknown"
        # No API call should be made for private IPs
        mock_urlopen.assert_not_called()

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_loopback_ip(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Loopback IP (127.0.0.1) should be handled without API call."""
        mock_query_dns.return_value = _dns_success(["127.0.0.1"])

        mx_records = [{"priority": 10, "exchange": "localhost"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert len(result["servers"]) == 1
        assert result["servers"][0]["country_code"] is None
        mock_urlopen.assert_not_called()

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_rfc1918_10_network(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """10.x.x.x private range should skip API call."""
        mock_query_dns.return_value = _dns_success(["10.0.0.1"])

        mx_records = [{"priority": 10, "exchange": "mx.corp.local"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["servers"][0]["country_code"] is None
        mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# Tests - IP lookup caching
# ---------------------------------------------------------------------------


class TestIpCaching:
    """When the same IP appears for multiple MX exchanges, the GeoIP
    lookup should only be performed once (caching)."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_check_geolocation_caches_ip_lookups(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Duplicate IPs across MX records should trigger only one API call."""
        # All MX exchanges resolve to the same public IP
        mock_query_dns.return_value = _dns_success(["24.20.30.40"])
        mock_urlopen.return_value = _geoip_response("CA", "Canada", "Quebec", "Cogeco")

        mx_records = [
            {"priority": 10, "exchange": "mx1.example.ca"},
            {"priority": 20, "exchange": "mx2.example.ca"},
            {"priority": 30, "exchange": "mx3.example.ca"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        # All three servers should have CA country code
        assert len(result["servers"]) == 3
        assert all(s["country_code"] == "CA" for s in result["servers"])

        # urlopen should have been called only once (cached for same IP)
        assert mock_urlopen.call_count == 1

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_different_ips_not_cached(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Different IPs should each trigger their own API lookup."""
        mock_query_dns.side_effect = [
            _dns_success(["1.1.1.1"]),
            _dns_success(["2.2.2.2"]),
        ]

        mock_urlopen.side_effect = [
            _geoip_response("CA", "Canada", "Montreal", "ISP-A"),
            _geoip_response("US", "United States", "Ashburn", "ISP-B"),
        ]

        mx_records = [
            {"priority": 10, "exchange": "mx1.example.ca"},
            {"priority": 20, "exchange": "mx2.example.com"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert mock_urlopen.call_count == 2


# ---------------------------------------------------------------------------
# Tests - Law 25 status classification logic
# ---------------------------------------------------------------------------


class TestLaw25StatusClassification:
    """Test the Law 25 classification logic for various country combinations."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_law25_status_classification_all_ca(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """100% Canadian servers should be 'compliant'."""
        mock_query_dns.return_value = _dns_success(["1.2.3.4"])
        mock_urlopen.return_value = _geoip_response("CA", "Canada", "Toronto", "Canadian ISP")

        mx_records = [{"priority": 10, "exchange": "mx.ca.example.com"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)
        assert result["law25_status"] == "compliant"

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_law25_status_classification_no_ca(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Zero Canadian servers should be 'review_needed'."""
        mock_query_dns.return_value = _dns_success(["5.6.7.8"])
        mock_urlopen.return_value = _geoip_response("US", "United States", "Ashburn", "US-ISP")

        mx_records = [{"priority": 10, "exchange": "mx.us.example.com"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)
        assert result["law25_status"] == "review_needed"

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_law25_status_classification_mixed(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Mix of CA and non-CA should be 'review_needed'."""
        mock_query_dns.side_effect = [
            _dns_success(["1.1.1.1"]),
            _dns_success(["2.2.2.2"]),
            _dns_success(["3.3.3.3"]),
        ]

        mock_urlopen.side_effect = [
            _geoip_response("CA", "Canada", "Montreal", "ISP-CA"),
            _geoip_response("US", "United States", "Ashburn", "ISP-US"),
            _geoip_response("CA", "Canada", "Toronto", "ISP-CA2"),
        ]

        mx_records = [
            {"priority": 10, "exchange": "mx1.example.ca"},
            {"priority": 20, "exchange": "mx2.example.com"},
            {"priority": 30, "exchange": "mx3.example.ca"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)
        assert result["law25_status"] == "review_needed"

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_law25_status_classification_unknown_country(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """When country cannot be determined for any server, status is 'unknown'."""
        import urllib.error

        mock_query_dns.return_value = _dns_success(["9.9.9.9"])
        mock_urlopen.side_effect = urllib.error.URLError("Lookup failed")

        mx_records = [{"priority": 10, "exchange": "mx.mystery.example.com"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)
        assert result["law25_status"] == "unknown"

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_law25_details_mentions_countries(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """The law25_details field should mention the countries found."""
        mock_query_dns.side_effect = [
            _dns_success(["1.1.1.1"]),
            _dns_success(["2.2.2.2"]),
        ]

        mock_urlopen.side_effect = [
            _geoip_response("CA", "Canada", "Montreal", "Bell"),
            _geoip_response("FR", "France", "Roubaix", "OVH SAS"),
        ]

        mx_records = [
            {"priority": 10, "exchange": "mx1.ca.example.com"},
            {"priority": 20, "exchange": "mx2.fr.example.com"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)
        assert result["law25_details"] is not None
        assert len(result["law25_details"]) > 0


# ---------------------------------------------------------------------------
# Tests - cloud provider identification and notes
# ---------------------------------------------------------------------------


class TestProviderIdentification:
    """Test that cloud providers are identified from MX hostnames and
    compliance notes are included in Law 25 details."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_microsoft_365_provider_note(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Microsoft 365 MX should include provider compliance note."""
        mock_query_dns.return_value = _dns_success(["52.101.190.1"])
        mock_urlopen.return_value = _geoip_response(
            "US", "United States", "Ashburn", "Microsoft Corporation"
        )

        mx_records = [
            {"priority": 10, "exchange": "domain-com.mail.protection.outlook.com"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] == "review_needed"
        assert "Microsoft 365" in result["law25_details"]

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_google_workspace_provider_note(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Google Workspace MX should include provider compliance note."""
        mock_query_dns.return_value = _dns_success(["142.250.1.27"])
        mock_urlopen.return_value = _geoip_response(
            "US", "United States", "Mountain View", "Google LLC"
        )

        mx_records = [
            {"priority": 10, "exchange": "alt1.aspmx.l.google.com"},
        ]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert result["law25_status"] == "review_needed"
        assert "Google Workspace" in result["law25_details"]


# ---------------------------------------------------------------------------
# Tests - settings pass-through
# ---------------------------------------------------------------------------


class TestSettingsPassthrough:
    """Verify that DnsSettings are forwarded to query_dns calls."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_settings_passed_to_query_dns(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """When settings are provided, they should be passed to query_dns."""
        mock_query_dns.return_value = _dns_success(["1.2.3.4"])
        mock_urlopen.return_value = _geoip_response("CA", "Canada", "Toronto", "ISP")

        from app.models import DnsSettings

        settings = DnsSettings(timeout_seconds=5.0, retries=3)
        mx_records = [{"priority": 10, "exchange": "mx.example.ca"}]

        from app.checker.geolocation import check_geolocation

        check_geolocation(mx_records, settings=settings)

        # Verify query_dns was called with the exchange, "A", and our settings
        mock_query_dns.assert_called_once()
        args = mock_query_dns.call_args
        assert args[0][0] == "mx.example.ca"
        assert args[0][1] == "A"
        assert args[0][2] is settings or args[1].get("settings") is settings \
            or (len(args[0]) > 2 and args[0][2] is settings)


# ---------------------------------------------------------------------------
# Tests - return structure validation
# ---------------------------------------------------------------------------


class TestReturnStructure:
    """Verify that the return dict always contains the expected keys
    regardless of input conditions."""

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_return_keys_present_success(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Successful lookup should return all documented keys."""
        mock_query_dns.return_value = _dns_success(["1.2.3.4"])
        mock_urlopen.return_value = _geoip_response("CA", "Canada", "Toronto", "ISP")

        mx_records = [{"priority": 10, "exchange": "mx.example.ca"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        assert "servers" in result
        assert "countries" in result
        assert "law25_status" in result
        assert "law25_details" in result
        assert "error" in result

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_return_keys_present_empty(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Empty MX list should still return all documented keys."""
        from app.checker.geolocation import check_geolocation

        result = check_geolocation([])

        assert "servers" in result
        assert "countries" in result
        assert "law25_status" in result
        assert "law25_details" in result
        assert "error" in result

    @patch("app.checker.geolocation.urllib.request.urlopen")
    @patch("app.checker.geolocation.query_dns")
    def test_server_entry_keys(
        self, mock_query_dns, mock_urlopen, app_context
    ):
        """Each server entry should contain the documented fields."""
        mock_query_dns.return_value = _dns_success(["1.2.3.4"])
        mock_urlopen.return_value = _geoip_response(
            "CA", "Canada", "Toronto", "Shaw Communications"
        )

        mx_records = [{"priority": 10, "exchange": "mx.example.ca"}]

        from app.checker.geolocation import check_geolocation

        result = check_geolocation(mx_records)

        server = result["servers"][0]
        assert "exchange" in server
        assert "ip" in server
        assert "country_code" in server
        assert "country_name" in server
        assert "description" in server
        assert server["exchange"] == "mx.example.ca"
        assert server["ip"] == "1.2.3.4"
        assert server["country_code"] == "CA"
        assert server["country_name"] == "Canada"
        assert "Shaw Communications" in server["description"]
