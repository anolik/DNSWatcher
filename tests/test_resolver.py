"""
F34 - Unit tests for app/checker/resolver.py

All dns.resolver calls are mocked so no real network activity occurs.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver
import pytest


# ---------------------------------------------------------------------------
# Helper: build a fake dns.resolver answer object
# ---------------------------------------------------------------------------


def _make_rdata(value: bytes) -> MagicMock:
    """Return a mock rdata object whose .strings attribute returns *value*."""
    rdata = MagicMock()
    rdata.strings = [value]
    return rdata


def _make_answer(*txt_values: str) -> list:
    """Return a list of mock rdata objects for TXT records."""
    return [_make_rdata(v.encode()) for v in txt_values]


# ---------------------------------------------------------------------------
# Tests - successful resolution
# ---------------------------------------------------------------------------


def test_query_dns_successful_txt_resolution(app):
    """A successful TXT DNS query returns success=True and the record strings."""
    with app.app_context():
        mock_answer = _make_answer("v=spf1 -all")

        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.return_value = mock_answer
            instance.nameservers = ["8.8.8.8"]

            from app.checker.resolver import query_dns
            from app.models import DnsSettings
            settings = DnsSettings.query.get(1)
            result = query_dns("example.com", "TXT", settings)

    assert result["success"] is True
    assert result["error_type"] is None
    assert result["error_message"] is None
    assert "v=spf1 -all" in result["records"]


def test_query_dns_returns_all_records(app):
    """Multiple TXT records are all returned in the records list."""
    with app.app_context():
        mock_answer = _make_answer("v=spf1 -all", "some-other-record")

        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.return_value = mock_answer
            instance.nameservers = ["8.8.8.8"]

            from app.checker.resolver import query_dns
            from app.models import DnsSettings
            settings = DnsSettings.query.get(1)
            result = query_dns("example.com", "TXT", settings)

    assert result["success"] is True
    assert len(result["records"]) == 2


# ---------------------------------------------------------------------------
# Tests - NXDOMAIN
# ---------------------------------------------------------------------------


def test_query_dns_nxdomain_classified_correctly(app):
    """dns.resolver.NXDOMAIN should return error_type='NXDOMAIN'."""
    with app.app_context():
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.resolver.NXDOMAIN()
            instance.nameservers = ["8.8.8.8"]

            from app.checker.resolver import query_dns
            from app.models import DnsSettings
            settings = DnsSettings.query.get(1)
            result = query_dns("nonexistent.example.com", "TXT", settings)

    assert result["success"] is False
    assert result["error_type"] == "NXDOMAIN"
    assert result["records"] == []
    assert "NXDOMAIN" in (result["error_message"] or "")


# ---------------------------------------------------------------------------
# Tests - NoAnswer
# ---------------------------------------------------------------------------


def test_query_dns_no_answer_classified_correctly(app):
    """dns.resolver.NoAnswer should return error_type='NO_ANSWER'."""
    with app.app_context():
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.resolver.NoAnswer()
            instance.nameservers = ["8.8.8.8"]

            from app.checker.resolver import query_dns
            from app.models import DnsSettings
            settings = DnsSettings.query.get(1)
            result = query_dns("example.com", "TXT", settings)

    assert result["success"] is False
    assert result["error_type"] == "NO_ANSWER"
    assert result["records"] == []


# ---------------------------------------------------------------------------
# Tests - Timeout
# ---------------------------------------------------------------------------


def test_query_dns_timeout_classified_correctly(app):
    """dns.resolver.Timeout should return error_type='TIMEOUT'."""
    with app.app_context():
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.resolver.Timeout()
            instance.nameservers = ["8.8.8.8"]

            from app.checker.resolver import query_dns
            from app.models import DnsSettings
            settings = DnsSettings.query.get(1)
            result = query_dns("slow.example.com", "TXT", settings)

    assert result["success"] is False
    assert result["error_type"] == "TIMEOUT"
    assert result["records"] == []
    assert "timed out" in (result["error_message"] or "").lower()


# ---------------------------------------------------------------------------
# Tests - SERVFAIL / NoNameservers
# ---------------------------------------------------------------------------


def test_query_dns_no_nameservers_classified_as_dns_error(app):
    """dns.resolver.NoNameservers (SERVFAIL) should return error_type='DNS_ERROR'."""
    with app.app_context():
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.resolver.NoNameservers()
            instance.nameservers = ["8.8.8.8"]

            from app.checker.resolver import query_dns
            from app.models import DnsSettings
            settings = DnsSettings.query.get(1)
            result = query_dns("servfail.example.com", "TXT", settings)

    assert result["success"] is False
    assert result["error_type"] == "DNS_ERROR"
    assert result["records"] == []


# ---------------------------------------------------------------------------
# Tests - generic DNS exception
# ---------------------------------------------------------------------------


def test_query_dns_generic_dns_exception_classified_as_dns_error(app):
    """A generic dns.exception.DNSException should return error_type='DNS_ERROR'."""
    with app.app_context():
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.exception.DNSException("bad")
            instance.nameservers = ["8.8.8.8"]

            from app.checker.resolver import query_dns
            from app.models import DnsSettings
            settings = DnsSettings.query.get(1)
            result = query_dns("error.example.com", "TXT", settings)

    assert result["success"] is False
    assert result["error_type"] == "DNS_ERROR"


# ---------------------------------------------------------------------------
# Tests - unexpected exceptions
# ---------------------------------------------------------------------------


def test_query_dns_unexpected_exception_returns_dns_error(app):
    """An unexpected non-DNS exception should still return a safe error dict."""
    with app.app_context():
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = RuntimeError("something unexpected")
            instance.nameservers = ["8.8.8.8"]

            from app.checker.resolver import query_dns
            from app.models import DnsSettings
            settings = DnsSettings.query.get(1)
            result = query_dns("example.com", "TXT", settings)

    assert result["success"] is False
    assert result["error_type"] == "DNS_ERROR"
    assert result["records"] == []


# ---------------------------------------------------------------------------
# Tests - create_resolver configuration
# ---------------------------------------------------------------------------


def test_create_resolver_uses_settings_nameservers(app):
    """create_resolver should apply nameservers from DnsSettings."""
    with app.app_context():
        from app.checker.resolver import create_resolver
        from app.models import DnsSettings

        settings = DnsSettings.query.get(1)
        settings.set_resolvers(["9.9.9.9", "149.112.112.112"])

        resolver = create_resolver(settings)

    assert "9.9.9.9" in resolver.nameservers


def test_create_resolver_uses_settings_timeout(app):
    """create_resolver should set timeout from DnsSettings.timeout_seconds."""
    with app.app_context():
        from app.checker.resolver import create_resolver
        from app.models import DnsSettings

        settings = DnsSettings.query.get(1)
        settings.timeout_seconds = 7.5

        resolver = create_resolver(settings)

    assert resolver.timeout == 7.5


def test_create_resolver_falls_back_to_defaults_when_no_resolvers(app):
    """When the resolver list is empty, defaults (8.8.8.8, 1.1.1.1) are used."""
    with app.app_context():
        from app.checker.resolver import create_resolver
        from app.models import DnsSettings

        settings = DnsSettings.query.get(1)
        settings.set_resolvers([])

        resolver = create_resolver(settings)

    # Default fallback nameservers
    assert "8.8.8.8" in resolver.nameservers or "1.1.1.1" in resolver.nameservers
