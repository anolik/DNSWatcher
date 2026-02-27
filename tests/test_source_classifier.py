"""Unit tests for app/dmarc_reports/source_classifier.py

All DNS calls are mocked — no real network access.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.name
import dns.resolver
import pytest

from app.dmarc_reports.source_classifier import (
    _match_provider,
    _lookup_ptr,
    classify_sources,
)


# ---------------------------------------------------------------------------
# Tests - _match_provider
# ---------------------------------------------------------------------------


def test_match_google():
    """Google hostnames are matched."""
    assert _match_provider("mail-lf1-f41.google.com") == "Google"
    assert _match_provider("smtp.googlemail.com") == "Google"


def test_match_microsoft():
    """Microsoft hostnames are matched."""
    assert _match_provider("mail-bn1.protection.outlook.com") == "Microsoft"
    assert _match_provider("smtp.outlook.com") == "Microsoft"


def test_match_sendgrid():
    """SendGrid hostnames are matched."""
    assert _match_provider("o1.ptr1234.sendgrid.net") == "SendGrid"


def test_match_amazon_ses():
    """Amazon SES hostnames are matched."""
    assert _match_provider("a1-23.smtp-out.amazonses.com") == "Amazon SES"


def test_unknown_hostname():
    """Unknown hostnames return None."""
    assert _match_provider("mail.unknowndomain.example") is None


def test_exact_domain_match():
    """Exact domain (without subdomain) also matches."""
    assert _match_provider("google.com") == "Google"


def test_case_insensitive():
    """Matching is case-insensitive."""
    assert _match_provider("MAIL.GOOGLE.COM") == "Google"


def test_trailing_dot():
    """Trailing dots in PTR hostnames are handled."""
    assert _match_provider("mail.google.com.") == "Google"


# ---------------------------------------------------------------------------
# Tests - _lookup_ptr (mocked DNS)
# ---------------------------------------------------------------------------


@patch("app.dmarc_reports.source_classifier.dns.resolver.Resolver")
def test_lookup_ptr_known(mock_resolver_cls):
    """Successful PTR lookup for a known provider."""
    mock_instance = MagicMock()
    mock_resolver_cls.return_value = mock_instance
    mock_answer = MagicMock()
    mock_answer.__str__ = lambda self: "mail-lf1-f41.google.com."
    mock_instance.resolve.return_value = [mock_answer]

    result = _lookup_ptr("198.51.100.1", timeout=3.0)

    assert result["ip"] == "198.51.100.1"
    assert result["ptr"] == "mail-lf1-f41.google.com"
    assert result["provider"] == "Google"
    assert result["category"] == "known"


@patch("app.dmarc_reports.source_classifier.dns.resolver.Resolver")
def test_lookup_ptr_unknown(mock_resolver_cls):
    """Successful PTR lookup but hostname doesn't match any known provider."""
    mock_instance = MagicMock()
    mock_resolver_cls.return_value = mock_instance
    mock_answer = MagicMock()
    mock_answer.__str__ = lambda self: "mail.randomhoster.example."
    mock_instance.resolve.return_value = [mock_answer]

    result = _lookup_ptr("198.51.100.2", timeout=3.0)

    assert result["ip"] == "198.51.100.2"
    assert result["ptr"] == "mail.randomhoster.example"
    assert result["provider"] is None
    assert result["category"] == "unknown"


@patch("app.dmarc_reports.source_classifier.dns.resolver.Resolver")
def test_lookup_ptr_timeout(mock_resolver_cls):
    """DNS timeout returns error category."""
    mock_instance = MagicMock()
    mock_resolver_cls.return_value = mock_instance
    mock_instance.resolve.side_effect = dns.resolver.LifetimeTimeout()

    result = _lookup_ptr("198.51.100.3", timeout=1.0)

    assert result["ip"] == "198.51.100.3"
    assert result["ptr"] is None
    assert result["provider"] is None
    assert result["category"] == "error"


@patch("app.dmarc_reports.source_classifier.dns.resolver.Resolver")
def test_lookup_ptr_nxdomain(mock_resolver_cls):
    """NXDOMAIN returns error category."""
    mock_instance = MagicMock()
    mock_resolver_cls.return_value = mock_instance
    mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN()

    result = _lookup_ptr("198.51.100.4", timeout=3.0)

    assert result["category"] == "error"


# ---------------------------------------------------------------------------
# Tests - classify_sources (mocked DNS)
# ---------------------------------------------------------------------------


@patch("app.dmarc_reports.source_classifier._lookup_ptr")
def test_classify_multiple_ips(mock_lookup):
    """classify_sources processes multiple IPs."""
    mock_lookup.side_effect = [
        {"ip": "1.1.1.1", "ptr": "mail.google.com", "provider": "Google", "category": "known"},
        {"ip": "2.2.2.2", "ptr": "unknown.example", "provider": None, "category": "unknown"},
    ]

    result = classify_sources(["1.1.1.1", "2.2.2.2"])

    assert len(result) == 2
    assert result["1.1.1.1"]["provider"] == "Google"
    assert result["2.2.2.2"]["category"] == "unknown"


def test_classify_empty_list():
    """Empty IP list returns empty dict."""
    result = classify_sources([])
    assert result == {}


@patch("app.dmarc_reports.source_classifier._lookup_ptr")
def test_classify_deduplicates(mock_lookup):
    """Duplicate IPs are deduplicated."""
    mock_lookup.return_value = {
        "ip": "1.1.1.1", "ptr": "mail.google.com",
        "provider": "Google", "category": "known",
    }

    result = classify_sources(["1.1.1.1", "1.1.1.1", "1.1.1.1"])

    assert len(result) == 1
    assert mock_lookup.call_count == 1


@patch("app.dmarc_reports.source_classifier._lookup_ptr")
def test_classify_respects_max_ips(mock_lookup):
    """Only max_ips IPs are processed."""
    mock_lookup.return_value = {
        "ip": "1.1.1.1", "ptr": None, "provider": None, "category": "error",
    }

    ips = [f"10.0.0.{i}" for i in range(100)]
    result = classify_sources(ips, max_ips=5)

    assert mock_lookup.call_count == 5
