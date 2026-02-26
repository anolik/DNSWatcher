"""
Unit tests for app/checker/mx.py

All DNS calls are mocked so no real network activity occurs.
Covers: provider identification, MX record parsing, priority sorting,
empty results, and DNS failures.
"""

from __future__ import annotations

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


def _dns_failure(error_type: str = "NXDOMAIN", msg: str = "not found") -> dict:
    """Simulate a failed query_dns result."""
    return {
        "success": False,
        "records": [],
        "error_type": error_type,
        "error_message": msg,
    }


# ---------------------------------------------------------------------------
# Tests - provider identification
# ---------------------------------------------------------------------------


class TestIdentifyMxProvider:
    """Test the identify_mx_provider() function directly."""

    def test_google_workspace(self):
        from app.checker.mx import identify_mx_provider

        assert identify_mx_provider("aspmx.l.google.com.") == "Google Workspace"
        assert identify_mx_provider("alt1.aspmx.l.google.com") == "Google Workspace"

    def test_microsoft_365(self):
        from app.checker.mx import identify_mx_provider

        assert identify_mx_provider("example-com.mail.protection.outlook.com.") == "Microsoft 365"

    def test_ovh(self):
        from app.checker.mx import identify_mx_provider

        assert identify_mx_provider("mx1.mail.ovh.net.") == "OVH"

    def test_proofpoint(self):
        from app.checker.mx import identify_mx_provider

        assert identify_mx_provider("mx1.example.pphosted.com") == "Proofpoint"

    def test_mimecast(self):
        from app.checker.mx import identify_mx_provider

        assert identify_mx_provider("us-smtp-inbound-1.mimecast.com") == "Mimecast"

    def test_protonmail(self):
        from app.checker.mx import identify_mx_provider

        assert identify_mx_provider("mail.protonmail.ch.") == "ProtonMail"

    def test_amazon_ses(self):
        from app.checker.mx import identify_mx_provider

        assert identify_mx_provider("inbound-smtp.us-east-1.amazonses.com") == "Amazon SES"

    def test_unknown_provider_returns_hostname(self):
        from app.checker.mx import identify_mx_provider

        result = identify_mx_provider("mx.custom-server.example.org.")
        assert result == "mx.custom-server.example.org"


# ---------------------------------------------------------------------------
# Tests - check_mx full flow
# ---------------------------------------------------------------------------


class TestCheckMx:
    """Test the check_mx() function with mocked DNS."""

    @patch("app.checker.mx.query_dns")
    def test_google_mx_records(self, mock_query, app):
        """Google Workspace MX records should be parsed and provider identified."""
        with app.app_context():
            mock_query.return_value = _dns_success([
                "10 aspmx.l.google.com.",
                "20 alt1.aspmx.l.google.com.",
                "30 alt2.aspmx.l.google.com.",
            ])

            from app.checker.mx import check_mx

            result = check_mx("example.com")

        assert result["provider"] == "Google Workspace"
        assert len(result["records"]) == 3
        assert result["records"][0]["priority"] == 10
        assert result["records"][0]["exchange"] == "aspmx.l.google.com"
        assert result["error"] is None

    @patch("app.checker.mx.query_dns")
    def test_microsoft_mx_records(self, mock_query, app):
        """Microsoft 365 MX records should be correctly identified."""
        with app.app_context():
            mock_query.return_value = _dns_success([
                "0 example-com.mail.protection.outlook.com.",
            ])

            from app.checker.mx import check_mx

            result = check_mx("example.com")

        assert result["provider"] == "Microsoft 365"
        assert len(result["records"]) == 1
        assert result["records"][0]["priority"] == 0

    @patch("app.checker.mx.query_dns")
    def test_priority_sorting(self, mock_query, app):
        """MX records should be sorted by priority (lowest first)."""
        with app.app_context():
            mock_query.return_value = _dns_success([
                "30 mx3.example.com.",
                "10 mx1.example.com.",
                "20 mx2.example.com.",
            ])

            from app.checker.mx import check_mx

            result = check_mx("example.com")

        priorities = [r["priority"] for r in result["records"]]
        assert priorities == [10, 20, 30]

    @patch("app.checker.mx.query_dns")
    def test_empty_mx_records(self, mock_query, app):
        """Domains with no MX records should return empty results."""
        with app.app_context():
            mock_query.return_value = _dns_failure("NO_ANSWER", "No MX records")

            from app.checker.mx import check_mx

            result = check_mx("example.com")

        assert result["records"] == []
        assert result["provider"] is None
        assert result["error"] is not None

    @patch("app.checker.mx.query_dns")
    def test_dns_timeout(self, mock_query, app):
        """DNS timeout should return empty results with error."""
        with app.app_context():
            mock_query.return_value = _dns_failure("TIMEOUT", "DNS query timed out")

            from app.checker.mx import check_mx

            result = check_mx("example.com")

        assert result["records"] == []
        assert result["provider"] is None
        assert "timed out" in result["error"]

    @patch("app.checker.mx.query_dns")
    def test_unknown_provider_uses_hostname(self, mock_query, app):
        """Unknown MX hostnames should use the raw hostname as provider."""
        with app.app_context():
            mock_query.return_value = _dns_success([
                "10 mail.custom-server.example.org.",
            ])

            from app.checker.mx import check_mx

            result = check_mx("example.com")

        assert result["provider"] == "mail.custom-server.example.org"
