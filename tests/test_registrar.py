"""
Unit tests for app/checker/registrar.py

All WHOIS calls are mocked so no real network activity occurs.
Covers: success path, WHOIS failures, ImportError fallback, date list handling,
and name server normalization.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Tests - successful WHOIS lookup
# ---------------------------------------------------------------------------


class TestCheckRegistrarSuccess:
    """Test check_registrar() with a successful WHOIS response."""

    @patch("whois.whois")
    def test_basic_registrar_lookup(self, mock_whois, app):
        """Standard WHOIS response should be parsed correctly."""
        with app.app_context():
            mock_whois.return_value = SimpleNamespace(
                registrar="GoDaddy.com, LLC",
                creation_date=datetime(2020, 1, 15, tzinfo=timezone.utc),
                expiration_date=datetime(2026, 1, 15, tzinfo=timezone.utc),
                name_servers=["ns1.example.com", "ns2.example.com"],
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com")

        assert result["registrar"] == "GoDaddy.com, LLC"
        assert result["creation_date"] is not None
        assert "2020" in result["creation_date"]
        assert result["expiration_date"] is not None
        assert "2026" in result["expiration_date"]
        assert len(result["name_servers"]) == 2
        assert result["error"] is None

    @patch("whois.whois")
    def test_date_list_handling(self, mock_whois, app):
        """Some TLDs return a list of dates; we should take the first one."""
        with app.app_context():
            mock_whois.return_value = SimpleNamespace(
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

            result = check_registrar("example.com")

        assert "2019" in result["creation_date"]
        assert "2025" in result["expiration_date"]
        assert result["error"] is None

    @patch("whois.whois")
    def test_name_servers_deduplicated_and_lowered(self, mock_whois, app):
        """Name servers should be deduplicated, lowercased, and sorted."""
        with app.app_context():
            mock_whois.return_value = SimpleNamespace(
                registrar="Test Registrar",
                creation_date=None,
                expiration_date=None,
                name_servers=["NS2.EXAMPLE.COM.", "ns1.example.com", "NS2.EXAMPLE.COM"],
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com")

        assert result["name_servers"] == ["ns1.example.com", "ns2.example.com"]

    @patch("whois.whois")
    def test_none_registrar_returns_none(self, mock_whois, app):
        """If WHOIS returns None for registrar, result should be None."""
        with app.app_context():
            mock_whois.return_value = SimpleNamespace(
                registrar=None,
                creation_date=None,
                expiration_date=None,
                name_servers=None,
            )

            from app.checker.registrar import check_registrar

            result = check_registrar("example.com")

        assert result["registrar"] is None
        assert result["name_servers"] == []
        assert result["error"] is None


# ---------------------------------------------------------------------------
# Tests - WHOIS failures
# ---------------------------------------------------------------------------


class TestCheckRegistrarFailure:
    """Test check_registrar() when WHOIS lookups fail."""

    @patch("whois.whois", side_effect=Exception("Connection timed out"))
    def test_whois_exception_returns_error(self, mock_whois, app):
        """WHOIS exceptions should be caught and returned as error."""
        with app.app_context():
            from app.checker.registrar import check_registrar

            result = check_registrar("example.com")

        assert result["registrar"] is None
        assert result["error"] is not None
        assert "timed out" in result["error"].lower()


# ---------------------------------------------------------------------------
# Tests - ImportError fallback
# ---------------------------------------------------------------------------


class TestCheckRegistrarImportError:
    """Test check_registrar() when python-whois is not installed."""

    def test_import_error_graceful_fallback(self, app):
        """If whois module is not importable, return error gracefully."""
        with app.app_context():
            import builtins

            original_import = builtins.__import__

            def mock_import(name, *args, **kwargs):
                if name == "whois":
                    raise ImportError("No module named 'whois'")
                return original_import(name, *args, **kwargs)

            with patch.object(builtins, "__import__", side_effect=mock_import):
                from importlib import reload

                import app.checker.registrar as reg_module

                reload(reg_module)
                result = reg_module.check_registrar("example.com")

            assert result["registrar"] is None
            assert "not installed" in result["error"].lower()

            # Restore module
            reload(reg_module)
