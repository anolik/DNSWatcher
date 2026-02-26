"""Unit tests for the TLS/STARTTLS checker module."""

from __future__ import annotations

import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest

from app.checker.tls import _probe_starttls, check_tls


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_mx(exchange: str, priority: int = 10) -> dict:
    """Build an MX record dict matching check_mx() output."""
    return {"exchange": exchange, "priority": priority}


def _mock_smtp(has_starttls: bool = True, tls_version: str = "TLSv1.3",
               cipher: str = "TLS_AES_256_GCM_SHA384",
               cert_subject: str = "*.example.com",
               cert_issuer: str = "Let's Encrypt Authority X3",
               not_after: str = "Jun 15 12:00:00 2026 GMT"):
    """Build a MagicMock that simulates smtplib.SMTP behaviour."""
    smtp_instance = MagicMock()
    smtp_instance.has_extn.return_value = has_starttls

    if has_starttls:
        mock_sock = MagicMock(spec=ssl.SSLSocket)
        mock_sock.version.return_value = tls_version
        mock_sock.cipher.return_value = (cipher, "TLSv1.3", 256)
        mock_sock.getpeercert.side_effect = lambda binary_form=False: (
            b"binary-cert-data" if binary_form else {
                "subject": ((("commonName", cert_subject),),),
                "issuer": ((("commonName", cert_issuer),),),
                "notAfter": not_after,
            }
        )
        smtp_instance.sock = mock_sock
    else:
        smtp_instance.sock = MagicMock()

    return smtp_instance


# ---------------------------------------------------------------------------
# Tests: check_tls() status logic
# ---------------------------------------------------------------------------

class TestCheckTlsStatus:
    """Test the status computation logic in check_tls()."""

    @patch("app.checker.tls._probe_starttls")
    def test_all_servers_starttls_ok(self, mock_probe):
        """All MX servers support STARTTLS → status='ok'."""
        mock_probe.return_value = {
            "exchange": "mail.example.com",
            "starttls": True,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cert_subject": "*.example.com",
            "cert_issuer": "Let's Encrypt",
            "cert_expiry": "2026-06-15",
            "cert_valid": True,
            "error": None,
        }

        result = check_tls([_make_mx("mail.example.com")])
        assert result["status"] == "ok"
        assert result["all_starttls"] is True
        assert len(result["servers"]) == 1

    @patch("app.checker.tls._probe_starttls")
    def test_some_servers_no_starttls_warning(self, mock_probe):
        """Some MX servers lack STARTTLS → status='warning'."""
        def side_effect(exchange):
            if exchange == "mail1.example.com":
                return {
                    "exchange": exchange, "starttls": True,
                    "tls_version": "TLSv1.3", "cipher": "AES256",
                    "cert_subject": None, "cert_issuer": None,
                    "cert_expiry": None, "cert_valid": None, "error": None,
                }
            return {
                "exchange": exchange, "starttls": False,
                "tls_version": None, "cipher": None,
                "cert_subject": None, "cert_issuer": None,
                "cert_expiry": None, "cert_valid": None, "error": None,
            }

        mock_probe.side_effect = side_effect

        result = check_tls([
            _make_mx("mail1.example.com", 10),
            _make_mx("mail2.example.com", 20),
        ])
        assert result["status"] == "warning"
        assert result["all_starttls"] is False
        assert len(result["warnings"]) >= 1

    @patch("app.checker.tls._probe_starttls")
    def test_no_servers_starttls_info(self, mock_probe):
        """No MX servers support STARTTLS → status='info'."""
        mock_probe.return_value = {
            "exchange": "mail.example.com", "starttls": False,
            "tls_version": None, "cipher": None,
            "cert_subject": None, "cert_issuer": None,
            "cert_expiry": None, "cert_valid": None, "error": None,
        }

        result = check_tls([_make_mx("mail.example.com")])
        assert result["status"] == "info"
        assert result["all_starttls"] is False

    def test_empty_mx_records_none_status(self):
        """No MX records → status=None."""
        result = check_tls([])
        assert result["status"] is None
        assert result["servers"] == []

    @patch("app.checker.tls._probe_starttls")
    def test_all_errors_returns_error_status(self, mock_probe):
        """All servers error → status='error'."""
        mock_probe.return_value = {
            "exchange": "mail.example.com", "starttls": False,
            "tls_version": None, "cipher": None,
            "cert_subject": None, "cert_issuer": None,
            "cert_expiry": None, "cert_valid": None,
            "error": "Connection refused",
        }

        result = check_tls([_make_mx("mail.example.com")])
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# Tests: per-host caching
# ---------------------------------------------------------------------------

class TestCheckTlsCaching:
    """Test that duplicate MX hostnames only trigger one probe."""

    @patch("app.checker.tls._probe_starttls")
    def test_duplicate_exchange_single_probe(self, mock_probe):
        """Two MX records with same exchange → only one probe call."""
        mock_probe.return_value = {
            "exchange": "mail.example.com", "starttls": True,
            "tls_version": "TLSv1.3", "cipher": "AES256",
            "cert_subject": None, "cert_issuer": None,
            "cert_expiry": None, "cert_valid": None, "error": None,
        }

        result = check_tls([
            _make_mx("mail.example.com", 10),
            _make_mx("mail.example.com", 20),
        ])
        # Only one unique exchange → one probe call
        assert mock_probe.call_count == 1
        # But both MX records appear in results
        assert len(result["servers"]) == 2


# ---------------------------------------------------------------------------
# Tests: _probe_starttls internals
# ---------------------------------------------------------------------------

class TestProbeStarttls:
    """Test the per-server STARTTLS probe function."""

    @patch("app.checker.tls.smtplib.SMTP")
    def test_starttls_supported(self, mock_smtp_cls):
        """Server supports STARTTLS → starttls=True with TLS details."""
        smtp_instance = _mock_smtp(has_starttls=True)
        mock_smtp_cls.return_value = smtp_instance

        result = _probe_starttls("mail.example.com")
        assert result["starttls"] is True
        assert result["tls_version"] == "TLSv1.3"
        assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
        assert result["cert_subject"] == "*.example.com"
        assert result["error"] is None

    @patch("app.checker.tls.smtplib.SMTP")
    def test_starttls_not_supported(self, mock_smtp_cls):
        """Server does NOT support STARTTLS → starttls=False."""
        smtp_instance = _mock_smtp(has_starttls=False)
        mock_smtp_cls.return_value = smtp_instance

        result = _probe_starttls("mail.example.com")
        assert result["starttls"] is False
        assert result["tls_version"] is None
        assert result["error"] is None

    @patch("app.checker.tls.smtplib.SMTP")
    def test_connection_timeout(self, mock_smtp_cls):
        """Connection timeout → error string, starttls=False."""
        mock_smtp_cls.side_effect = socket.timeout("Connection timed out")

        result = _probe_starttls("mail.example.com")
        assert result["starttls"] is False
        assert result["error"] is not None
        assert "timed out" in result["error"].lower()

    @patch("app.checker.tls.smtplib.SMTP")
    def test_connection_refused(self, mock_smtp_cls):
        """Connection refused → error string, starttls=False."""
        mock_smtp_cls.side_effect = ConnectionRefusedError("Connection refused")

        result = _probe_starttls("mail.example.com")
        assert result["starttls"] is False
        assert result["error"] is not None

    @patch("app.checker.tls.smtplib.SMTP")
    def test_cert_expired(self, mock_smtp_cls):
        """Certificate with past expiry → cert_valid=False."""
        smtp_instance = _mock_smtp(
            has_starttls=True,
            not_after="Jan 01 00:00:00 2020 GMT",
        )
        mock_smtp_cls.return_value = smtp_instance

        result = _probe_starttls("mail.example.com")
        assert result["starttls"] is True
        assert result["cert_valid"] is False
        assert result["cert_expiry"] == "2020-01-01"

    @patch("app.checker.tls.smtplib.SMTP")
    def test_cert_valid(self, mock_smtp_cls):
        """Certificate with future expiry → cert_valid=True."""
        smtp_instance = _mock_smtp(
            has_starttls=True,
            not_after="Dec 31 23:59:59 2030 GMT",
        )
        mock_smtp_cls.return_value = smtp_instance

        result = _probe_starttls("mail.example.com")
        assert result["starttls"] is True
        assert result["cert_valid"] is True


# ---------------------------------------------------------------------------
# Tests: warnings for outdated TLS
# ---------------------------------------------------------------------------

class TestCheckTlsWarnings:
    """Test that old TLS versions produce warnings."""

    @patch("app.checker.tls._probe_starttls")
    def test_old_tls_version_warns(self, mock_probe):
        """Server with TLSv1.0 → generates a warning."""
        mock_probe.return_value = {
            "exchange": "mail.example.com", "starttls": True,
            "tls_version": "TLSv1.0", "cipher": "DES-CBC3-SHA",
            "cert_subject": None, "cert_issuer": None,
            "cert_expiry": None, "cert_valid": None, "error": None,
        }

        result = check_tls([_make_mx("mail.example.com")])
        assert result["status"] == "ok"
        assert any("TLSv1.0" in w for w in result["warnings"])
