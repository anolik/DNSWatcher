"""
TLS/STARTTLS checker for MX mail servers.

Connects to each MX server via SMTP on port 25, issues EHLO + STARTTLS,
and if supported, performs a TLS handshake to extract the TLS version,
cipher suite, and certificate details.  Results are informational only
and do not affect the overall domain check status.

Uses a ThreadPoolExecutor with a hard timeout per server to prevent
hanging connections (same pattern as registrar.py).
"""

from __future__ import annotations

import logging
import smtplib
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from typing import Any

from app.models import DnsSettings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_SMTP_CONNECT_TIMEOUT: int = 10
_SMTP_HARD_TIMEOUT: int = 15
_MAX_WORKERS: int = 3


# ---------------------------------------------------------------------------
# Per-server STARTTLS probe
# ---------------------------------------------------------------------------


def _probe_starttls(exchange: str) -> dict[str, Any]:
    """Connect to *exchange* on port 25 and probe STARTTLS support.

    Args:
        exchange: MX exchange hostname (e.g. "aspmx.l.google.com").

    Returns:
        A dict with STARTTLS probe results for this server.
    """
    result: dict[str, Any] = {
        "exchange": exchange,
        "starttls": False,
        "tls_version": None,
        "cipher": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_valid": None,
        "error": None,
    }

    smtp: smtplib.SMTP | None = None
    try:
        smtp = smtplib.SMTP(
            host=exchange,
            port=25,
            timeout=_SMTP_CONNECT_TIMEOUT,
        )
        smtp.ehlo()

        # Check if STARTTLS is advertised in EHLO extensions
        if not smtp.has_extn("starttls"):
            result["starttls"] = False
            return result

        # Upgrade to TLS
        context = ssl.create_default_context()
        # Allow self-signed certs — we still want to inspect the connection
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        smtp.starttls(context=context)
        smtp.ehlo()

        result["starttls"] = True

        # Inspect the SSL socket
        sock = smtp.sock
        if isinstance(sock, ssl.SSLSocket):
            result["tls_version"] = sock.version()

            cipher_info = sock.cipher()
            if cipher_info:
                result["cipher"] = cipher_info[0]  # cipher name

            # Get peer certificate (DER → dict)
            cert_bin = sock.getpeercert(binary_form=True)
            if cert_bin:
                # Re-parse via a validating context to get structured cert
                try:
                    cert_dict = sock.getpeercert(binary_form=False)
                except ValueError:
                    cert_dict = None

                if cert_dict:
                    result["cert_subject"] = _extract_cn(cert_dict.get("subject", ()))
                    result["cert_issuer"] = _extract_cn(cert_dict.get("issuer", ()))

                    not_after = cert_dict.get("notAfter")
                    if not_after:
                        try:
                            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            result["cert_expiry"] = expiry_dt.strftime("%Y-%m-%d")
                            result["cert_valid"] = expiry_dt > datetime.utcnow()
                        except (ValueError, TypeError):
                            result["cert_expiry"] = not_after

    except (smtplib.SMTPException, socket.error, ssl.SSLError, OSError) as exc:
        result["error"] = str(exc)
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass

    return result


def _extract_cn(rdns: tuple) -> str | None:
    """Extract the Common Name (CN) from an RDN sequence.

    Args:
        rdns: A tuple of tuples as returned by ``ssl.SSLSocket.getpeercert()``.

    Returns:
        The CN string, or None if not found.
    """
    for rdn in rdns:
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                return attr_value
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_tls(
    mx_records: list[dict[str, Any]],
    settings: DnsSettings | None = None,
) -> dict[str, Any]:
    """Probe STARTTLS support on each MX mail server.

    For each MX exchange hostname, connects on port 25 via SMTP, issues
    EHLO, and checks for STARTTLS capability.  If supported, upgrades
    the connection and inspects the TLS version, cipher, and certificate.

    Results are cached per exchange hostname within the check run so that
    duplicate MX entries pointing to the same host only trigger one probe.

    Args:
        mx_records: List of MX record dicts as returned by ``check_mx()``,
            each with keys ``priority`` (int) and ``exchange`` (str).
        settings: Optional DnsSettings (unused currently, reserved for
            future timeout overrides).

    Returns:
        A dict with keys: status, servers, all_starttls, warnings, error.
    """
    if not mx_records:
        return {
            "status": None,
            "servers": [],
            "all_starttls": False,
            "warnings": [],
            "error": "No MX records to process",
        }

    # Deduplicate exchanges (preserve order and priority from first occurrence)
    seen_exchanges: dict[str, dict[str, Any]] = {}
    ordered_exchanges: list[str] = []
    exchange_priority: dict[str, int] = {}

    for mx in mx_records:
        exchange = (mx.get("exchange") or "").rstrip(".").lower()
        if not exchange:
            continue
        if exchange not in seen_exchanges:
            seen_exchanges[exchange] = mx
            ordered_exchanges.append(exchange)
            exchange_priority[exchange] = mx.get("priority", 0)

    if not ordered_exchanges:
        return {
            "status": None,
            "servers": [],
            "all_starttls": False,
            "warnings": [],
            "error": "No valid MX exchanges found",
        }

    # Probe each unique exchange in parallel with hard timeout
    probe_results: dict[str, dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="tls") as executor:
        future_map = {
            executor.submit(_probe_starttls, exch): exch
            for exch in ordered_exchanges
        }

        for future in future_map:
            exchange = future_map[future]
            try:
                probe_results[exchange] = future.result(timeout=_SMTP_HARD_TIMEOUT)
            except FuturesTimeoutError:
                logger.warning("TLS probe timed out for %s after %ds", exchange, _SMTP_HARD_TIMEOUT)
                probe_results[exchange] = {
                    "exchange": exchange,
                    "starttls": False,
                    "tls_version": None,
                    "cipher": None,
                    "cert_subject": None,
                    "cert_issuer": None,
                    "cert_expiry": None,
                    "cert_valid": None,
                    "error": f"Connection timed out after {_SMTP_HARD_TIMEOUT}s",
                }
            except Exception as exc:
                logger.warning("TLS probe failed for %s: %s", exchange, exc)
                probe_results[exchange] = {
                    "exchange": exchange,
                    "starttls": False,
                    "tls_version": None,
                    "cipher": None,
                    "cert_subject": None,
                    "cert_issuer": None,
                    "cert_expiry": None,
                    "cert_valid": None,
                    "error": str(exc),
                }

    # Build final server list (one entry per original MX record, using cached probes)
    servers: list[dict[str, Any]] = []
    for mx in mx_records:
        exchange = (mx.get("exchange") or "").rstrip(".").lower()
        if not exchange or exchange not in probe_results:
            continue
        probe = probe_results[exchange]
        servers.append({
            "exchange": mx.get("exchange", exchange),
            "priority": mx.get("priority", 0),
            "starttls": probe["starttls"],
            "tls_version": probe["tls_version"],
            "cipher": probe["cipher"],
            "cert_subject": probe["cert_subject"],
            "cert_issuer": probe["cert_issuer"],
            "cert_expiry": probe["cert_expiry"],
            "cert_valid": probe["cert_valid"],
            "error": probe["error"],
        })

    # Compute summary
    warnings: list[str] = []
    has_starttls = [s for s in servers if s["starttls"]]
    has_error = [s for s in servers if s["error"] and not s["starttls"]]
    no_starttls = [s for s in servers if not s["starttls"] and not s["error"]]

    all_starttls = len(has_starttls) == len(servers) and len(servers) > 0

    # Status logic
    if len(servers) == 0:
        status = None
    elif all_starttls:
        status = "ok"
    elif len(has_error) == len(servers):
        status = "error"
    elif len(has_starttls) > 0:
        status = "warning"
        for s in no_starttls:
            warnings.append(f"{s['exchange']} does not support STARTTLS")
    else:
        status = "info"
        warnings.append("No mail servers support STARTTLS")

    # Warn about old TLS versions
    for s in has_starttls:
        if s["tls_version"] and s["tls_version"] not in ("TLSv1.2", "TLSv1.3"):
            warnings.append(f"{s['exchange']} uses outdated {s['tls_version']}")

    logger.info(
        "TLS check: %d servers, starttls=%d/%d, status=%s",
        len(servers),
        len(has_starttls),
        len(servers),
        status,
    )

    return {
        "status": status,
        "servers": servers,
        "all_starttls": all_starttls,
        "warnings": warnings,
        "error": None,
    }
