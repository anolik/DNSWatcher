"""
MTA-STS and TLS-RPT checker — informational check, does not affect overall status.

MTA-STS (RFC 8461) enforces TLS encryption for inbound SMTP connections.
TLS-RPT (RFC 8460) provides a reporting mechanism for TLS failures.

This check is purely informational: its status is stored but never included
in the overall_status calculation.
"""

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.models import DnsSettings

logger = logging.getLogger(__name__)

# Timeout (seconds) for the HTTPS policy file fetch
_POLICY_FETCH_TIMEOUT = 5


def check_mta_sts(domain: str, settings: "DnsSettings | None") -> dict[str, Any]:
    """Check MTA-STS and TLS-RPT configuration for *domain*.

    Args:
        domain: The domain name to check (e.g., "example.com").
        settings: DnsSettings instance for resolver configuration, or None.

    Returns:
        A dict with keys:
            status (str|None): "ok", "warning", "info", "error", or None.
            record (str|None): Raw TXT record at _mta-sts.domain.
            version (str|None): "STSv1" if present.
            id (str|None): The id= field value.
            policy_mode (str|None): "enforce", "testing", or "none".
            policy_mx (list[str]): MX patterns from the policy file.
            policy_max_age (int|None): max_age value in seconds.
            policy_reachable (bool|None): Whether the policy URL was reachable.
            tls_rpt_record (str|None): Raw TXT at _smtp._tls.domain.
            tls_rpt_rua (list[str]): TLS-RPT report URIs.
            warnings (list[str]): Non-fatal issues detected.
    """
    from app.checker.spf import query_dns  # reuse existing DNS wrapper

    warnings: list[str] = []

    # ---- Query _mta-sts.{domain} TXT ----
    mta_sts_name = f"_mta-sts.{domain}"
    sts_records = _query_txt(mta_sts_name, settings)

    if sts_records is None:
        # DNS error
        return _error_result(warnings)

    # Find the MTA-STS TXT record (starts with "v=STSv1")
    sts_record = _find_sts_record(sts_records)

    if not sts_record:
        # No record found — informational absence
        return {
            "status": None,
            "record": None,
            "version": None,
            "id": None,
            "policy_mode": None,
            "policy_mx": [],
            "policy_max_age": None,
            "policy_reachable": None,
            "tls_rpt_record": None,
            "tls_rpt_rua": [],
            "tls_rpt_valid": None,
            "tls_rpt_warnings": [],
            "warnings": warnings,
        }

    # ---- Parse the TXT record tags ----
    tags = _parse_tags(sts_record)
    version = tags.get("v")
    record_id = tags.get("id")

    if version and version.lower() != "stsv1":
        warnings.append(f"Unexpected MTA-STS version: {version!r}")

    # ---- Fetch HTTPS policy file ----
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    policy_mode, policy_mx, policy_max_age, policy_reachable = _fetch_policy(
        policy_url, warnings
    )

    # ---- Query _smtp._tls.{domain} TXT (TLS-RPT) ----
    tls_rpt_name = f"_smtp._tls.{domain}"
    tls_rpt_records = _query_txt(tls_rpt_name, settings)
    tls_rpt_record: str | None = None
    tls_rpt_rua: list[str] = []

    tls_rpt_valid: bool | None = None
    tls_rpt_warnings: list[str] = []

    if tls_rpt_records:
        tls_rpt_record = _find_tls_rpt_record(tls_rpt_records)
        if tls_rpt_record:
            rpt_tags = _parse_tags(tls_rpt_record)
            rua_raw = rpt_tags.get("rua", "")
            tls_rpt_rua = [u.strip() for u in rua_raw.split(",") if u.strip()]
            tls_rpt_valid, tls_rpt_warnings = _validate_tls_rpt(rpt_tags, tls_rpt_rua)

    # Warn if MTA-STS is present but TLS-RPT is missing (best practice per RFC 8460)
    if sts_record and not tls_rpt_record:
        warnings.append("MTA-STS is configured but no TLS-RPT record found. "
                         "Consider adding a _smtp._tls TXT record for failure reporting.")

    # ---- Determine status ----
    status = _compute_status(policy_mode, policy_reachable, warnings)

    return {
        "status": status,
        "record": sts_record,
        "version": version,
        "id": record_id,
        "policy_mode": policy_mode,
        "policy_mx": policy_mx,
        "policy_max_age": policy_max_age,
        "policy_reachable": policy_reachable,
        "tls_rpt_record": tls_rpt_record,
        "tls_rpt_rua": tls_rpt_rua,
        "tls_rpt_valid": tls_rpt_valid,
        "tls_rpt_warnings": tls_rpt_warnings,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _query_txt(name: str, settings: "DnsSettings | None") -> list[str] | None:
    """Query TXT records for *name*, returning None on DNS error."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        if settings:
            try:
                resolver.nameservers = settings.get_resolvers()
                resolver.timeout = settings.timeout_seconds
                resolver.lifetime = settings.timeout_seconds * settings.retries
            except Exception:
                pass

        answers = resolver.resolve(name, "TXT")
        results: list[str] = []
        for rdata in answers:
            txt = "".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
            results.append(txt)
        return results
    except Exception as exc:
        # Treat NXDOMAIN and NoAnswer as legitimate absence of record
        exc_type = type(exc).__name__
        if exc_type in ("NXDOMAIN", "NoAnswer"):
            return []
        err_str = str(exc).lower()
        if "nxdomain" in err_str or "no answer" in err_str or "nodomain" in err_str:
            return []  # Legitimate absence
        logger.debug("DNS TXT query failed for %s: %s", name, exc)
        return None  # True DNS error


def _find_sts_record(records: list[str]) -> str | None:
    """Return the first record that looks like an MTA-STS TXT entry."""
    for rec in records:
        if rec.lower().startswith("v=stsv1"):
            return rec
    return None


def _find_tls_rpt_record(records: list[str]) -> str | None:
    """Return the first record that looks like a TLS-RPT TXT entry."""
    for rec in records:
        if rec.lower().startswith("v=tlsrpt"):
            return rec
    return None


def _parse_tags(record: str) -> dict[str, str]:
    """Parse semicolon-separated tag=value pairs from a DNS TXT record."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


def _fetch_policy(
    url: str,
    warnings: list[str],
) -> tuple[str | None, list[str], int | None, bool | None]:
    """Attempt to fetch and parse the MTA-STS policy file.

    Returns:
        (policy_mode, policy_mx, policy_max_age, policy_reachable)
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SPF-DMARC-Watcher/1.0"})
        with urllib.request.urlopen(req, timeout=_POLICY_FETCH_TIMEOUT) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        warnings.append(f"MTA-STS policy file unreachable: {exc.reason}")
        return None, [], None, False
    except Exception as exc:
        warnings.append(f"MTA-STS policy fetch failed: {exc}")
        return None, [], None, False

    return _parse_policy_file(body, warnings)


def _parse_policy_file(
    body: str,
    warnings: list[str],
) -> tuple[str | None, list[str], int | None, bool]:
    """Parse the content of an MTA-STS policy file."""
    policy_mode: str | None = None
    policy_mx: list[str] = []
    policy_max_age: int | None = None

    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "version":
            if value.lower() != "stsv1":
                warnings.append(f"Unexpected policy file version: {value!r}")
        elif key == "mode":
            policy_mode = value.lower()
            if policy_mode not in ("enforce", "testing", "none"):
                warnings.append(f"Unknown MTA-STS mode: {value!r}")
        elif key == "mx":
            policy_mx.append(value)
        elif key == "max_age":
            try:
                policy_max_age = int(value)
            except ValueError:
                warnings.append(f"Invalid max_age value: {value!r}")

    return policy_mode, policy_mx, policy_max_age, True


def _compute_status(
    policy_mode: str | None,
    policy_reachable: bool | None,
    warnings: list[str],
) -> str | None:
    """Determine the MTA-STS status string."""
    if policy_mode == "enforce":
        if policy_reachable is False:
            return "warning"  # Policy claims enforce but file is unreachable
        return "ok"
    if policy_mode == "testing":
        return "warning"
    if policy_mode == "none":
        return "info"
    if policy_reachable is False:
        return "warning"
    # Record exists but no mode parsed
    if warnings:
        return "warning"
    return "info"


def _validate_tls_rpt(
    tags: dict[str, str],
    rua_uris: list[str],
) -> tuple[bool, list[str]]:
    """Validate a TLS-RPT record per RFC 8460.

    Checks:
        1. Version tag is ``TLSRPTv1`` (required).
        2. ``rua`` tag is present and non-empty (required).
        3. Each URI uses an allowed scheme (``mailto:`` or ``https:``).

    Args:
        tags: Parsed tag dict from the TLS-RPT TXT record.
        rua_uris: List of report URI strings extracted from the ``rua`` tag.

    Returns:
        A (valid, warnings) tuple.
    """
    rpt_warnings: list[str] = []

    # 1. Version check (RFC 8460 §3: "v=TLSRPTv1" is mandatory)
    version = tags.get("v", "")
    if version.lower() != "tlsrptv1":
        rpt_warnings.append(f"Invalid TLS-RPT version: {version!r} (expected TLSRPTv1)")

    # 2. rua tag is required (RFC 8460 §3)
    if not rua_uris:
        rpt_warnings.append("Missing or empty 'rua' tag — no report destination configured")
        return False, rpt_warnings

    # 3. Each URI must use mailto: or https: scheme
    for uri in rua_uris:
        if not uri.startswith("mailto:") and not uri.startswith("https:"):
            rpt_warnings.append(f"Invalid report URI scheme: {uri!r} (must be mailto: or https:)")

    valid = len(rpt_warnings) == 0
    return valid, rpt_warnings


def _error_result(warnings: list[str]) -> dict[str, Any]:
    """Return an error result dict."""
    return {
        "status": "error",
        "record": None,
        "version": None,
        "id": None,
        "policy_mode": None,
        "policy_mx": [],
        "policy_max_age": None,
        "policy_reachable": None,
        "tls_rpt_record": None,
        "tls_rpt_rua": [],
        "tls_rpt_valid": None,
        "tls_rpt_warnings": [],
        "warnings": warnings,
    }
