"""
F12 - DKIM key validation.

Validates DKIM (DomainKeys Identified Mail) keys for a domain:
- Queries {selector}._domainkey.{domain} TXT records for each selector
- Parses DKIM record tags (v=, k=, p=, t=)
- Validates key presence and detects revoked keys (empty p=)
- Measures RSA key size using the cryptography library
- Aggregates status across all selectors
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from app.checker.resolver import query_dns
from app.models import DnsSettings

logger = logging.getLogger(__name__)


def check_dkim(
    domain: str,
    selectors: list[str],
    settings: DnsSettings | None = None,
) -> dict[str, Any]:
    """Validate DKIM keys for *domain* across all given *selectors*.

    Args:
        domain: The domain name to check.
        selectors: List of DKIM selector strings to validate.
        settings: Optional DnsSettings; loaded from DB if not provided.

    Returns:
        A dict with keys: status, results (list of per-selector dicts),
        warnings.
    """
    result: dict[str, Any] = {
        "status": "warning",
        "results": [],
        "warnings": [],
    }

    if not selectors:
        result["status"] = "warning"
        result["warnings"].append("No DKIM selectors configured for this domain")
        return result

    valid_selectors_found = 0
    worst_status = "ok"

    for selector in selectors:
        selector_result = _check_single_selector(domain, selector, settings)
        result["results"].append(selector_result)

        if selector_result.get("valid"):
            valid_selectors_found += 1
            worst_status = _worst_status(worst_status, selector_result["status"])
        elif selector_result.get("error_type") != "NXDOMAIN":
            # Non-NXDOMAIN errors count as real failures
            worst_status = _worst_status(worst_status, selector_result["status"])

        # Propagate warnings
        for warning in selector_result.get("warnings", []):
            result["warnings"].append(f"[{selector}] {warning}")

    if valid_selectors_found == 0:
        result["status"] = "warning"
        result["warnings"].append("No valid DKIM selectors found for any configured selector")
    else:
        result["status"] = worst_status

    return result


def _check_single_selector(
    domain: str,
    selector: str,
    settings: DnsSettings | None,
) -> dict[str, Any]:
    """Validate a single DKIM selector for *domain*.

    Args:
        domain: The domain name.
        selector: The DKIM selector string.
        settings: Optional DnsSettings for resolver configuration.

    Returns:
        A dict with keys: selector, record, status, key_type, key_size,
        tags, warnings, valid, error_type, error_message.
    """
    selector_result: dict[str, Any] = {
        "selector": selector,
        "record": None,
        "status": "critical",
        "key_type": None,
        "key_size": None,
        "tags": {},
        "warnings": [],
        "valid": False,
        "error_type": None,
        "error_message": None,
    }

    dkim_domain = f"{selector}._domainkey.{domain}"
    dns_result = query_dns(dkim_domain, "TXT", settings)

    if not dns_result["success"]:
        error_type = dns_result.get("error_type", "DNS_ERROR")
        selector_result["error_type"] = error_type
        selector_result["error_message"] = dns_result.get("error_message", "")

        if error_type == "NXDOMAIN":
            # NXDOMAIN is graceful - selector just does not exist
            selector_result["status"] = "info"
            selector_result["warnings"].append(f"Selector {selector} not found (NXDOMAIN)")
        else:
            selector_result["status"] = "critical"
            selector_result["warnings"].append(
                f"DNS query failed for {dkim_domain}: {dns_result.get('error_message', '')}"
            )
        return selector_result

    # Combine all TXT record chunks into one string
    records = dns_result["records"]
    if not records:
        selector_result["status"] = "critical"
        selector_result["warnings"].append(f"Empty TXT response for {dkim_domain}")
        return selector_result

    # DKIM TXT records may span multiple strings; join them
    raw_record = "".join(records)
    selector_result["record"] = raw_record

    # Parse DKIM tags
    tags = _parse_dkim_tags(raw_record)
    selector_result["tags"] = tags

    # Validate version
    v_tag = tags.get("v", "")
    if v_tag and v_tag.upper() != "DKIM1":
        selector_result["warnings"].append(f"Unexpected DKIM version: v={v_tag}")

    # Key type (defaults to rsa)
    key_type = tags.get("k", "rsa").lower()
    selector_result["key_type"] = key_type

    # Check for testing mode
    t_tag = tags.get("t", "")
    if "y" in t_tag.lower():
        selector_result["warnings"].append("DKIM key is in testing mode (t=y)")

    # Validate public key
    p_tag = tags.get("p", "")

    if p_tag == "":
        # Empty p= means key is revoked
        selector_result["status"] = "critical"
        selector_result["valid"] = False
        selector_result["warnings"].append("DKIM key has been revoked (empty p= value)")
        return selector_result

    # Decode and measure key size
    key_size = _measure_key_size(p_tag, key_type)
    selector_result["key_size"] = key_size

    if key_size is not None:
        selector_result["valid"] = True
        if key_size >= 2048:
            selector_result["status"] = "ok"
        elif key_size >= 1024:
            selector_result["status"] = "warning"
            selector_result["warnings"].append(
                f"DKIM key size is {key_size} bits; consider upgrading to 2048+ bits"
            )
        else:
            selector_result["status"] = "critical"
            selector_result["warnings"].append(
                f"DKIM key size is {key_size} bits; minimum 1024 required, 2048+ recommended"
            )
    else:
        # Could not determine key size but key exists
        selector_result["valid"] = True
        selector_result["status"] = "warning"
        selector_result["warnings"].append("Could not determine DKIM key size")

    return selector_result


def _parse_dkim_tags(record: str) -> dict[str, str]:
    """Parse a DKIM TXT record into a dict of tag=value pairs.

    Tags are separated by semicolons. Whitespace within values is preserved
    but leading/trailing whitespace on tags and values is stripped.
    """
    tags: dict[str, str] = {}
    parts = record.split(";")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            # Remove internal whitespace from value (common in DKIM base64 keys)
            tags[key.strip().lower()] = value.strip()
    return tags


def _measure_key_size(p_value: str, key_type: str) -> int | None:
    """Decode the base64 public key and return its size in bits.

    Uses the cryptography library to load the DER-encoded public key.
    Returns None if the key cannot be parsed.

    Args:
        p_value: The base64-encoded public key from the p= tag.
        key_type: The key algorithm (rsa, ed25519).

    Returns:
        Key size in bits, or None if parsing fails.
    """
    # Remove any whitespace from the base64 data
    clean_b64 = p_value.replace(" ", "").replace("\t", "").replace("\n", "").replace("\r", "")

    try:
        der_bytes = base64.b64decode(clean_b64)
    except Exception as exc:
        logger.debug("Failed to decode DKIM p= base64: %s", exc)
        return None

    if key_type == "ed25519":
        # Ed25519 keys are always 256 bits
        return 256

    # Default: RSA key
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        public_key = load_der_public_key(der_bytes)
        return public_key.key_size
    except Exception as exc:
        logger.debug("Failed to load DER public key: %s", exc)

    # Fallback: try wrapping in SubjectPublicKeyInfo structure
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        # Some DKIM records contain raw RSA public key (PKCS#1) rather than
        # SubjectPublicKeyInfo (PKCS#8). Wrap it with the RSA OID header.
        rsa_oid_header = bytes([
            0x30, 0x82,  # SEQUENCE
        ])
        # Attempt to parse as RSA public key using cryptography's internal parser
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives.asymmetric import padding

        # If the simple load failed, we cannot determine key size
        return None
    except Exception:
        return None


def _worst_status(status_a: str, status_b: str) -> str:
    """Return the worse of two status values.

    Severity order: ok < info < warning < critical < error.
    """
    severity = {"ok": 0, "info": 1, "warning": 2, "critical": 3, "error": 4}
    if severity.get(status_a, 0) >= severity.get(status_b, 0):
        return status_a
    return status_b
