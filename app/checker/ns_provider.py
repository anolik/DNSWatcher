"""
F13B - NS Provider Identification.

Identifies the DNS hosting provider from nameserver hostnames.
The registrar (where the domain was purchased) is not necessarily the
NS provider (who hosts the DNS zone).

Uses pattern matching on NS hostnames — no additional DNS queries needed.
Reuses the name_servers list already collected by the registrar checker.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known NS provider patterns
# ---------------------------------------------------------------------------
# Each entry: (compiled regex pattern, provider display name)
# Patterns are tested against lowercased, dot-stripped NS hostnames.
# Order matters: more specific patterns should come first.

_NS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # --- Major cloud DNS ---
    (re.compile(r"\.cloudflare\.com$"), "Cloudflare"),
    (re.compile(r"\.awsdns-\d+\.\w+$"), "AWS Route53"),
    (re.compile(r"ns-cloud-\w+\.googledomains\.com$"), "Google Cloud DNS"),
    (re.compile(r"\.googledomains\.com$"), "Google Domains"),
    (re.compile(r"\.azure-dns\.\w+$"), "Azure DNS"),
    (re.compile(r"\.azuredns-\w+\.\w+$"), "Azure DNS"),
    (re.compile(r"dns\d*\.p\d+\.nsone\.net$"), "NS1"),
    (re.compile(r"\.nsone\.net$"), "NS1"),
    (re.compile(r"\.dnsimple\.com$"), "DNSimple"),
    (re.compile(r"\.dynect\.net$"), "Oracle Dyn"),
    (re.compile(r"\.constellix\.com$"), "Constellix"),
    (re.compile(r"\.cloudns\.net$"), "ClouDNS"),
    (re.compile(r"\.easydns\.com$"), "easyDNS"),
    (re.compile(r"\.ultradns\.\w+$"), "UltraDNS"),

    # --- Registrar DNS ---
    (re.compile(r"\.domaincontrol\.com$"), "GoDaddy"),
    (re.compile(r"\.godaddy\.com$"), "GoDaddy"),
    (re.compile(r"\.registrar-servers\.com$"), "Namecheap"),
    (re.compile(r"\.namecheaphosting\.com$"), "Namecheap"),
    (re.compile(r"dns\d*\.ovh\.\w+$"), "OVH"),
    (re.compile(r"\.ovh\.\w+$"), "OVH"),
    (re.compile(r"\.gandi\.net$"), "Gandi"),
    (re.compile(r"\.name\.com$"), "Name.com"),
    (re.compile(r"\.porkbun\.com$"), "Porkbun"),
    (re.compile(r"\.hover\.com$"), "Hover"),
    (re.compile(r"\.register\.com$"), "Register.com"),
    (re.compile(r"\.ionos\.\w+$"), "IONOS"),
    (re.compile(r"\.ui-dns\.\w+$"), "IONOS"),
    (re.compile(r"\.inwx\.\w+$"), "INWX"),

    # --- Hosting providers ---
    (re.compile(r"\.hetzner\.com$"), "Hetzner"),
    (re.compile(r"\.digitalocean\.com$"), "DigitalOcean"),
    (re.compile(r"\.linode\.com$"), "Linode/Akamai"),
    (re.compile(r"\.akam\.net$"), "Akamai"),
    (re.compile(r"\.akamai\.\w+$"), "Akamai"),
    (re.compile(r"\.vultr\.com$"), "Vultr"),
    (re.compile(r"\.dreamhost\.com$"), "DreamHost"),
    (re.compile(r"\.bluehost\.com$"), "Bluehost"),
    (re.compile(r"\.siteground\.net$"), "SiteGround"),
    (re.compile(r"\.hostinger\.\w+$"), "Hostinger"),
    (re.compile(r"\.liquidweb\.com$"), "Liquid Web"),
    (re.compile(r"\.mediatemple\.net$"), "Media Temple"),

    # --- Website builders / platforms ---
    (re.compile(r"\.netlify\.com$"), "Netlify"),
    (re.compile(r"dns\d*\.vercel-dns\.com$"), "Vercel"),
    (re.compile(r"\.vercel-dns\.com$"), "Vercel"),
    (re.compile(r"\.squarespace\.com$"), "Squarespace"),
    (re.compile(r"\.squarespace-dns\.com$"), "Squarespace"),
    (re.compile(r"\.wixdns\.net$"), "Wix"),
    (re.compile(r"\.shopify\.com$"), "Shopify"),
    (re.compile(r"\.wordpress\.com$"), "WordPress.com"),
    (re.compile(r"\.wpengine\.com$"), "WP Engine"),

    # --- Canadian / regional ---
    (re.compile(r"\.cira\.ca$"), "CIRA"),
    (re.compile(r"\.rebel\.com$"), "Rebel.ca"),
    (re.compile(r"\.webnames\.ca$"), "Webnames.ca"),
    (re.compile(r"\.wildwestdomains\.com$"), "Wild West Domains"),

    # --- Other DNS providers ---
    (re.compile(r"\.he\.net$"), "Hurricane Electric"),
    (re.compile(r"\.bunny\.net$"), "Bunny.net"),
    (re.compile(r"\.fastly\.net$"), "Fastly"),
    (re.compile(r"\.stackpath\.net$"), "StackPath"),
    (re.compile(r"\.dnsmadeeasy\.com$"), "DNS Made Easy"),
    (re.compile(r"\.afraid\.org$"), "FreeDNS"),
    (re.compile(r"\.no-ip\.com$"), "No-IP"),
    (re.compile(r"\.duckdns\.org$"), "DuckDNS"),
    (re.compile(r"\.transip\.\w+$"), "TransIP"),
    (re.compile(r"\.online\.net$"), "Scaleway"),
    (re.compile(r"\.scaleway\.com$"), "Scaleway"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def identify_ns_provider(name_servers: list[str]) -> dict[str, Any]:
    """Identify the DNS hosting provider from a list of NS hostnames.

    Args:
        name_servers: List of nameserver hostnames (e.g., from RDAP/WHOIS).

    Returns:
        A dict with keys:
            ns_provider (str|None): Identified provider name.
            ns_hostnames (list[str]): The input nameservers (normalized).
            confidence (str): "exact" if a known pattern matched,
                "inferred" if we fell back to the parent domain.
    """
    if not name_servers:
        return {
            "ns_provider": None,
            "ns_hostnames": [],
            "confidence": None,
        }

    # Normalize: lowercase, strip trailing dots
    normalized = [ns.lower().rstrip(".") for ns in name_servers if isinstance(ns, str) and ns.strip()]

    if not normalized:
        return {
            "ns_provider": None,
            "ns_hostnames": [],
            "confidence": None,
        }

    # Try pattern matching — majority vote across all NS hostnames
    provider_votes: dict[str, int] = {}
    for ns in normalized:
        for pattern, provider_name in _NS_PATTERNS:
            if pattern.search(ns):
                provider_votes[provider_name] = provider_votes.get(provider_name, 0) + 1
                break

    if provider_votes:
        # Pick the provider with the most matching NS hostnames
        best_provider = max(provider_votes, key=provider_votes.get)  # type: ignore[arg-type]
        logger.debug(
            "NS provider identified: %s (votes: %s)",
            best_provider,
            provider_votes,
        )
        return {
            "ns_provider": best_provider,
            "ns_hostnames": normalized,
            "confidence": "exact",
        }

    # Fallback: extract parent domain from first NS hostname
    inferred = _infer_provider_from_hostname(normalized[0])
    if inferred:
        logger.debug("NS provider inferred from hostname: %s", inferred)
        return {
            "ns_provider": inferred,
            "ns_hostnames": normalized,
            "confidence": "inferred",
        }

    return {
        "ns_provider": None,
        "ns_hostnames": normalized,
        "confidence": None,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _infer_provider_from_hostname(ns_hostname: str) -> str | None:
    """Extract a provider name from the parent domain of an NS hostname.

    For example: ``ns1.example.com`` -> ``example.com``
    """
    parts = ns_hostname.split(".")
    if len(parts) >= 2:
        # Return the last two labels as the inferred provider domain
        return ".".join(parts[-2:])
    return None
