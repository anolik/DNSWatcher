"""Source IP classifier using PTR (reverse DNS) lookups.

Maps sending IPs to known email service providers by matching PTR
hostnames against a curated list of ESP domain patterns.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.name
import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known ESP patterns (PTR hostname suffix → provider name)
# ---------------------------------------------------------------------------

_KNOWN_PROVIDERS: dict[str, str] = {
    "google.com": "Google",
    "googlemail.com": "Google",
    "outlook.com": "Microsoft",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "postmarkapp.com": "Postmark",
    "mtasv.net": "Postmark",
    "messagelabs.com": "Broadcom",
    "mailchimp.com": "Mailchimp",
    "mandrillapp.com": "Mandrill",
    "sparkpostmail.com": "SparkPost",
    "hubspotemail.net": "HubSpot",
    "salesforce.com": "Salesforce",
    "exacttarget.com": "Salesforce MC",
    "rsgsv.net": "Mailchimp",
    "fireeyecloud.com": "Trellix",
    "barracudanetworks.com": "Barracuda",
    "zoho.com": "Zoho",
    "fastmail.com": "Fastmail",
    "ovh.net": "OVH",
}


def _match_provider(ptr_hostname: str) -> str | None:
    """Return the provider name if *ptr_hostname* matches a known pattern."""
    ptr_lower = ptr_hostname.rstrip(".").lower()
    for suffix, provider in _KNOWN_PROVIDERS.items():
        if ptr_lower == suffix or ptr_lower.endswith("." + suffix):
            return provider
    return None


def _lookup_ptr(ip: str, timeout: float) -> dict:
    """Perform a single PTR lookup and classify the result.

    Args:
        ip: IPv4 or IPv6 address string.
        timeout: DNS query timeout in seconds.

    Returns:
        Dict with ip, ptr, provider, category keys.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, "PTR")
        ptr_hostname = str(answers[0]).rstrip(".")
    except Exception as exc:
        logger.debug("PTR lookup failed for %s: %s", ip, exc)
        return {
            "ip": ip,
            "ptr": None,
            "provider": None,
            "category": "error",
        }

    provider = _match_provider(ptr_hostname)
    return {
        "ip": ip,
        "ptr": ptr_hostname,
        "provider": provider,
        "category": "known" if provider else "unknown",
    }


def classify_sources(
    ip_list: list[str],
    max_ips: int = 25,
    timeout: float = 3.0,
) -> dict[str, dict]:
    """Classify a list of source IPs via PTR lookup and pattern matching.

    Args:
        ip_list: IP addresses to classify.
        max_ips: Maximum number of IPs to process (to limit DNS traffic).
        timeout: Per-lookup DNS timeout in seconds.

    Returns:
        Dict keyed by IP address, each value a dict with
        ip, ptr, provider, and category fields.
    """
    if not ip_list:
        return {}

    # Deduplicate and cap
    unique_ips = list(dict.fromkeys(ip_list))[:max_ips]
    results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_ip = {
            executor.submit(_lookup_ptr, ip, timeout): ip
            for ip in unique_ips
        }
        for future in as_completed(future_to_ip):
            try:
                result = future.result()
                results[result["ip"]] = result
            except Exception as exc:
                ip = future_to_ip[future]
                logger.warning("classify_sources: unexpected error for %s: %s", ip, exc)
                results[ip] = {
                    "ip": ip,
                    "ptr": None,
                    "provider": None,
                    "category": "error",
                }

    return results
