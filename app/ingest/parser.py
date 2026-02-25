"""
F23 - Email file parser for the ingest blueprint.

Extracts unique domains from a text file that may contain email addresses,
plain domain names, or mixed content.
"""

from __future__ import annotations

import re

# Matches an email address and captures the domain part (group 1)
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
)

# Hostname validation: must be a valid-looking domain
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$"
)


def parse_email_file(content: str) -> dict:
    """Extract unique lowercase domain names from a text file.

    Each line is scanned for email addresses using a regex.  Any domain
    extracted from a valid email address is normalised to lowercase and
    collected.  Lines that contain no recognisable email address are
    recorded as invalid.

    Args:
        content: Raw text content of the uploaded file.

    Returns:
        A dict with two keys:
          - "domains": sorted list of unique, valid domain names
          - "invalid_lines": list of lines that contained no email address
    """
    domains: set[str] = set()
    invalid_lines: list[str] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue  # skip blank lines silently

        matches = _EMAIL_RE.findall(line)
        if matches:
            for domain in matches:
                domain_lower = domain.lower()
                if _HOSTNAME_RE.match(domain_lower):
                    domains.add(domain_lower)
        else:
            # Record the line as invalid (no email found)
            invalid_lines.append(line)

    return {
        "domains": sorted(domains),
        "invalid_lines": invalid_lines,
    }
