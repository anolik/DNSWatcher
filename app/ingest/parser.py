"""
F23 - File parser for the ingest blueprint.

Extracts unique domains from a text file that may contain email addresses,
plain domain names, or mixed content.  Automatically detects the format:

- **Email list**: lines contain email addresses (``user@example.com``);
  the domain part is extracted.
- **Domain list**: lines contain bare domain names (``example.com``).
- **Mixed**: both formats in one file.
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


def parse_import_file(content: str) -> dict:
    """Extract unique lowercase domain names from a text file.

    Each line is processed in two passes:

    1. **Email extraction** - scan for email addresses and capture the
       domain part (e.g. ``alice@example.com`` → ``example.com``).
    2. **Bare domain extraction** - if no email was found, treat the
       trimmed line (or each comma/semicolon/tab-separated token) as a
       potential domain name and validate it.

    This means the importer accepts email lists, domain lists, or any
    mix of both.

    Args:
        content: Raw text content of the uploaded file.

    Returns:
        A dict with keys:
          - ``domains``: sorted list of unique, valid domain names.
          - ``invalid_lines``: list of lines where nothing could be
            extracted.
    """
    domains: set[str] = set()
    invalid_lines: list[str] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue  # skip blank lines silently

        # Comment lines (common in CSV headers or notes)
        if line.startswith("#"):
            continue

        found_any = False

        # Pass 1: look for email addresses
        email_matches = _EMAIL_RE.findall(line)
        if email_matches:
            for domain in email_matches:
                domain_lower = domain.lower()
                if _HOSTNAME_RE.match(domain_lower):
                    domains.add(domain_lower)
                    found_any = True

        # Pass 2: treat tokens as potential bare domain names
        if not found_any:
            tokens = re.split(r"[,;\t|]+", line)
            for token in tokens:
                candidate = token.strip().strip('"').strip("'").lower()
                if _HOSTNAME_RE.match(candidate):
                    domains.add(candidate)
                    found_any = True

        if not found_any:
            invalid_lines.append(line)

    return {
        "domains": sorted(domains),
        "invalid_lines": invalid_lines,
    }


# Keep the old name as an alias for backward compatibility
parse_email_file = parse_import_file
