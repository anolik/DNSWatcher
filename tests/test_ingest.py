"""
F36 - Unit tests for app/ingest/parser.py

Verifies the file parser correctly extracts domains from email lists,
domain lists, or mixed content.  Handles duplicates, identifies invalid
lines, and processes edge cases.
"""

from __future__ import annotations

import pytest

from app.ingest.parser import parse_email_file, parse_import_file


# ---------------------------------------------------------------------------
# Tests - valid email address extraction
# ---------------------------------------------------------------------------


def test_single_email_extracts_domain():
    """A file with one email address should return its domain."""
    content = "user@example.com"
    result = parse_email_file(content)

    assert "example.com" in result["domains"]
    assert result["invalid_lines"] == []


def test_multiple_emails_extract_all_domains():
    """Multiple email addresses should each contribute their domain."""
    content = "alice@example.com\nbob@another.org\ncarol@test.net"
    result = parse_email_file(content)

    assert "example.com" in result["domains"]
    assert "another.org" in result["domains"]
    assert "test.net" in result["domains"]


def test_same_domain_from_multiple_emails_deduplicated():
    """Two different users at the same domain should yield one domain entry."""
    content = "alice@example.com\nbob@example.com\ncarol@example.com"
    result = parse_email_file(content)

    assert result["domains"].count("example.com") == 1
    assert len(result["domains"]) == 1


def test_same_email_address_twice_yields_one_domain():
    """Duplicate lines should not produce duplicate domain entries."""
    content = "user@example.com\nuser@example.com"
    result = parse_email_file(content)

    assert result["domains"].count("example.com") == 1


# ---------------------------------------------------------------------------
# Tests - domain normalisation
# ---------------------------------------------------------------------------


def test_domains_normalised_to_lowercase():
    """Email domains with uppercase letters should be lowercased."""
    content = "User@EXAMPLE.COM"
    result = parse_email_file(content)

    assert "example.com" in result["domains"]
    assert "EXAMPLE.COM" not in result["domains"]


def test_mixed_case_email_normalised():
    """Email with mixed-case domain is normalised to lowercase."""
    content = "Admin@MyCompany.ORG"
    result = parse_email_file(content)

    assert "mycompany.org" in result["domains"]


# ---------------------------------------------------------------------------
# Tests - invalid lines
# ---------------------------------------------------------------------------


def test_line_without_email_counted_as_invalid():
    """A line that contains no email address is recorded as invalid."""
    content = "this is not an email"
    result = parse_email_file(content)

    assert "domains" in result
    assert len(result["domains"]) == 0
    assert "this is not an email" in result["invalid_lines"]


def test_mixed_valid_and_invalid_lines():
    """Valid and invalid lines are separated correctly."""
    content = (
        "user@valid.com\n"
        "not-an-email\n"
        "admin@another.org\n"
        "also-invalid 12345\n"
    )
    result = parse_email_file(content)

    assert "valid.com" in result["domains"]
    assert "another.org" in result["domains"]
    assert "not-an-email" in result["invalid_lines"]
    assert "also-invalid 12345" in result["invalid_lines"]
    assert len(result["invalid_lines"]) == 2


def test_only_invalid_lines():
    """A file with no email addresses should return an empty domain list."""
    content = "no-emails-here\njust text\n12345"
    result = parse_email_file(content)

    assert result["domains"] == []
    assert len(result["invalid_lines"]) == 3


# ---------------------------------------------------------------------------
# Tests - empty input
# ---------------------------------------------------------------------------


def test_empty_string_returns_empty_results():
    """An empty input string should return empty domains and invalid_lines."""
    result = parse_email_file("")

    assert result["domains"] == []
    assert result["invalid_lines"] == []


def test_only_blank_lines_returns_empty_results():
    """A file containing only whitespace/blank lines should return empty results."""
    content = "\n\n   \n\t\n"
    result = parse_email_file(content)

    assert result["domains"] == []
    assert result["invalid_lines"] == []


# ---------------------------------------------------------------------------
# Tests - email addresses embedded in text
# ---------------------------------------------------------------------------


def test_email_embedded_in_sentence_extracted():
    """An email address embedded in a sentence should still be extracted."""
    content = "Please contact us at support@company.io for help."
    result = parse_email_file(content)

    assert "company.io" in result["domains"]
    assert result["invalid_lines"] == []


def test_multiple_emails_on_same_line():
    """Multiple email addresses on one line should all be extracted."""
    content = "From: alice@first.com, To: bob@second.com"
    result = parse_email_file(content)

    assert "first.com" in result["domains"]
    assert "second.com" in result["domains"]


# ---------------------------------------------------------------------------
# Tests - subdomains and special TLDs
# ---------------------------------------------------------------------------


def test_subdomain_email_extracts_subdomain_as_domain():
    """Email with a subdomain (mail.example.com) should use the full subdomain."""
    content = "user@mail.example.com"
    result = parse_email_file(content)

    # The parser extracts whatever is after @
    assert "mail.example.com" in result["domains"]


def test_long_tld_email_accepted():
    """Email addresses with long TLDs like .education should be accepted."""
    content = "student@university.education"
    result = parse_email_file(content)

    # Whether accepted depends on the _HOSTNAME_RE pattern (>= 2 chars TLD)
    # .education has 9 chars - should match
    assert "university.education" in result["domains"]


# ---------------------------------------------------------------------------
# Tests - result structure
# ---------------------------------------------------------------------------


def test_result_contains_required_keys():
    """parse_email_file always returns a dict with 'domains' and 'invalid_lines'."""
    result = parse_email_file("user@example.com")

    assert "domains" in result
    assert "invalid_lines" in result
    assert isinstance(result["domains"], list)
    assert isinstance(result["invalid_lines"], list)


def test_domains_list_is_sorted():
    """The returned domain list should be sorted alphabetically."""
    content = "z@zebra.com\na@apple.com\nm@mango.org"
    result = parse_email_file(content)

    assert result["domains"] == sorted(result["domains"])


# ---------------------------------------------------------------------------
# Tests - large input
# ---------------------------------------------------------------------------


def test_large_input_with_many_domains():
    """Parser handles a large file with many unique domains efficiently."""
    lines = [f"user{i}@domain{i}.com" for i in range(100)]
    content = "\n".join(lines)
    result = parse_email_file(content)

    assert len(result["domains"]) == 100
    assert result["invalid_lines"] == []


def test_large_input_with_repeated_domains():
    """Many emails sharing the same domain produce only one domain entry."""
    lines = [f"user{i}@shared.example.com" for i in range(50)]
    content = "\n".join(lines)
    result = parse_email_file(content)

    assert len(result["domains"]) == 1
    assert result["domains"][0] == "shared.example.com"


# ---------------------------------------------------------------------------
# Tests - whitespace handling
# ---------------------------------------------------------------------------


def test_leading_trailing_whitespace_on_lines_stripped():
    """Lines with surrounding whitespace should still extract the email."""
    content = "   user@example.com   "
    result = parse_email_file(content)

    assert "example.com" in result["domains"]


def test_windows_line_endings_handled():
    """Files with Windows-style (CRLF) line endings should parse correctly."""
    content = "alice@first.com\r\nbob@second.com\r\n"
    result = parse_email_file(content)

    assert "first.com" in result["domains"]
    assert "second.com" in result["domains"]


# ---------------------------------------------------------------------------
# Tests - bare domain list parsing
# ---------------------------------------------------------------------------


def test_bare_domain_single():
    """A file with one bare domain name should be accepted."""
    result = parse_import_file("example.com")

    assert "example.com" in result["domains"]
    assert result["invalid_lines"] == []


def test_bare_domain_multiple():
    """Multiple bare domain names (one per line) are all extracted."""
    content = "example.com\nanother.org\ntest.net"
    result = parse_import_file(content)

    assert result["domains"] == ["another.org", "example.com", "test.net"]
    assert result["invalid_lines"] == []


def test_bare_domain_deduplication():
    """Duplicate bare domains are deduplicated."""
    content = "example.com\nexample.com\nexample.com"
    result = parse_import_file(content)

    assert result["domains"] == ["example.com"]


def test_bare_domain_normalised_to_lowercase():
    """Bare domains with uppercase letters are lowercased."""
    content = "EXAMPLE.COM\nAnother.Org"
    result = parse_import_file(content)

    assert "example.com" in result["domains"]
    assert "another.org" in result["domains"]


def test_bare_domain_with_subdomain():
    """Bare subdomains like mail.example.com are accepted."""
    content = "mail.example.com"
    result = parse_import_file(content)

    assert "mail.example.com" in result["domains"]


def test_bare_domain_with_whitespace():
    """Leading/trailing whitespace around a bare domain is stripped."""
    content = "   example.com   "
    result = parse_import_file(content)

    assert "example.com" in result["domains"]


def test_bare_domain_invalid_format_rejected():
    """Lines that are not valid domains and not emails go to invalid_lines."""
    content = "not-a-domain\n123.456\n@nope"
    result = parse_import_file(content)

    assert result["domains"] == []
    assert len(result["invalid_lines"]) == 3


# ---------------------------------------------------------------------------
# Tests - CSV/delimited domain lists
# ---------------------------------------------------------------------------


def test_comma_separated_domains():
    """Comma-separated domains on one line are all extracted."""
    content = "example.com,another.org,test.net"
    result = parse_import_file(content)

    assert "example.com" in result["domains"]
    assert "another.org" in result["domains"]
    assert "test.net" in result["domains"]


def test_semicolon_separated_domains():
    """Semicolon-separated domains on one line are all extracted."""
    content = "example.com;another.org"
    result = parse_import_file(content)

    assert "example.com" in result["domains"]
    assert "another.org" in result["domains"]


def test_tab_separated_domains():
    """Tab-separated domains on one line are all extracted."""
    content = "example.com\tanother.org"
    result = parse_import_file(content)

    assert "example.com" in result["domains"]
    assert "another.org" in result["domains"]


def test_quoted_domains_in_csv():
    """Domains wrapped in quotes (CSV export) have quotes stripped."""
    content = '"example.com","another.org"'
    result = parse_import_file(content)

    assert "example.com" in result["domains"]
    assert "another.org" in result["domains"]


# ---------------------------------------------------------------------------
# Tests - mixed email and domain content
# ---------------------------------------------------------------------------


def test_mixed_emails_and_domains():
    """A file mixing emails and bare domains extracts all unique domains."""
    content = "alice@example.com\nanother.org\nbob@test.net\nmysite.io"
    result = parse_import_file(content)

    assert "example.com" in result["domains"]
    assert "another.org" in result["domains"]
    assert "test.net" in result["domains"]
    assert "mysite.io" in result["domains"]
    assert result["invalid_lines"] == []


def test_mixed_with_invalid_lines():
    """Mixed content with some invalid lines separates correctly."""
    content = "example.com\nnot valid\nalice@test.org\n12345"
    result = parse_import_file(content)

    assert "example.com" in result["domains"]
    assert "test.org" in result["domains"]
    assert "not valid" in result["invalid_lines"]
    assert "12345" in result["invalid_lines"]


# ---------------------------------------------------------------------------
# Tests - comment lines
# ---------------------------------------------------------------------------


def test_comment_lines_skipped():
    """Lines starting with # are treated as comments and skipped."""
    content = "# This is a header\nexample.com\n# Another comment\ntest.org"
    result = parse_import_file(content)

    assert result["domains"] == ["example.com", "test.org"]
    assert result["invalid_lines"] == []


# ---------------------------------------------------------------------------
# Tests - backward compatibility alias
# ---------------------------------------------------------------------------


def test_parse_email_file_is_alias():
    """parse_email_file is an alias for parse_import_file."""
    assert parse_email_file is parse_import_file
