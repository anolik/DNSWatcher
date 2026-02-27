"""
Unit tests for app/dmarc_reports/parser.py

Verifies that the DMARC aggregate report parser correctly extracts fields
from XML, including envelope_to (destination domain).
"""

from __future__ import annotations

from app.dmarc_reports.parser import parse_dmarc_attachment


# ---------------------------------------------------------------------------
# Sample XML
# ---------------------------------------------------------------------------

_REPORT_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>123456</report_id>
    <date_range>
      <begin>1700000000</begin>
      <end>1700086400</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
  </policy_published>
  <record>
    <row>
      <source_ip>198.51.100.1</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_to>recipient.org</envelope_to>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.5</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>quarantine</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_to>other-dest.net</envelope_to>
    </identifiers>
    <auth_results>
      <spf>
        <domain>spoofed.com</domain>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
</feedback>
"""


_REPORT_NO_ENVELOPE_TO = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>yahoo.com</org_name>
    <report_id>789</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published><domain>test.com</domain><p>none</p></policy_published>
  <record>
    <row>
      <source_ip>10.0.0.1</source_ip>
      <count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers>
      <header_from>test.com</header_from>
    </identifiers>
  </record>
</feedback>
"""


_REPORT_WITH_OVERRIDES = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>override-test</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>s</adkim>
    <aspf>s</aspf>
    <p>reject</p>
    <pct>100</pct>
    <sp>quarantine</sp>
  </policy_published>
  <record>
    <row>
      <source_ip>198.51.100.1</source_ip>
      <count>5</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
        <reason>
          <type>forwarded</type>
          <comment>Forwarded via mailing gateway</comment>
        </reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>bounce.example.com</envelope_from>
      <envelope_to>dest.org</envelope_to>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <selector>sel1</selector>
        <result>pass</result>
      </dkim>
      <dkim>
        <domain>thirdparty.com</domain>
        <selector>s2048</selector>
        <result>fail</result>
      </dkim>
      <spf>
        <domain>bounce.example.com</domain>
        <result>softfail</result>
        <scope>mfrom</scope>
      </spf>
    </auth_results>
  </record>
</feedback>
"""


_REPORT_MINIMAL_POLICY = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>yahoo.com</org_name>
    <report_id>minimal-policy</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>minimal.com</domain>
    <p>none</p>
  </policy_published>
  <record>
    <row>
      <source_ip>10.0.0.1</source_ip>
      <count>2</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>minimal.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>minimal.com</domain><result>pass</result></dkim>
      <spf><domain>minimal.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>
"""


# ---------------------------------------------------------------------------
# Tests - envelope_to parsing
# ---------------------------------------------------------------------------


def test_envelope_to_extracted_from_records():
    """Parser extracts envelope_to from <identifiers> element."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)

    assert result is not None
    records = result["records"]
    assert len(records) == 2
    assert records[0]["envelope_to"] == "recipient.org"
    assert records[1]["envelope_to"] == "other-dest.net"


def test_envelope_to_empty_when_missing():
    """When <envelope_to> is absent, the field defaults to empty string."""
    result = parse_dmarc_attachment("report.xml", _REPORT_NO_ENVELOPE_TO)

    assert result is not None
    records = result["records"]
    assert len(records) == 1
    assert records[0]["envelope_to"] == ""


# ---------------------------------------------------------------------------
# Tests - standard fields still work
# ---------------------------------------------------------------------------


def test_header_from_extracted():
    """Parser extracts header_from correctly."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)

    assert result["records"][0]["header_from"] == "example.com"


def test_source_ip_and_count_extracted():
    """Parser extracts source_ip and count correctly."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)

    assert result["records"][0]["source_ip"] == "198.51.100.1"
    assert result["records"][0]["count"] == 10
    assert result["records"][1]["source_ip"] == "203.0.113.5"
    assert result["records"][1]["count"] == 3


def test_report_metadata_extracted():
    """Parser extracts org_name, report_id, and policy_domain."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)

    assert result["org_name"] == "google.com"
    assert result["report_id"] == "123456"
    assert result["policy_domain"] == "example.com"


def test_policy_evaluation_extracted():
    """Parser extracts disposition, dkim, and spf from policy_evaluated."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)

    assert result["records"][0]["disposition"] == "none"
    assert result["records"][0]["dkim"] == "pass"
    assert result["records"][0]["spf"] == "pass"
    assert result["records"][1]["disposition"] == "quarantine"
    assert result["records"][1]["dkim"] == "fail"
    assert result["records"][1]["spf"] == "fail"


def test_auth_results_extracted():
    """Parser extracts dkim_domain, dkim_result, spf_domain, spf_result."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)

    assert result["records"][0]["dkim_domain"] == "example.com"
    assert result["records"][0]["dkim_result"] == "pass"
    assert result["records"][0]["spf_domain"] == "example.com"
    assert result["records"][0]["spf_result"] == "pass"


def test_invalid_xml_returns_none():
    """Invalid XML data returns None."""
    result = parse_dmarc_attachment("bad.xml", b"this is not xml")

    assert result is None


def test_gzip_format_supported():
    """Parser handles GZ-compressed XML."""
    import gzip

    gz_data = gzip.compress(_REPORT_XML)
    result = parse_dmarc_attachment("report.xml.gz", gz_data)

    assert result is not None
    assert result["report_id"] == "123456"
    assert result["records"][0]["envelope_to"] == "recipient.org"


def test_zip_format_supported():
    """Parser handles ZIP-compressed XML."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.xml", _REPORT_XML)
    zip_data = buf.getvalue()

    result = parse_dmarc_attachment("report.zip", zip_data)

    assert result is not None
    assert result["report_id"] == "123456"
    assert result["records"][0]["envelope_to"] == "recipient.org"


# ---------------------------------------------------------------------------
# Tests - new enriched fields
# ---------------------------------------------------------------------------


def test_envelope_from_extracted():
    """Parser extracts envelope_from from <identifiers> element."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    assert result["records"][0]["envelope_from"] == "bounce.example.com"


def test_envelope_from_empty_when_missing():
    """When <envelope_from> is absent, field defaults to empty string."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)
    assert result is not None
    assert result["records"][0]["envelope_from"] == ""


def test_override_reason_extracted():
    """Parser extracts override reason type."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    assert result["records"][0]["override_reason"] == "forwarded"


def test_override_comment_extracted():
    """Parser extracts override comment text."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    assert result["records"][0]["override_comment"] == "Forwarded via mailing gateway"


def test_override_empty_when_missing():
    """When no override reason present, fields default to empty strings."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)
    assert result is not None
    assert result["records"][0]["override_reason"] == ""
    assert result["records"][0]["override_comment"] == ""


def test_multiple_dkim_signatures():
    """Parser extracts all DKIM signatures into all_dkim_results list."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    dkim_results = result["records"][0]["all_dkim_results"]
    assert len(dkim_results) == 2
    assert dkim_results[0]["domain"] == "example.com"
    assert dkim_results[0]["selector"] == "sel1"
    assert dkim_results[0]["result"] == "pass"
    assert dkim_results[1]["domain"] == "thirdparty.com"
    assert dkim_results[1]["selector"] == "s2048"
    assert dkim_results[1]["result"] == "fail"


def test_dkim_selector_extracted():
    """Parser extracts DKIM selector from auth_results."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    assert result["records"][0]["dkim_selector"] == "sel1"


def test_dkim_selector_none_when_missing():
    """When no selector in auth_results, dkim_selector is None."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)
    assert result is not None
    # The original XML doesn't have <selector>
    assert result["records"][0]["dkim_selector"] is None


def test_spf_scope_extracted():
    """Parser extracts SPF scope from auth_results."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    assert result["records"][0]["spf_scope"] == "mfrom"


def test_spf_scope_none_when_missing():
    """When no scope in SPF auth_results, spf_scope is None."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)
    assert result is not None
    assert result["records"][0]["spf_scope"] is None


def test_granular_spf_results():
    """Parser captures raw SPF result values like softfail."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    assert result["records"][0]["spf_result_raw"] == "softfail"


def test_published_policy_fields():
    """Parser extracts published policy fields: adkim, aspf, pct, sp."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    assert result["published_adkim"] == "s"
    assert result["published_aspf"] == "s"
    assert result["published_pct"] == 100
    assert result["published_sp"] == "quarantine"


def test_published_policy_from_original_xml():
    """Published policy in existing test XML has adkim=r, aspf=r."""
    result = parse_dmarc_attachment("report.xml", _REPORT_XML)
    assert result is not None
    assert result["published_adkim"] == "r"
    assert result["published_aspf"] == "r"
    assert result["published_pct"] is None  # not in original XML
    assert result["published_sp"] == ""  # not in original XML


def test_missing_policy_fields_default():
    """When policy fields are absent, they default to empty/None."""
    result = parse_dmarc_attachment("report.xml", _REPORT_MINIMAL_POLICY)
    assert result is not None
    assert result["published_adkim"] == ""
    assert result["published_aspf"] == ""
    assert result["published_pct"] is None
    assert result["published_sp"] == ""


def test_backward_compat_old_records():
    """Old records without new fields are handled gracefully."""
    result = parse_dmarc_attachment("report.xml", _REPORT_NO_ENVELOPE_TO)
    assert result is not None
    rec = result["records"][0]
    # New fields should have defaults
    assert rec["envelope_from"] == ""
    assert rec["override_reason"] == ""
    assert rec["override_comment"] == ""
    assert rec["all_dkim_results"] == []  # no auth_results in this XML
    assert rec["dkim_selector"] is None
    assert rec["spf_scope"] is None


def test_dkim_result_raw_matches_result():
    """dkim_result_raw captures the same value as dkim_result."""
    result = parse_dmarc_attachment("report.xml", _REPORT_WITH_OVERRIDES)
    assert result is not None
    assert result["records"][0]["dkim_result_raw"] == "pass"
    assert result["records"][0]["dkim_result"] == "pass"
