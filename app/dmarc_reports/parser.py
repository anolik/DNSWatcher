"""
DMARC aggregate report parser (RFC 7489).

Supports ZIP-compressed, GZ-compressed, and plain XML reports.
"""

from __future__ import annotations

import gzip
import io
import logging
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def parse_dmarc_attachment(filename: str, data: bytes) -> dict | None:
    """Parse a DMARC aggregate report attachment.

    Accepts ZIP, GZ, or raw XML.  Returns a normalised dict or None if
    the format is unrecognised or the content is not a valid DMARC report.

    Args:
        filename: Original attachment filename (used to detect format).
        data: Raw bytes of the attachment.

    Returns:
        Normalised report dict or None.
    """
    xml_bytes = _decompress(filename.lower(), data)
    if xml_bytes is None:
        logger.warning("parse_dmarc_attachment: unsupported format for %r", filename)
        return None
    return _parse_xml(xml_bytes)


# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------


def _decompress(filename: str, data: bytes) -> bytes | None:
    """Return raw XML bytes from the (possibly compressed) attachment."""
    if filename.endswith(".zip"):
        return _unzip(data)
    if filename.endswith(".gz"):
        try:
            return gzip.decompress(data)
        except Exception as exc:
            logger.warning("GZ decompression failed: %s", exc)
            return None
    if filename.endswith(".xml"):
        return data
    # Try ZIP first, then GZ, then treat as raw XML
    result = _unzip(data)
    if result is not None:
        return result
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    return data  # assume raw XML


def _unzip(data: bytes) -> bytes | None:
    """Extract the first XML-like file from a ZIP archive."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.lower().endswith((".xml", ".dmarc")):
                    return zf.read(name)
            # Fallback: return first file regardless of extension
            names = zf.namelist()
            if names:
                return zf.read(names[0])
    except Exception as exc:
        logger.debug("ZIP extraction failed: %s", exc)
    return None


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------


def _parse_xml(xml_bytes: bytes) -> dict | None:
    """Parse DMARC XML and return a normalised dict."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        logger.warning("XML parse error: %s", exc)
        return None

    # Locate <feedback> element (may be the root or a child)
    if root.tag == "feedback":
        feedback = root
    else:
        feedback = root.find("feedback")
        if feedback is None:
            feedback = root  # Try treating the document as the report

    # ------------------------------------------------------------------
    # report_metadata
    # ------------------------------------------------------------------
    meta = feedback.find("report_metadata")
    if meta is None:
        logger.warning("Missing <report_metadata>")
        return None

    report_id = _text(meta, "report_id") or ""
    org_name = _text(meta, "org_name") or ""

    date_range = meta.find("date_range")
    begin_ts = int(_text(date_range, "begin") or 0) if date_range is not None else 0
    end_ts = int(_text(date_range, "end") or 0) if date_range is not None else 0

    begin_date = datetime.fromtimestamp(begin_ts, tz=timezone.utc)
    end_date = datetime.fromtimestamp(end_ts, tz=timezone.utc)

    # ------------------------------------------------------------------
    # policy_published
    # ------------------------------------------------------------------
    policy = feedback.find("policy_published")
    policy_domain = _text(policy, "domain") or "" if policy is not None else ""
    published_adkim = _text(policy, "adkim") or "" if policy is not None else ""
    published_aspf = _text(policy, "aspf") or "" if policy is not None else ""
    published_pct_str = _text(policy, "pct") if policy is not None else None
    published_pct = int(published_pct_str) if published_pct_str is not None else None
    published_sp = _text(policy, "sp") or "" if policy is not None else ""

    # ------------------------------------------------------------------
    # record[]
    # ------------------------------------------------------------------
    records: list[dict] = []
    for record in feedback.findall("record"):
        row = record.find("row")
        if row is None:
            continue

        source_ip = _text(row, "source_ip") or ""
        count = int(_text(row, "count") or 0)

        policy_eval = row.find("policy_evaluated")
        disposition = _text(policy_eval, "disposition") or "none" if policy_eval is not None else "none"
        dkim_eval = _text(policy_eval, "dkim") or "fail" if policy_eval is not None else "fail"
        spf_eval = _text(policy_eval, "spf") or "fail" if policy_eval is not None else "fail"

        override_reason = ""
        override_comment = ""
        if policy_eval is not None:
            reason_elem = policy_eval.find("reason")
            if reason_elem is not None:
                override_reason = _text(reason_elem, "type") or ""
                override_comment = _text(reason_elem, "comment") or ""

        # identifiers
        identifiers = record.find("identifiers")
        header_from = _text(identifiers, "header_from") or "" if identifiers is not None else ""
        envelope_to = _text(identifiers, "envelope_to") or "" if identifiers is not None else ""
        envelope_from = _text(identifiers, "envelope_from") or "" if identifiers is not None else ""

        # auth_results
        auth_results = record.find("auth_results")
        dkim_domain: str | None = None
        dkim_result: str | None = None
        dkim_selector: str | None = None
        dkim_result_raw: str | None = None
        spf_domain: str | None = None
        spf_result: str | None = None
        spf_result_raw: str | None = None
        spf_scope: str | None = None
        all_dkim_results: list[dict] = []

        if auth_results is not None:
            for dkim_elem in auth_results.findall("dkim"):
                d = _text(dkim_elem, "domain")
                r = _text(dkim_elem, "result")
                s = _text(dkim_elem, "selector")
                all_dkim_results.append({"domain": d, "selector": s, "result": r})
                if dkim_domain is None:  # keep first as primary
                    dkim_domain = d
                    dkim_result = r
                    dkim_selector = s
                    dkim_result_raw = r

            spf_elem = auth_results.find("spf")
            if spf_elem is not None:
                spf_domain = _text(spf_elem, "domain")
                spf_result = _text(spf_elem, "result")
                spf_result_raw = spf_result
                spf_scope = _text(spf_elem, "scope")

        records.append({
            "source_ip": source_ip,
            "count": count,
            "disposition": disposition,
            "dkim": dkim_eval,
            "spf": spf_eval,
            "header_from": header_from,
            "envelope_to": envelope_to,
            "envelope_from": envelope_from,
            "override_reason": override_reason,
            "override_comment": override_comment,
            "dkim_domain": dkim_domain,
            "dkim_result": dkim_result,
            "dkim_selector": dkim_selector,
            "dkim_result_raw": dkim_result_raw,
            "all_dkim_results": all_dkim_results,
            "spf_domain": spf_domain,
            "spf_result": spf_result,
            "spf_result_raw": spf_result_raw,
            "spf_scope": spf_scope,
        })

    return {
        "report_id": report_id,
        "org_name": org_name,
        "policy_domain": policy_domain,
        "begin_date": begin_date,
        "end_date": end_date,
        "published_adkim": published_adkim,
        "published_aspf": published_aspf,
        "published_pct": published_pct,
        "published_sp": published_sp,
        "records": records,
    }


def _text(element: ET.Element | None, tag: str) -> str | None:
    """Return stripped text of a child element, or None."""
    if element is None:
        return None
    child = element.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip()
