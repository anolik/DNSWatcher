"""
Microsoft Graph API client for fetching DMARC aggregate reports from Exchange Online.

Uses OAuth2 client credentials flow (no new pip dependencies - stdlib only).
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import DnsSettings

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_ATTACHMENT_EXTENSIONS = (".zip", ".gz", ".xml")


# ---------------------------------------------------------------------------
# Internal HTTP helper
# ---------------------------------------------------------------------------


def _make_request(
    url: str,
    *,
    token: str | None = None,
    method: str = "GET",
    body: dict | None = None,
    timeout: int = 10,
) -> dict:
    """Perform a single HTTP request and return the parsed JSON response.

    Args:
        url: Full request URL.
        token: OAuth2 bearer token for the Authorization header. Optional so
               the helper can also be used for the token endpoint itself.
        method: HTTP method (GET, PATCH, POST, etc.).
        body: Optional dict to be JSON-encoded and sent as the request body.
              When provided, Content-Type is set to application/json.
        timeout: Socket timeout in seconds.

    Returns:
        Parsed JSON response body as a dict.

    Raises:
        urllib.error.URLError: On network-level errors.
        urllib.error.HTTPError: On non-2xx responses.
        json.JSONDecodeError: If the response body is not valid JSON.
    """
    headers: dict[str, str] = {}

    if token is not None:
        headers["Authorization"] = f"Bearer {token}"

    data: bytes | None = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read()

    return json.loads(raw) if raw else {}


# ---------------------------------------------------------------------------
# OAuth2 token acquisition
# ---------------------------------------------------------------------------


def _get_access_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    timeout: int = 10,
) -> str:
    """Obtain an OAuth2 client credentials access token from Azure AD.

    Args:
        tenant_id: Azure AD tenant (directory) ID.
        client_id: Application (client) ID registered in Azure AD.
        client_secret: Client secret for the registered application.
        timeout: Socket timeout in seconds.

    Returns:
        The raw access token string.

    Raises:
        urllib.error.URLError: On network-level errors.
        urllib.error.HTTPError: On non-2xx token responses (e.g. bad credentials).
        KeyError: If the response JSON does not contain 'access_token'.
    """
    url = _TOKEN_URL.format(tenant_id=tenant_id)
    form_body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=form_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout) as response:
        payload = json.loads(response.read())

    return payload["access_token"]


# ---------------------------------------------------------------------------
# Graph API operations
# ---------------------------------------------------------------------------


def _list_unread_messages(
    mailbox: str,
    token: str,
    max_age_days: int = 30,
) -> list[dict]:
    """Return up to 50 unread messages that have attachments.

    Only messages received within the last *max_age_days* days are returned
    to avoid downloading excessive historical data on first run.

    Args:
        mailbox: The Exchange Online mailbox UPN or ID.
        token: Valid Graph API bearer token.
        max_age_days: Maximum age of messages to fetch (default 30 days).

    Returns:
        List of message objects from the Graph API response.
    """
    since = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    filter_expr = (
        f"hasAttachments eq true and isRead eq false"
        f" and receivedDateTime ge {since}"
    )
    params = urllib.parse.urlencode(
        {
            "$filter": filter_expr,
            "$top": "50",
            "$select": "id,subject,hasAttachments",
        }
    )
    url = f"{_GRAPH_BASE}/users/{mailbox}/messages?{params}"
    logger.info("Graph list messages: filter since %s (%d days)", since, max_age_days)
    response = _make_request(url, token=token)
    return response.get("value", [])


def _get_attachments(mailbox: str, message_id: str, token: str) -> list[dict]:
    """Fetch attachment metadata and content for a single message.

    Only attachments whose filenames end with .zip, .gz, or .xml
    (case-insensitive) are included. The contentBytes field is decoded from
    Base64 into raw bytes.

    Args:
        mailbox: The Exchange Online mailbox UPN or ID.
        message_id: Graph API message ID.
        token: Valid Graph API bearer token.

    Returns:
        List of dicts with keys 'name' (str) and 'data' (bytes).
    """
    safe_msg_id = urllib.parse.quote(message_id, safe="")
    url = f"{_GRAPH_BASE}/users/{mailbox}/messages/{safe_msg_id}/attachments"
    response = _make_request(url, token=token)

    attachments: list[dict] = []
    for item in response.get("value", []):
        name: str = item.get("name", "")
        content_bytes: str | None = item.get("contentBytes")

        if not name.lower().endswith(_ATTACHMENT_EXTENSIONS):
            logger.debug(
                "Skipping attachment %r (unsupported extension) in message %s",
                name,
                message_id,
            )
            continue

        if not content_bytes:
            logger.debug(
                "Attachment %r in message %s has empty contentBytes, skipping",
                name,
                message_id,
            )
            continue

        try:
            data = base64.b64decode(content_bytes)
        except Exception as exc:
            logger.error(
                "Base64 decode failed for attachment %r in message %s: %s",
                name,
                message_id,
                exc,
            )
            continue

        logger.debug("Extracted attachment %r (%d bytes) from message %s", name, len(data), message_id)
        attachments.append({"name": name, "data": data})

    return attachments


def _mark_as_read(mailbox: str, message_id: str, token: str) -> None:
    """Mark a single message as read via a PATCH request.

    Args:
        mailbox: The Exchange Online mailbox UPN or ID.
        message_id: Graph API message ID.
        token: Valid Graph API bearer token.
    """
    safe_msg_id = urllib.parse.quote(message_id, safe="")
    url = f"{_GRAPH_BASE}/users/{mailbox}/messages/{safe_msg_id}"
    _make_request(url, token=token, method="PATCH", body={"isRead": True})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def fetch_dmarc_emails(settings: "DnsSettings") -> list[dict]:
    """Fetch unread emails with DMARC report attachments from Exchange Online.

    Uses the Microsoft Graph API with OAuth2 client credentials flow.
    Marks each processed email as read after successful attachment extraction.

    Args:
        settings: DnsSettings model instance with graph_* fields populated.

    Returns:
        List of dicts: [{"subject": str, "message_id": str, "attachments": [{"name": str, "data": bytes}]}]
        Returns empty list if credentials missing or on any fatal error.
    """
    # --- Validate required credentials ---
    tenant_id: str | None = settings.graph_tenant_id
    client_id: str | None = settings.graph_client_id
    client_secret: str | None = settings.graph_client_secret
    mailbox: str | None = settings.graph_mailbox

    missing = [
        name
        for name, value in (
            ("graph_tenant_id", tenant_id),
            ("graph_client_id", client_id),
            ("graph_client_secret", client_secret),
            ("graph_mailbox", mailbox),
        )
        if not value
    ]

    if missing:
        logger.warning(
            "Graph fetch skipped: missing required setting(s): %s",
            ", ".join(missing),
        )
        return []

    # --- Acquire OAuth2 token ---
    try:
        token = _get_access_token(
            tenant_id=tenant_id,  # type: ignore[arg-type]  # validated above
            client_id=client_id,  # type: ignore[arg-type]
            client_secret=client_secret,  # type: ignore[arg-type]
        )
    except urllib.error.HTTPError as exc:
        logger.error(
            "Graph token request failed (HTTP %s): %s",
            exc.code,
            exc.reason,
        )
        return []
    except urllib.error.URLError as exc:
        logger.error("Graph token request network error: %s", exc.reason)
        return []
    except (KeyError, json.JSONDecodeError) as exc:
        logger.error("Graph token response parse error: %s", exc)
        return []

    # --- List unread messages ---
    try:
        messages = _list_unread_messages(mailbox=mailbox, token=token)  # type: ignore[arg-type]
    except urllib.error.HTTPError as exc:
        logger.error(
            "Graph list messages failed (HTTP %s): %s",
            exc.code,
            exc.reason,
        )
        return []
    except urllib.error.URLError as exc:
        logger.error("Graph list messages network error: %s", exc.reason)
        return []
    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("Graph list messages response parse error: %s", exc)
        return []

    logger.info("Graph fetch: found %d unread messages with attachments", len(messages))

    # --- Process each message ---
    results: list[dict] = []

    for message in messages:
        message_id: str = message.get("id", "")
        subject: str = message.get("subject", "")

        if not message_id:
            logger.error("Graph message missing 'id' field, skipping entry")
            continue

        try:
            attachments = _get_attachments(
                mailbox=mailbox,  # type: ignore[arg-type]
                message_id=message_id,
                token=token,
            )
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            logger.error(
                "Failed to fetch attachments for message %s (HTTP %s): %s — %s",
                message_id,
                exc.code,
                exc.reason,
                body,
            )
            continue
        except urllib.error.URLError as exc:
            logger.error(
                "Network error fetching attachments for message %s: %s",
                message_id,
                exc.reason,
            )
            continue
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error(
                "Parse error for attachments of message %s: %s",
                message_id,
                exc,
            )
            continue

        if not attachments:
            # No relevant attachments; do not mark as read to avoid silently
            # swallowing non-DMARC emails.
            logger.debug(
                "No DMARC attachments found in message %s (%r), skipping mark-as-read",
                message_id,
                subject,
            )
            continue

        # Mark as read only after we have successfully extracted attachments.
        try:
            _mark_as_read(mailbox=mailbox, message_id=message_id, token=token)  # type: ignore[arg-type]
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            # Non-fatal: log and continue — the report data was still extracted.
            logger.error(
                "Could not mark message %s as read: %s",
                message_id,
                exc,
            )

        results.append(
            {
                "subject": subject,
                "message_id": message_id,
                "attachments": attachments,
            }
        )

    return results
