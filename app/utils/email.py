"""
F42 - Email sending via Microsoft Graph API.

Sends emails using the Graph API's sendMail endpoint.
Falls back to logging email content when Graph is not configured.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


def _get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain an OAuth2 client credentials access token."""
    url = _TOKEN_URL.format(tenant_id=tenant_id)
    form_body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }).encode("utf-8")

    req = urllib.request.Request(
        url, data=form_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = json.loads(response.read())
    return payload["access_token"]


def _get_graph_settings():
    """Load Graph API settings from DnsSettings (global, org_id=NULL)."""
    from app.utils.tenant import get_org_settings  # noqa: PLC0415
    return get_org_settings(None)


def send_email(to: str, subject: str, html_body: str, text_body: str = "") -> bool:
    """Send email via Microsoft Graph API.

    Uses graph_tenant_id, graph_client_id, graph_client_secret, graph_mailbox
    from DnsSettings (global). Returns True on success, False on failure.
    Falls back to logging the email content when Graph is not configured.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        html_body: HTML email body.
        text_body: Plain text email body (fallback).

    Returns:
        True if email was sent successfully, False otherwise.
    """
    settings = _get_graph_settings()

    if settings is None or not settings.graph_enabled:
        logger.info(
            "Email not sent (Graph not configured): to=%r subject=%r", to, subject
        )
        logger.debug("Email body (text): %s", text_body or html_body[:500])
        return False

    tenant_id = settings.graph_tenant_id
    client_id = settings.graph_client_id
    client_secret = settings.graph_client_secret
    mailbox = settings.graph_mailbox

    if not all([tenant_id, client_id, client_secret, mailbox]):
        logger.warning("Email not sent (incomplete Graph credentials): to=%r", to)
        return False

    try:
        token = _get_access_token(tenant_id, client_id, client_secret)
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError) as exc:
        logger.error("Graph token request failed for email send: %s", exc)
        return False

    # Build the sendMail payload
    message_payload = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": html_body,
            },
            "toRecipients": [
                {"emailAddress": {"address": to}}
            ],
        },
        "saveToSentItems": "false",
    }

    url = f"{_GRAPH_BASE}/users/{mailbox}/sendMail"
    data = json.dumps(message_payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            # 202 Accepted is the expected response
            logger.info(
                "Email sent via Graph: to=%r subject=%r status=%d",
                to, subject, response.status,
            )
            return True
    except urllib.error.HTTPError as exc:
        logger.error(
            "Graph sendMail failed (HTTP %s): to=%r subject=%r error=%s",
            exc.code, to, subject, exc.reason,
        )
        return False
    except urllib.error.URLError as exc:
        logger.error(
            "Graph sendMail network error: to=%r error=%s", to, exc.reason,
        )
        return False
