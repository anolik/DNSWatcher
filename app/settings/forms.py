"""
F22 - Flask-WTF forms for the settings blueprint.
"""

from __future__ import annotations

import re

from flask_wtf import FlaskForm
from wtforms import BooleanField, IntegerField, SelectField, StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Optional, ValidationError

# Curated timezone list covering major regions.
# Uses IANA timezone names supported by Python's zoneinfo module.
TIMEZONE_CHOICES: list[tuple[str, str]] = [
    ("UTC", "UTC"),
    ("US/Eastern", "US / Eastern (New York)"),
    ("US/Central", "US / Central (Chicago)"),
    ("US/Mountain", "US / Mountain (Denver)"),
    ("US/Pacific", "US / Pacific (Los Angeles)"),
    ("US/Alaska", "US / Alaska"),
    ("US/Hawaii", "US / Hawaii"),
    ("Canada/Atlantic", "Canada / Atlantic (Halifax)"),
    ("Canada/Eastern", "Canada / Eastern (Toronto)"),
    ("Canada/Central", "Canada / Central (Winnipeg)"),
    ("Canada/Mountain", "Canada / Mountain (Edmonton)"),
    ("Canada/Pacific", "Canada / Pacific (Vancouver)"),
    ("Europe/London", "Europe / London"),
    ("Europe/Paris", "Europe / Paris"),
    ("Europe/Berlin", "Europe / Berlin"),
    ("Europe/Amsterdam", "Europe / Amsterdam"),
    ("Europe/Brussels", "Europe / Brussels"),
    ("Europe/Zurich", "Europe / Zurich"),
    ("Europe/Rome", "Europe / Rome"),
    ("Europe/Madrid", "Europe / Madrid"),
    ("Europe/Lisbon", "Europe / Lisbon"),
    ("Europe/Stockholm", "Europe / Stockholm"),
    ("Europe/Oslo", "Europe / Oslo"),
    ("Europe/Helsinki", "Europe / Helsinki"),
    ("Europe/Warsaw", "Europe / Warsaw"),
    ("Europe/Bucharest", "Europe / Bucharest"),
    ("Europe/Athens", "Europe / Athens"),
    ("Europe/Moscow", "Europe / Moscow"),
    ("Asia/Dubai", "Asia / Dubai"),
    ("Asia/Kolkata", "Asia / Kolkata (India)"),
    ("Asia/Shanghai", "Asia / Shanghai (China)"),
    ("Asia/Tokyo", "Asia / Tokyo"),
    ("Asia/Seoul", "Asia / Seoul"),
    ("Asia/Singapore", "Asia / Singapore"),
    ("Asia/Hong_Kong", "Asia / Hong Kong"),
    ("Australia/Sydney", "Australia / Sydney"),
    ("Australia/Melbourne", "Australia / Melbourne"),
    ("Australia/Perth", "Australia / Perth"),
    ("Pacific/Auckland", "Pacific / Auckland (New Zealand)"),
    ("America/Sao_Paulo", "America / Sao Paulo"),
    ("America/Mexico_City", "America / Mexico City"),
    ("America/Argentina/Buenos_Aires", "America / Buenos Aires"),
    ("Africa/Johannesburg", "Africa / Johannesburg"),
    ("Africa/Cairo", "Africa / Cairo"),
    ("Africa/Lagos", "Africa / Lagos"),
]

_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


def _is_valid_ip(address: str) -> bool:
    """Return True if *address* is a valid IPv4 address."""
    if not _IP_RE.match(address):
        return False
    parts = address.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


class DnsSettingsForm(FlaskForm):
    """Form for editing the DNS resolver configuration."""

    resolvers: TextAreaField = TextAreaField(
        "DNS Resolvers (one IP per line)",
        validators=[DataRequired(message="At least one resolver IP is required.")],
        render_kw={
            "rows": 5,
            "placeholder": "8.8.8.8\n1.1.1.1\n9.9.9.9",
        },
    )
    timeout_seconds: IntegerField = IntegerField(
        "Timeout (seconds)",
        validators=[
            DataRequired(message="Timeout is required."),
            NumberRange(min=1, max=30, message="Timeout must be between 1 and 30 seconds."),
        ],
    )
    retries: IntegerField = IntegerField(
        "Retries",
        validators=[
            DataRequired(message="Retries is required."),
            NumberRange(min=1, max=10, message="Retries must be between 1 and 10."),
        ],
    )
    flap_threshold: IntegerField = IntegerField(
        "Flap Threshold",
        validators=[
            DataRequired(message="Flap threshold is required."),
            NumberRange(
                min=1, max=5, message="Flap threshold must be between 1 and 5."
            ),
        ],
    )
    display_timezone: SelectField = SelectField(
        "Display Timezone",
        choices=TIMEZONE_CHOICES,
        default="UTC",
    )
    check_concurrency: IntegerField = IntegerField(
        "Check Concurrency",
        validators=[
            DataRequired(message="Concurrency is required."),
            NumberRange(min=1, max=10, message="Concurrency must be between 1 and 10."),
        ],
    )
    managed_domains: TextAreaField = TextAreaField(
        "Managed Domains (one hostname per line)",
        render_kw={
            "rows": 8,
            "placeholder": "example.com\nmail.example.com\nother.org",
        },
    )
    # Feature toggles
    check_spf_enabled: BooleanField = BooleanField("SPF")
    check_dmarc_enabled: BooleanField = BooleanField("DMARC")
    check_dkim_enabled: BooleanField = BooleanField("DKIM")
    check_mx_enabled: BooleanField = BooleanField("MX Records")
    check_reputation_enabled: BooleanField = BooleanField("Reputation (DNSBL)")
    check_registrar_enabled: BooleanField = BooleanField("Registrar (WHOIS)")
    check_geolocation_enabled: BooleanField = BooleanField("Geolocation & Loi 25")
    check_mta_sts_enabled: BooleanField = BooleanField("MTA-STS & TLS-RPT")
    check_bimi_enabled: BooleanField = BooleanField("BIMI")
    check_tls_enabled: BooleanField = BooleanField("SMTP TLS (STARTTLS)")

    data_retention_days: IntegerField = IntegerField(
        "Data retention (days)",
        validators=[
            DataRequired(message="Retention period is required."),
            NumberRange(min=7, max=730, message="Retention must be between 7 and 730 days."),
        ],
    )

    graph_enabled: BooleanField = BooleanField("Enable Microsoft Graph API auto-fetch")
    graph_tenant_id: StringField = StringField("Azure Tenant ID", validators=[Optional()])
    graph_client_id: StringField = StringField("App (Client) ID", validators=[Optional()])
    graph_client_secret: StringField = StringField(
        "Client Secret",
        render_kw={"type": "password", "autocomplete": "new-password"},
        validators=[Optional()],
    )
    graph_mailbox: StringField = StringField(
        "Mailbox email (rua= address)",
        validators=[Optional()],
    )
    submit: SubmitField = SubmitField("Save Settings")

    def validate_resolvers(self, field: TextAreaField) -> None:
        """Ensure each non-empty line is a valid IPv4 address."""
        lines = [line.strip() for line in (field.data or "").splitlines()]
        valid_ips = [line for line in lines if line]
        if not valid_ips:
            raise ValidationError("At least one resolver IP is required.")
        invalid = [ip for ip in valid_ips if not _is_valid_ip(ip)]
        if invalid:
            raise ValidationError(
                f"Invalid IP address(es): {', '.join(invalid)}. "
                "Each resolver must be a valid IPv4 address."
            )
