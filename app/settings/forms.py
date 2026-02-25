"""
F22 - Flask-WTF forms for the settings blueprint.
"""

from __future__ import annotations

import re

from flask_wtf import FlaskForm
from wtforms import IntegerField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError

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
            "class": "form-control font-monospace",
            "placeholder": "8.8.8.8\n1.1.1.1\n9.9.9.9",
        },
    )
    timeout_seconds: IntegerField = IntegerField(
        "Timeout (seconds)",
        validators=[
            DataRequired(message="Timeout is required."),
            NumberRange(min=1, max=30, message="Timeout must be between 1 and 30 seconds."),
        ],
        render_kw={"class": "form-control"},
    )
    retries: IntegerField = IntegerField(
        "Retries",
        validators=[
            DataRequired(message="Retries is required."),
            NumberRange(min=1, max=10, message="Retries must be between 1 and 10."),
        ],
        render_kw={"class": "form-control"},
    )
    flap_threshold: IntegerField = IntegerField(
        "Flap Threshold",
        validators=[
            DataRequired(message="Flap threshold is required."),
            NumberRange(
                min=1, max=5, message="Flap threshold must be between 1 and 5."
            ),
        ],
        render_kw={"class": "form-control"},
    )
    submit: SubmitField = SubmitField("Save Settings", render_kw={"class": "btn btn-primary"})

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
