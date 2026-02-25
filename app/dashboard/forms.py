"""
F17 - Flask-WTF forms for the dashboard blueprint.
"""

from __future__ import annotations

import re

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError

# Hostname validation pattern: lowercase labels separated by dots, min 2-char TLD
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$"
)


class AddDomainForm(FlaskForm):
    """Inline form for adding a new domain to monitor."""

    hostname: StringField = StringField(
        "Hostname",
        validators=[
            DataRequired(message="Hostname is required."),
            Length(min=3, max=255, message="Hostname must be between 3 and 255 characters."),
        ],
        render_kw={"placeholder": "example.com", "class": "form-control"},
    )
    submit: SubmitField = SubmitField("Add Domain", render_kw={"class": "btn btn-primary"})

    def validate_hostname(self, field: StringField) -> None:
        """Enforce RFC-compliant hostname format (lowercase)."""
        value = (field.data or "").strip().lower()
        if not _HOSTNAME_RE.match(value):
            raise ValidationError(
                "Invalid hostname format. Use lowercase letters, digits, hyphens and dots "
                "(e.g. example.com)."
            )


class AddSelectorForm(FlaskForm):
    """Form for adding a DKIM selector to a domain."""

    selector: StringField = StringField(
        "Selector",
        validators=[
            DataRequired(message="Selector name is required."),
            Length(min=1, max=100, message="Selector must be between 1 and 100 characters."),
        ],
        render_kw={"placeholder": "default", "class": "form-control"},
    )
    submit: SubmitField = SubmitField("Add Selector", render_kw={"class": "btn btn-primary"})
