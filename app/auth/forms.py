"""
F05 - Flask-WTF forms for the authentication blueprint.
"""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    """Form for authenticating an existing user."""

    username: StringField = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=1, max=80, message="Username must be between 1 and 80 characters."),
        ],
    )
    password: PasswordField = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
        ],
    )
    submit: SubmitField = SubmitField("Log In")
