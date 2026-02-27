"""
F05 - Flask-WTF forms for the authentication blueprint.
"""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional


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


class ProfileForm(FlaskForm):
    """Form for editing user profile."""

    full_name = StringField("Full Name", validators=[Optional(), Length(max=200)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    language = SelectField(
        "Language",
        choices=[("fr", "Fran\u00e7ais"), ("en", "English")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Save Profile")


class ChangePasswordForm(FlaskForm):
    """Form for changing password."""

    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords must match."),
        ],
    )
    submit_password = SubmitField("Change Password")


class ForgotPasswordForm(FlaskForm):
    """Form for requesting a password reset."""

    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Reset Link")


class ResetPasswordForm(FlaskForm):
    """Form for setting a new password after reset."""

    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Reset Password")
