"""Forms for admin user and organization management."""
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Email, Length, NumberRange, Optional


class CreateUserForm(FlaskForm):
    """Form for creating a new user."""

    username = StringField("Username", validators=[DataRequired(), Length(min=1, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    full_name = StringField("Full Name", validators=[Optional(), Length(max=200)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    role = SelectField("Role", choices=[
        ("viewer", "Viewer"),
        ("editor", "Editor"),
        ("admin", "Admin"),
        ("superadmin", "Superadmin"),
    ], validators=[DataRequired()])
    org_id = SelectField("Organization", coerce=int, validators=[Optional()])
    submit = SubmitField("Create User")


class EditUserForm(FlaskForm):
    """Form for editing an existing user."""

    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    full_name = StringField("Full Name", validators=[Optional(), Length(max=200)])
    role = SelectField("Role", choices=[
        ("viewer", "Viewer"),
        ("editor", "Editor"),
        ("admin", "Admin"),
        ("superadmin", "Superadmin"),
    ], validators=[DataRequired()])
    org_id = SelectField("Organization", coerce=int, validators=[Optional()])
    is_active = BooleanField("Active")
    submit = SubmitField("Save Changes")


class CreateOrgForm(FlaskForm):
    """Form for creating a new organization."""

    name = StringField("Organization Name", validators=[DataRequired(), Length(max=200)])
    slug = StringField("Slug", validators=[DataRequired(), Length(max=100)])
    max_domains = IntegerField(
        "Max Domains", default=100, validators=[DataRequired(), NumberRange(min=1, max=10000)]
    )
    notes = TextAreaField("Notes", validators=[Optional(), Length(max=2000)])
    submit = SubmitField("Create Organization")


class EditOrgForm(FlaskForm):
    """Form for editing an existing organization."""

    name = StringField("Organization Name", validators=[DataRequired(), Length(max=200)])
    slug = StringField("Slug", validators=[DataRequired(), Length(max=100)])
    max_domains = IntegerField(
        "Max Domains", validators=[DataRequired(), NumberRange(min=1, max=10000)]
    )
    notes = TextAreaField("Notes", validators=[Optional(), Length(max=2000)])
    is_active = BooleanField("Active")
    submit = SubmitField("Save Changes")
