"""
F06 - Admin user creation script for SPF/DMARC/DKIM Watcher.

Creates a new admin user in the database.  Credentials may be supplied
via command-line flags or entered interactively when flags are omitted.

Usage:
    python create_admin.py --username admin --password s3cr3tP@ss
    python create_admin.py          # prompts interactively
"""

from __future__ import annotations

import argparse
import getpass
import sys

from werkzeug.security import generate_password_hash

from app import create_app, db
from app.models import User


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an admin user for the SPF/DMARC/DKIM Watcher application."
    )
    parser.add_argument(
        "--username",
        type=str,
        default=None,
        help="Username for the new admin account (prompted if omitted).",
    )
    parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Password for the new admin account (prompted if omitted).",
    )
    parser.add_argument(
        "--email",
        type=str,
        default=None,
        help="Email for the new admin account (prompted if omitted).",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------


def prompt_username() -> str:
    """Prompt for and return a non-empty username."""
    while True:
        username = input("Username: ").strip()
        if username:
            return username
        print("Username must not be empty. Please try again.")


def prompt_password() -> str:
    """Prompt for a password (with confirmation) that is >= 8 characters."""
    while True:
        password = getpass.getpass("Password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters. Please try again.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Please try again.")
            continue
        return password


def prompt_email() -> str:
    """Prompt for and return a non-empty email address."""
    while True:
        email = input("Email: ").strip()
        if email and "@" in email:
            return email
        print("Please enter a valid email address.")


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def create_admin(username: str, password: str, email: str) -> None:
    """Create the superadmin user inside the Flask application context."""
    if len(password) < 8:
        print("ERROR: Password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)

    app = create_app()

    with app.app_context():
        existing: User | None = (
            db.session.execute(db.select(User).where(User.username == username))
            .scalars()
            .first()
        )
        if existing is not None:
            print(f"ERROR: A user with username '{username}' already exists.", file=sys.stderr)
            sys.exit(1)

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            role="superadmin",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

        print(f"Superadmin user '{username}' created successfully (id={user.id}, role=superadmin).")


def main() -> None:
    args = parse_args()

    # Detect non-interactive mode (e.g. Railway/Docker)
    interactive = sys.stdin.isatty()

    username: str = args.username if args.username else (prompt_username() if interactive else _bail("--username"))
    password: str = args.password if args.password else (prompt_password() if interactive else _bail("--password"))
    email: str = args.email if args.email else (prompt_email() if interactive else "admin@localhost")

    create_admin(username, password, email)


def _bail(flag: str) -> str:
    """Exit with error when a required flag is missing in non-interactive mode."""
    print(f"ERROR: {flag} is required in non-interactive mode.", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
