"""Add managed_domains column to dns_settings table.

Run once after updating models.py:
    python migrate_add_managed_domains.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Add the managed_domains column if it does not already exist."""
    app = create_app()
    with app.app_context():
        try:
            db.session.execute(
                text("ALTER TABLE dns_settings ADD COLUMN managed_domains TEXT")
            )
            db.session.commit()
            print("  Column 'managed_domains' added to dns_settings.")
        except Exception as exc:
            db.session.rollback()
            if "duplicate column" in str(exc).lower():
                print("  Column 'managed_domains' already exists — skipping.")
            else:
                raise


if __name__ == "__main__":
    migrate()
