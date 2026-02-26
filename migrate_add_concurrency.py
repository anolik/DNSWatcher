"""Add check_concurrency column to dns_settings table.

Run once after updating models.py:
    python migrate_add_concurrency.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Add the check_concurrency column if it does not already exist."""
    app = create_app()
    with app.app_context():
        try:
            db.session.execute(
                text(
                    "ALTER TABLE dns_settings "
                    "ADD COLUMN check_concurrency INTEGER NOT NULL DEFAULT 5"
                )
            )
            db.session.commit()
            print("  Column 'check_concurrency' added to dns_settings.")
        except Exception as exc:
            db.session.rollback()
            if "duplicate column" in str(exc).lower():
                print("  Column 'check_concurrency' already exists — skipping.")
            else:
                raise


if __name__ == "__main__":
    migrate()
