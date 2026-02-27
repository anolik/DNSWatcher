"""Add data_retention_days column to dns_settings table.

Run once after updating models.py:
    python migrate_add_retention.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Add data_retention_days column to dns_settings if it does not exist."""
    app = create_app()
    with app.app_context():
        try:
            db.session.execute(
                text(
                    "ALTER TABLE dns_settings"
                    " ADD COLUMN data_retention_days INTEGER NOT NULL DEFAULT 90"
                )
            )
            db.session.commit()
            print("  Column 'data_retention_days' added to dns_settings.")
        except Exception as exc:
            db.session.rollback()
            if "duplicate column" in str(exc).lower():
                print("  Column 'data_retention_days' already exists — skipping.")
            else:
                raise


if __name__ == "__main__":
    migrate()
