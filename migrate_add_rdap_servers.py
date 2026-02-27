"""Add rdap_servers column to dns_settings table.

Run once after updating models.py:
    python migrate_add_rdap_servers.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Add rdap_servers column to dns_settings if it does not exist."""
    app = create_app()
    with app.app_context():
        try:
            db.session.execute(
                text(
                    "ALTER TABLE dns_settings "
                    "ADD COLUMN rdap_servers TEXT NOT NULL DEFAULT '[\"https://rdap.org\"]'"
                )
            )
            db.session.commit()
            print("  Column 'rdap_servers' added to dns_settings.")
        except Exception as exc:
            db.session.rollback()
            if "duplicate column" in str(exc).lower():
                print("  Column 'rdap_servers' already exists — skipping.")
            else:
                raise


if __name__ == "__main__":
    migrate()
