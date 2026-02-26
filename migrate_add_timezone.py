"""
Migration script: add display_timezone column to dns_settings table.

For new installs, db.create_all() handles this automatically.
For existing installs, run this script once.

Usage:
    python migrate_add_timezone.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Add display_timezone column to dns_settings table."""
    app = create_app()

    with app.app_context():
        try:
            db.session.execute(
                text(
                    "ALTER TABLE dns_settings "
                    "ADD COLUMN display_timezone VARCHAR(50) NOT NULL DEFAULT 'UTC'"
                )
            )
            db.session.commit()
            print("  Added column: dns_settings.display_timezone (VARCHAR(50))")
        except Exception as exc:
            db.session.rollback()
            if "duplicate column" in str(exc).lower():
                print("  Column already exists: dns_settings.display_timezone (skipped)")
            else:
                raise

    print("\nMigration complete.")


if __name__ == "__main__":
    migrate()
