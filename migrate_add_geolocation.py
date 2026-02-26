"""
Migration script: add MX geolocation and Law 25 columns to check_results table.

Adds two columns for tracking the physical location of MX servers and the
resulting Quebec Law 25 compliance status.  Uses ALTER TABLE statements
executed through the SQLAlchemy engine connection.  Handles the "duplicate
column" error gracefully in case the migration has already been applied.

Usage:
    python migrate_add_geolocation.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Add mx_geolocation and law25_status columns to check_results."""
    app = create_app()

    columns = [
        ("mx_geolocation", "TEXT"),
        ("law25_status", "VARCHAR(20)"),
    ]

    with app.app_context():
        for col_name, col_type in columns:
            try:
                db.session.execute(
                    text(f"ALTER TABLE check_results ADD COLUMN {col_name} {col_type}")
                )
                db.session.commit()
                print(f"  Added column: check_results.{col_name} ({col_type})")
            except Exception as exc:
                db.session.rollback()
                if "duplicate column" in str(exc).lower():
                    print(f"  Column already exists: check_results.{col_name} (skipped)")
                else:
                    raise

    print("\nMigration complete.")


if __name__ == "__main__":
    migrate()
