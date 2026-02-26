"""
Migration script: add MX and registrar columns to check_results table.

SQLite does not support adding columns to existing tables via db.create_all(),
so this script uses ALTER TABLE statements executed through the SQLAlchemy
engine connection.  It handles the "duplicate column" error gracefully in case
the migration has already been applied.

Usage:
    python migrate_add_mx_registrar.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Add mx_records, mx_provider, registrar, registrar_details columns."""
    app = create_app()

    columns = [
        ("mx_records", "TEXT"),
        ("mx_provider", "VARCHAR(100)"),
        ("registrar", "VARCHAR(200)"),
        ("registrar_details", "TEXT"),
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
