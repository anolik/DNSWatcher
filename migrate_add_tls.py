"""Add TLS columns to check_results table.

Run once after updating models.py:
    python migrate_add_tls.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db

_COLUMNS = [
    ("tls_status", "TEXT"),
    ("tls_details", "TEXT"),
]


def migrate() -> None:
    """Add TLS columns to check_results if they do not exist."""
    app = create_app()
    with app.app_context():
        for col_name, col_type in _COLUMNS:
            try:
                db.session.execute(
                    text(f"ALTER TABLE check_results ADD COLUMN {col_name} {col_type}")
                )
                db.session.commit()
                print(f"  Column '{col_name}' added to check_results.")
            except Exception as exc:
                db.session.rollback()
                if "duplicate column" in str(exc).lower():
                    print(f"  Column '{col_name}' already exists — skipping.")
                else:
                    raise


if __name__ == "__main__":
    migrate()
