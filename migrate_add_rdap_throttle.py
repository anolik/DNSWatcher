"""Add rdap_throttle_delay column to dns_settings table.

Run once after updating models.py:
    python migrate_add_rdap_throttle.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db

_COLUMNS = [
    ("rdap_throttle_delay", "REAL DEFAULT 2.0"),
]


def migrate() -> None:
    """Add RDAP throttle delay column to dns_settings if it does not exist."""
    app = create_app()
    with app.app_context():
        for col_name, col_type in _COLUMNS:
            try:
                db.session.execute(
                    text(f"ALTER TABLE dns_settings ADD COLUMN {col_name} {col_type}")
                )
                db.session.commit()
                print(f"  Column '{col_name}' added to dns_settings.")
            except Exception as exc:
                db.session.rollback()
                if "duplicate column" in str(exc).lower():
                    print(f"  Column '{col_name}' already exists — skipping.")
                else:
                    raise


if __name__ == "__main__":
    migrate()
