"""Add policy_published_json column to dmarc_reports table.

Run once after updating models.py:
    python migrate_add_dmarc_policy.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Add policy_published_json column to dmarc_reports if it does not exist."""
    app = create_app()
    with app.app_context():
        try:
            db.session.execute(
                text(
                    "ALTER TABLE dmarc_reports"
                    " ADD COLUMN policy_published_json TEXT"
                )
            )
            db.session.commit()
            print("  Column 'policy_published_json' added to dmarc_reports.")
        except Exception as exc:
            db.session.rollback()
            if "duplicate column" in str(exc).lower():
                print("  Column 'policy_published_json' already exists — skipping.")
            else:
                raise


if __name__ == "__main__":
    migrate()
