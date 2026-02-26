"""Add feature toggle columns to dns_settings table.

Run once after updating models.py:
    python migrate_add_feature_toggles.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db

# All feature toggles default to 1 (enabled / True).
_COLUMNS = [
    "check_spf_enabled",
    "check_dmarc_enabled",
    "check_dkim_enabled",
    "check_mx_enabled",
    "check_reputation_enabled",
    "check_registrar_enabled",
    "check_geolocation_enabled",
    "check_mta_sts_enabled",
    "check_bimi_enabled",
    "check_tls_enabled",
]


def migrate() -> None:
    """Add feature toggle columns to dns_settings if they do not exist."""
    app = create_app()
    with app.app_context():
        for col_name in _COLUMNS:
            try:
                db.session.execute(
                    text(
                        f"ALTER TABLE dns_settings ADD COLUMN {col_name} BOOLEAN NOT NULL DEFAULT 1"
                    )
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
