"""
Migration script: create dnsbl_cooldowns table.

This table tracks query-refused responses per DNSBL provider and manages
24-hour cooldowns after 3 consecutive refusals.

For new installs, db.create_all() handles this automatically.
For existing installs, run this script once.

Usage:
    python migrate_add_dnsbl_cooldown.py
"""

from __future__ import annotations

from sqlalchemy import text

from app import create_app, db


def migrate() -> None:
    """Create dnsbl_cooldowns table if it does not exist."""
    app = create_app()

    with app.app_context():
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS dnsbl_cooldowns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dnsbl VARCHAR(200) NOT NULL UNIQUE,
                consecutive_refusals INTEGER NOT NULL DEFAULT 0,
                last_refused_at DATETIME,
                cooldown_until DATETIME
            )
        """))
        db.session.commit()
        print("  Table dnsbl_cooldowns: created (or already exists)")
        print("\nMigration complete.")


if __name__ == "__main__":
    migrate()
