"""Migration: add breach_monitoring_enabled column to domains.

Per-domain flag to control which domains are checked for data breaches.
Defaults to False (opt-in).
"""

from __future__ import annotations

import logging
import sqlite3
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def migrate(db_path: str) -> None:
    """Add breach_monitoring_enabled column to domains if missing."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(domains)")
    existing = {row[1] for row in cursor.fetchall()}

    if "breach_monitoring_enabled" not in existing:
        cursor.execute(
            "ALTER TABLE domains ADD COLUMN breach_monitoring_enabled BOOLEAN DEFAULT 0 NOT NULL"
        )
        conn.commit()
        logger.info("Migration complete: added domains.breach_monitoring_enabled")
    else:
        logger.info("Migration skipped: column already exists")

    conn.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        from app import create_app

        app = create_app()
        with app.app_context():
            from app import db as flask_db

            db_url = str(flask_db.engine.url)
            if "///" in db_url:
                db_path = db_url.split("///", 1)[1]
            else:
                db_path = "instance/watcher.db"
            migrate(db_path)
    else:
        migrate(sys.argv[1])
