"""Migration: add ns_provider and ns_details columns to check_results.

F13B - NS Provider Identification: stores the identified DNS hosting
provider (distinct from the registrar) and supporting details.
"""

from __future__ import annotations

import logging
import sqlite3
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def migrate(db_path: str) -> None:
    """Add ns_provider and ns_details columns to check_results if missing."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Inspect existing columns
    cursor.execute("PRAGMA table_info(check_results)")
    existing = {row[1] for row in cursor.fetchall()}

    added = []

    if "ns_provider" not in existing:
        cursor.execute("ALTER TABLE check_results ADD COLUMN ns_provider VARCHAR(100)")
        added.append("ns_provider")

    if "ns_details" not in existing:
        cursor.execute("ALTER TABLE check_results ADD COLUMN ns_details TEXT")
        added.append("ns_details")

    conn.commit()
    conn.close()

    if added:
        logger.info("Migration complete: added columns %s to check_results", added)
    else:
        logger.info("Migration skipped: columns already exist")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Default: use Flask app to resolve DB path
        from app import create_app

        app = create_app()
        with app.app_context():
            from app import db as flask_db

            db_url = str(flask_db.engine.url)
            # Extract file path from sqlite:///path
            if "///" in db_url:
                db_path = db_url.split("///", 1)[1]
            else:
                db_path = "instance/watcher.db"
            migrate(db_path)
    else:
        migrate(sys.argv[1])
