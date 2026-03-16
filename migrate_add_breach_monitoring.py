"""Migration: add breach monitoring tables and columns.

F39 - Breach Data Models: creates breach_results, breach_entries tables
and adds HIBP settings to dns_settings + breach fields to domains.
"""

from __future__ import annotations

import logging
import sqlite3
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def migrate(db_path: str) -> None:
    """Add breach monitoring tables and columns."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    added = []

    # ---- breach_results table ----
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='breach_results'"
    )
    if not cursor.fetchone():
        cursor.execute("""
            CREATE TABLE breach_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                checked_at TIMESTAMP NOT NULL,
                total_breaches INTEGER NOT NULL DEFAULT 0,
                total_emails INTEGER NOT NULL DEFAULT 0,
                breaches_json TEXT,
                emails_json TEXT,
                unacknowledged_count INTEGER NOT NULL DEFAULT 0,
                error TEXT
            )
        """)
        cursor.execute(
            "CREATE INDEX ix_breach_results_domain_checked ON breach_results(domain_id, checked_at)"
        )
        added.append("breach_results table")

    # ---- breach_entries table ----
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='breach_entries'"
    )
    if not cursor.fetchone():
        cursor.execute("""
            CREATE TABLE breach_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                breach_name VARCHAR(200) NOT NULL,
                breach_date VARCHAR(20),
                data_classes TEXT,
                pwn_count INTEGER NOT NULL DEFAULT 0,
                description TEXT,
                emails_json TEXT,
                first_seen_at TIMESTAMP NOT NULL,
                acknowledged BOOLEAN NOT NULL DEFAULT 0,
                acknowledged_by INTEGER REFERENCES users(id),
                acknowledged_at TIMESTAMP,
                UNIQUE(domain_id, breach_name)
            )
        """)
        cursor.execute(
            "CREATE INDEX ix_breach_entries_domain ON breach_entries(domain_id)"
        )
        added.append("breach_entries table")

    # ---- domains columns ----
    cursor.execute("PRAGMA table_info(domains)")
    domain_cols = {row[1] for row in cursor.fetchall()}

    if "breach_status" not in domain_cols:
        cursor.execute("ALTER TABLE domains ADD COLUMN breach_status VARCHAR(20) DEFAULT 'pending' NOT NULL")
        added.append("domains.breach_status")

    if "unacknowledged_breaches" not in domain_cols:
        cursor.execute("ALTER TABLE domains ADD COLUMN unacknowledged_breaches INTEGER DEFAULT 0 NOT NULL")
        added.append("domains.unacknowledged_breaches")

    # ---- dns_settings columns ----
    cursor.execute("PRAGMA table_info(dns_settings)")
    settings_cols = {row[1] for row in cursor.fetchall()}

    if "hibp_api_key" not in settings_cols:
        cursor.execute("ALTER TABLE dns_settings ADD COLUMN hibp_api_key VARCHAR(200)")
        added.append("dns_settings.hibp_api_key")

    if "check_breach_enabled" not in settings_cols:
        cursor.execute("ALTER TABLE dns_settings ADD COLUMN check_breach_enabled BOOLEAN DEFAULT 0 NOT NULL")
        added.append("dns_settings.check_breach_enabled")

    if "breach_check_frequency_days" not in settings_cols:
        cursor.execute("ALTER TABLE dns_settings ADD COLUMN breach_check_frequency_days INTEGER DEFAULT 7 NOT NULL")
        added.append("dns_settings.breach_check_frequency_days")

    if "breach_last_full_scan_at" not in settings_cols:
        cursor.execute("ALTER TABLE dns_settings ADD COLUMN breach_last_full_scan_at TIMESTAMP")
        added.append("dns_settings.breach_last_full_scan_at")

    conn.commit()
    conn.close()

    if added:
        logger.info("Migration complete: %s", ", ".join(added))
    else:
        logger.info("Migration skipped: all tables/columns already exist")


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
