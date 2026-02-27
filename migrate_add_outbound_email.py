"""
Idempotent migration: add outbound email columns to the dns_settings table.

Adds: outbound_tenant_id, outbound_client_id, outbound_client_secret,
      outbound_mailbox, outbound_enabled.

Safe to run multiple times.
"""

from __future__ import annotations

import sqlite3
import sys

from app import create_app


def _column_exists(cursor: sqlite3.Cursor, table: str, column: str) -> bool:
    """Check if a column exists in a SQLite table."""
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


def _add_column_if_missing(
    cursor: sqlite3.Cursor,
    table: str,
    column: str,
    col_type: str,
    default: str | None = None,
) -> bool:
    """Add a column to a table if it doesn't already exist. Returns True if added."""
    if _column_exists(cursor, table, column):
        return False
    default_clause = f" DEFAULT {default}" if default is not None else ""
    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}{default_clause}")
    return True


def migrate() -> None:
    """Run the migration inside the Flask app context."""
    app = create_app()

    with app.app_context():
        from app import db
        db_uri = str(db.engine.url)
        # Extract SQLite file path from URI
        if "sqlite" not in db_uri:
            print("ERROR: This migration only supports SQLite.", file=sys.stderr)
            sys.exit(1)

        db_path = db_uri.replace("sqlite:///", "")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        changes = []

        # Outbound email columns on dns_settings
        if _add_column_if_missing(cursor, "dns_settings", "outbound_tenant_id", "VARCHAR(200)"):
            changes.append("dns_settings.outbound_tenant_id")
        if _add_column_if_missing(cursor, "dns_settings", "outbound_client_id", "VARCHAR(200)"):
            changes.append("dns_settings.outbound_client_id")
        if _add_column_if_missing(cursor, "dns_settings", "outbound_client_secret", "VARCHAR(500)"):
            changes.append("dns_settings.outbound_client_secret")
        if _add_column_if_missing(cursor, "dns_settings", "outbound_mailbox", "VARCHAR(200)"):
            changes.append("dns_settings.outbound_mailbox")
        if _add_column_if_missing(cursor, "dns_settings", "outbound_enabled", "BOOLEAN", "0"):
            changes.append("dns_settings.outbound_enabled")

        conn.commit()
        conn.close()

        if changes:
            print("Migration complete. Changes applied:")
            for c in changes:
                print(f"  + {c}")
        else:
            print("Migration: no changes needed (all columns already exist).")


if __name__ == "__main__":
    migrate()
