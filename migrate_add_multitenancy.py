"""
F46 - Idempotent migration: add multi-tenancy (organizations) support.

Creates the organizations table, adds org_id FK columns, creates Default org,
and assigns all existing data to it.

Safe to run multiple times.

Run once after updating models.py:
    python migrate_add_multitenancy.py
"""

from __future__ import annotations

import sqlite3
import sys

from app import create_app


def _table_exists(cursor: sqlite3.Cursor, table: str) -> bool:
    """Check whether a table exists in the database."""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    )
    return cursor.fetchone() is not None


def _column_exists(cursor: sqlite3.Cursor, table: str, column: str) -> bool:
    """Check whether a column exists on a given table."""
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


def _index_exists(cursor: sqlite3.Cursor, index_name: str) -> bool:
    """Check whether an index exists in the database."""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
        (index_name,),
    )
    return cursor.fetchone() is not None


def migrate() -> None:
    """Run the multi-tenancy migration."""
    app = create_app()

    with app.app_context():
        from app import db

        db_uri = str(db.engine.url)
        if "sqlite" not in db_uri:
            print("ERROR: This migration only supports SQLite.", file=sys.stderr)
            sys.exit(1)

        db_path = db_uri.replace("sqlite:///", "")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        changes: list[str] = []

        # 1. Create organizations table
        if not _table_exists(cursor, "organizations"):
            cursor.execute("""
                CREATE TABLE organizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(200) NOT NULL UNIQUE,
                    slug VARCHAR(100) NOT NULL UNIQUE,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_by INTEGER,
                    max_domains INTEGER NOT NULL DEFAULT 100,
                    notes TEXT,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                )
            """)
            changes.append("created table: organizations")

        # 2. Add org_id to tables that need it
        for table in ["users", "domains", "dns_settings", "dmarc_reports"]:
            if _table_exists(cursor, table) and not _column_exists(cursor, table, "org_id"):
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN org_id INTEGER REFERENCES organizations(id)"
                )
                changes.append(f"added column: {table}.org_id")

        # 3. Create "Default" organization if not exists
        cursor.execute("SELECT id FROM organizations WHERE slug = 'default'")
        default_org = cursor.fetchone()
        if default_org is None:
            cursor.execute(
                "INSERT INTO organizations (name, slug, is_active, max_domains, created_at)"
                " VALUES (?, ?, 1, 1000, datetime('now'))",
                ("Default", "default"),
            )
            default_org_id = cursor.lastrowid
            changes.append(f"created Default organization (id={default_org_id})")
        else:
            default_org_id = default_org[0]

        # 4. Assign existing users to Default org (where org_id is NULL)
        cursor.execute("UPDATE users SET org_id = ? WHERE org_id IS NULL", (default_org_id,))
        if cursor.rowcount > 0:
            changes.append(f"assigned {cursor.rowcount} users to Default org")

        # 5. Assign existing domains to Default org
        cursor.execute("UPDATE domains SET org_id = ? WHERE org_id IS NULL", (default_org_id,))
        if cursor.rowcount > 0:
            changes.append(f"assigned {cursor.rowcount} domains to Default org")

        # 6. Assign existing DMARC reports to Default org
        if _table_exists(cursor, "dmarc_reports"):
            cursor.execute(
                "UPDATE dmarc_reports SET org_id = ? WHERE org_id IS NULL",
                (default_org_id,),
            )
            if cursor.rowcount > 0:
                changes.append(f"assigned {cursor.rowcount} dmarc_reports to Default org")

        # 7. DnsSettings: keep existing row as global default (org_id=NULL) - no change needed

        # 8. Add indexes on FK columns
        for table in ["users", "domains", "dns_settings", "dmarc_reports"]:
            idx_name = f"ix_{table}_org_id"
            if (
                _table_exists(cursor, table)
                and _column_exists(cursor, table, "org_id")
                and not _index_exists(cursor, idx_name)
            ):
                cursor.execute(f"CREATE INDEX {idx_name} ON {table}(org_id)")
                changes.append(f"created index: {idx_name}")

        conn.commit()
        conn.close()

        if changes:
            print("Migration complete. Changes applied:")
            for c in changes:
                print(f"  + {c}")
        else:
            print("Migration: no changes needed (all tables/columns already exist).")


if __name__ == "__main__":
    migrate()
