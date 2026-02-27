"""
F38 - Idempotent migration: add new columns to the users table.

Adds: email, full_name, role, language, last_login_at, updated_at, org_id.
Existing users get role='superadmin' to preserve full access.

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

        # Users table new columns
        if _add_column_if_missing(cursor, "users", "email", "VARCHAR(255)"):
            changes.append("users.email")
        if _add_column_if_missing(cursor, "users", "full_name", "VARCHAR(200)"):
            changes.append("users.full_name")
        if _add_column_if_missing(cursor, "users", "role", "VARCHAR(20)", "'viewer'"):
            changes.append("users.role")
            # Set existing users to superadmin to preserve full access
            cursor.execute("UPDATE users SET role = 'superadmin' WHERE role = 'viewer' OR role IS NULL")
            changes.append("  -> existing users set to role='superadmin'")
        if _add_column_if_missing(cursor, "users", "language", "VARCHAR(5)", "'fr'"):
            changes.append("users.language")
        if _add_column_if_missing(cursor, "users", "last_login_at", "DATETIME"):
            changes.append("users.last_login_at")
        if _add_column_if_missing(cursor, "users", "updated_at", "DATETIME"):
            changes.append("users.updated_at")
        if _add_column_if_missing(cursor, "users", "org_id", "INTEGER"):
            changes.append("users.org_id")

        # Create unique index on email if not exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='ix_users_email'")
        if not cursor.fetchone():
            try:
                cursor.execute("CREATE UNIQUE INDEX ix_users_email ON users(email)")
                changes.append("index: ix_users_email")
            except sqlite3.OperationalError:
                # May fail if duplicate NULLs, which is fine for SQLite
                pass

        conn.commit()
        conn.close()

        if changes:
            print(f"Migration complete. Changes applied:")
            for c in changes:
                print(f"  + {c}")
        else:
            print("Migration: no changes needed (all columns already exist).")


if __name__ == "__main__":
    migrate()
