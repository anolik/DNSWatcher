"""
Migration: add dmarc_reports table and Graph API columns to dns_settings.

Run once:
    python migrate_add_dmarc_reports.py
"""

from __future__ import annotations

import sys


def main() -> int:
    """Execute the migration inside a Flask application context."""
    try:
        from app import create_app, db
    except ImportError as exc:
        print(f"ERROR: Could not import app: {exc}", file=sys.stderr)
        return 1

    app = create_app()
    with app.app_context():
        conn = db.engine.raw_connection()
        cursor = conn.cursor()

        # ------------------------------------------------------------------
        # Create dmarc_reports table
        # ------------------------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dmarc_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL,
                org_name TEXT NOT NULL,
                policy_domain TEXT NOT NULL,
                begin_date DATETIME NOT NULL,
                end_date DATETIME NOT NULL,
                total_messages INTEGER NOT NULL DEFAULT 0,
                pass_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                records_json TEXT,
                ingested_at DATETIME NOT NULL,
                source TEXT NOT NULL,
                domain_id INTEGER REFERENCES domains(id) ON DELETE SET NULL,
                email_subject TEXT,
                UNIQUE(report_id, org_name)
            )
        """)
        print("Table 'dmarc_reports': created (or already exists).")

        # ------------------------------------------------------------------
        # Add Graph API columns to dns_settings (ALTER TABLE is idempotent
        # via catch on "duplicate column name")
        # ------------------------------------------------------------------
        graph_columns = [
            ("graph_tenant_id", "TEXT"),
            ("graph_client_id", "TEXT"),
            ("graph_client_secret", "TEXT"),
            ("graph_mailbox", "TEXT"),
            ("graph_enabled", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_type in graph_columns:
            try:
                cursor.execute(
                    f"ALTER TABLE dns_settings ADD COLUMN {col_name} {col_type}"
                )
                print(f"Column 'dns_settings.{col_name}': added.")
            except Exception as exc:
                if "duplicate column name" in str(exc).lower():
                    print(f"Column 'dns_settings.{col_name}': already exists, skipped.")
                else:
                    print(f"ERROR adding column '{col_name}': {exc}", file=sys.stderr)
                    conn.rollback()
                    conn.close()
                    return 1

        conn.commit()
        conn.close()
        print("Migration complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
