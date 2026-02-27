"""Add rdap_servers column to dns_settings table.

Run once after updating models.py:
    python migrate_add_rdap_servers.py
"""

from __future__ import annotations

import sys
import traceback

print("migrate_add_rdap_servers: starting", flush=True)

try:
    from sqlalchemy import text
    from app import create_app, db
except Exception as exc:
    print(f"migrate_add_rdap_servers: import error: {exc}", flush=True)
    traceback.print_exc()
    sys.exit(0)  # Don't block startup


def migrate() -> None:
    """Add rdap_servers column to dns_settings if it does not exist."""
    print("migrate_add_rdap_servers: creating app", flush=True)
    app = create_app()
    with app.app_context():
        try:
            print("migrate_add_rdap_servers: executing ALTER TABLE", flush=True)
            db.session.execute(
                text(
                    "ALTER TABLE dns_settings "
                    "ADD COLUMN rdap_servers TEXT DEFAULT '[\"https://rdap.org\"]'"
                )
            )
            db.session.commit()
            print("migrate_add_rdap_servers: Column 'rdap_servers' added to dns_settings.", flush=True)
        except Exception as exc:
            db.session.rollback()
            if "duplicate column" in str(exc).lower():
                print("migrate_add_rdap_servers: Column 'rdap_servers' already exists — skipping.", flush=True)
            else:
                print(f"migrate_add_rdap_servers: unexpected error: {exc}", flush=True)
                traceback.print_exc()


if __name__ == "__main__":
    try:
        migrate()
    except Exception as exc:
        print(f"migrate_add_rdap_servers: fatal error: {exc}", flush=True)
        traceback.print_exc()
    print("migrate_add_rdap_servers: done", flush=True)
