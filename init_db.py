"""
F04 - Database initialisation script for SPF/DMARC/DKIM Watcher.

Creates all tables, seeds the DnsSettings singleton, and enables
SQLite WAL mode for improved concurrent read performance.

Safe to run multiple times (idempotent).

Usage:
    python init_db.py
"""

from __future__ import annotations

import json
import sys

from sqlalchemy import text

from app import create_app, db


def init_database() -> None:
    """Initialise the database within the Flask application context."""
    app = create_app()

    with app.app_context():
        # ------------------------------------------------------------------
        # Create all tables (safe to call on existing databases)
        # ------------------------------------------------------------------
        db.create_all()
        print("[init_db] Tables created / verified.")

        # ------------------------------------------------------------------
        # Enable WAL mode for better SQLite concurrency
        # ------------------------------------------------------------------
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA journal_mode=WAL"))
            mode = result.scalar()
        print(f"[init_db] SQLite journal_mode = {mode}")

        # ------------------------------------------------------------------
        # Seed the DnsSettings singleton (id=1) if it does not yet exist.
        # Uses raw SQL to avoid ORM column mismatch when migrations haven't
        # run yet (the model may have columns the table lacks).
        # ------------------------------------------------------------------
        with db.engine.connect() as conn:
            row = conn.execute(text("SELECT id FROM dns_settings WHERE id = 1")).fetchone()
            if row is None:
                conn.execute(text(
                    "INSERT INTO dns_settings (id, resolvers, timeout_seconds, retries, flap_threshold)"
                    " VALUES (1, :resolvers, 5.0, 3, 2)"
                ), {"resolvers": json.dumps(["8.8.8.8", "1.1.1.1", "9.9.9.9"])})
                conn.commit()
                print("[init_db] DnsSettings singleton seeded (id=1).")
            else:
                print("[init_db] DnsSettings singleton already exists — skipped.")

        print("[init_db] Initialisation complete.")


if __name__ == "__main__":
    try:
        init_database()
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[init_db] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
