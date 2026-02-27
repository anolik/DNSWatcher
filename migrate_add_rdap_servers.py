"""Add rdap_servers column to dns_settings table."""

import sqlite3
import sys

DB = "instance/app.db"


def main() -> None:
    """Add the rdap_servers column if it does not already exist."""
    try:
        conn = sqlite3.connect(DB)
    except sqlite3.OperationalError as exc:
        print(f"Cannot open database {DB}: {exc}")
        sys.exit(1)

    cur = conn.cursor()
    cols = [r[1] for r in cur.execute("PRAGMA table_info(dns_settings)")]

    if "rdap_servers" not in cols:
        cur.execute(
            "ALTER TABLE dns_settings "
            "ADD COLUMN rdap_servers TEXT NOT NULL DEFAULT '[\"https://rdap.org\"]'"
        )
        conn.commit()
        print("Added rdap_servers column to dns_settings")
    else:
        print("Column rdap_servers already exists — skipping")

    conn.close()


if __name__ == "__main__":
    main()
