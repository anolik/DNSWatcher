"""
One-shot migration: assign orphaned DmarcReport rows (org_id=NULL) to the
first organization.  Safe to run multiple times — only touches NULL rows.
"""

from __future__ import annotations

from app import create_app, db
from app.models import DmarcReport, Organization


def migrate() -> None:
    app = create_app()
    with app.app_context():
        org = db.session.execute(
            db.select(Organization).order_by(Organization.id).limit(1)
        ).scalars().first()

        if org is None:
            print("Migration: no organizations found, nothing to do.")
            return

        count = db.session.execute(
            db.update(DmarcReport)
            .where(DmarcReport.org_id.is_(None))
            .values(org_id=org.id)
        ).rowcount
        db.session.commit()

        if count:
            print(f"Migration: assigned {count} orphaned DMARC report(s) to org '{org.name}' (id={org.id}).")
        else:
            print("Migration: no orphaned DMARC reports found.")


if __name__ == "__main__":
    migrate()
