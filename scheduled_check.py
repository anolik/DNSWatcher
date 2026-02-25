"""
F31 - Standalone scheduled check script for SPF/DMARC/DKIM Watcher.

Designed to be run as a PythonAnywhere daily scheduled task, or via cron on
any UNIX system.  Can also be invoked manually for ad-hoc checks.

PYTHONANYWHERE DEPLOYMENT – SCHEDULED TASK SETUP
=================================================

PREREQUISITE: Complete the full deployment described in wsgi.py first.

PLAN REQUIREMENT:
  The Hacker plan ($5/month) or higher is REQUIRED.
  The free plan blocks outbound DNS queries (UDP port 53).  All checks will
  fail with timeout errors on the free plan.

ADD THE SCHEDULED TASK:
  1. Log in to PythonAnywhere and click the "Tasks" tab.
  2. Click "Add a new scheduled task".
  3. Enter the following command (substitute your username and project path):

       /home/<username>/.virtualenvs/watcher/bin/python \
       /home/<username>/watcher/scheduled_check.py

     Always use the full path to the virtualenv Python interpreter so that
     all installed packages (dnspython, checkdmarc, etc.) are available.

  4. Set the schedule: "Daily" at your preferred hour (e.g. 06:00 UTC).
     Off-peak hours reduce risk of DNS server rate limiting.

  5. Click "Create".

ENVIRONMENT VARIABLES FOR SCHEDULED TASKS:
  PythonAnywhere scheduled tasks do not inherit web app environment variables.
  You must either:
    a) Export them in the command:
         SECRET_KEY=xxx DATABASE_URL=sqlite:////home/<user>/watcher/instance/watcher.db \
         /home/<user>/.virtualenvs/watcher/bin/python /home/<user>/watcher/scheduled_check.py
    b) Or place them in a .env file and source it:
         source /home/<user>/watcher/.env && \
         /home/<user>/.virtualenvs/watcher/bin/python /home/<user>/watcher/scheduled_check.py

SQLITE PATH ON PYTHONANYWHERE:
  Use an absolute path for the database.  The DATABASE_URL must use four
  slashes for an absolute filesystem path:
    sqlite:////home/<username>/watcher/instance/watcher.db
  (three slashes = protocol, one slash = filesystem root)

LOGS:
  PythonAnywhere captures stdout and stderr automatically.
  Review output in the Tasks tab after each scheduled run.

MANUAL TEST RUN:
  Before relying on the scheduler, open a Bash console and test manually:
    workon watcher
    cd /home/<username>/watcher
    python scheduled_check.py --verbose

SINGLE DOMAIN CHECK:
  python scheduled_check.py --domain example.com --verbose

USAGE
=====
  # Check all active domains (daily cron)
  python scheduled_check.py

  # Check a single domain by hostname
  python scheduled_check.py --domain example.com

  # Enable debug-level logging
  python scheduled_check.py --verbose

  # Combine flags
  python scheduled_check.py --domain example.com --verbose

EXIT CODES
==========
  0 - Success (all checks completed, even if individual checks reported issues)
  1 - Fatal error (e.g. unable to create app context, database unreachable)
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Argument parsing (done before app import so --help works without Flask)
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run SPF/DMARC/DKIM checks for monitored domains.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--domain",
        metavar="HOSTNAME",
        default=None,
        help="Check a single domain instead of all active domains.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable DEBUG-level logging output.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Logging setup (before Flask to capture early errors)
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool) -> logging.Logger:
    """Configure root logger for the scheduled script.

    Args:
        verbose: If True, set level to DEBUG; otherwise INFO.

    Returns:
        A logger instance named after this module.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        stream=sys.stdout,
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    return logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Execute the scheduled domain check run.

    Returns:
        Integer exit code: 0 for success, 1 for fatal error.
    """
    args = _parse_args()
    logger = _configure_logging(args.verbose)

    run_start = datetime.now(timezone.utc)
    logger.info("=== scheduled_check.py started at %s ===", run_start.isoformat())

    # ------------------------------------------------------------------
    # Bootstrap Flask application context
    # ------------------------------------------------------------------
    try:
        from app import create_app, db

        flask_app = create_app()
    except Exception:
        logger.exception("FATAL: Failed to create Flask application.")
        return 1

    # All database and model access must happen inside an app context.
    with flask_app.app_context():
        try:
            from app.checker.engine import run_all_checks, run_domain_check
            from app.models import Domain
        except Exception:
            logger.exception("FATAL: Failed to import checker engine or models.")
            return 1

        # ------------------------------------------------------------------
        # Single-domain mode: --domain <hostname>
        # ------------------------------------------------------------------
        if args.domain:
            hostname = args.domain.strip().lower()
            logger.info("Single-domain mode: checking '%s'", hostname)

            domain: Domain | None = (
                Domain.query.filter_by(hostname=hostname, is_active=True).first()
            )
            if domain is None:
                logger.error(
                    "Domain '%s' not found or not active. "
                    "Use the web interface to add it first.",
                    hostname,
                )
                return 1

            t0 = time.monotonic()
            try:
                result = run_domain_check(domain, trigger_type="scheduled")
                elapsed = time.monotonic() - t0
                logger.info(
                    "DONE  %-50s  overall=%-8s  spf=%-8s  dmarc=%-8s  dkim=%-8s  rep=%-8s  elapsed=%.1fs",
                    hostname,
                    result.overall_status,
                    result.spf_status or "n/a",
                    result.dmarc_status or "n/a",
                    result.dkim_status or "n/a",
                    result.reputation_status or "n/a",
                    elapsed,
                )
            except Exception:
                logger.exception("Check failed for domain '%s'.", hostname)
                return 1

        # ------------------------------------------------------------------
        # All-domains mode (default) — uses run_all_checks() which handles
        # concurrency internally based on the DnsSettings.check_concurrency
        # setting.
        # ------------------------------------------------------------------
        else:
            active_domains = Domain.query.filter_by(is_active=True).all()
            total = len(active_domains)
            logger.info("All-domains mode: %d active domain(s) to check.", total)

            if total == 0:
                logger.warning("No active domains found. Add domains via the web interface.")
                _log_summary(logger, run_start, checked=0, failed=0)
                return 0

            results = run_all_checks(trigger_type="scheduled")

            for result in results:
                logger.info(
                    "DONE  %-50s  overall=%-8s  spf=%-8s  dmarc=%-8s  dkim=%-8s  rep=%-8s  elapsed=%dms",
                    result.domain.hostname if result.domain else f"id={result.domain_id}",
                    result.overall_status,
                    result.spf_status or "n/a",
                    result.dmarc_status or "n/a",
                    result.dkim_status or "n/a",
                    result.reputation_status or "n/a",
                    result.execution_time_ms or 0,
                )

            checked = len(results)
            failed = total - checked
            _log_summary(logger, run_start, checked=checked, failed=failed)

            # ------------------------------------------------------------------
            # DMARC auto-fetch via Microsoft Graph API (if configured)
            # ------------------------------------------------------------------
            try:
                from app.models import DnsSettings
                dns_settings = db.session.get(DnsSettings, 1)
                if dns_settings and getattr(dns_settings, "graph_enabled", False):
                    from app.dmarc_reports.routes import run_graph_fetch
                    imported, dupes = run_graph_fetch(flask_app)
                    logger.info(
                        "DMARC auto-fetch: %d imported, %d duplicates skipped",
                        imported,
                        dupes,
                    )
            except Exception:
                logger.exception("DMARC auto-fetch failed.")

    return 0


def _log_summary(
    logger: logging.Logger,
    run_start: datetime,
    checked: int,
    failed: int,
) -> None:
    """Emit a structured summary log line at the end of a run.

    Args:
        logger: Logger instance to write to.
        run_start: UTC datetime when the run began.
        checked: Number of domains successfully checked.
        failed: Number of domains where the check raised an exception.
    """
    run_end = datetime.now(timezone.utc)
    elapsed_total = (run_end - run_start).total_seconds()
    logger.info(
        "=== Run complete: checked=%d  failed=%d  total_elapsed=%.1fs  ended=%s ===",
        checked,
        failed,
        elapsed_total,
        run_end.isoformat(),
    )


# ---------------------------------------------------------------------------
# Script entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
