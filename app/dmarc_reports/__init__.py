"""DMARC aggregate report ingestion blueprint."""

from flask import Blueprint

bp = Blueprint("dmarc_reports", __name__, url_prefix="/dmarc-reports")

from app.dmarc_reports import routes  # noqa: E402, F401
