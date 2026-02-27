"""
F03 - SQLAlchemy models for SPF/DMARC/DKIM Watcher.

All eight models are defined here:
  User, Domain, DkimSelector, CheckResult,
  FlapState, ChangeLog, DnsSettings, DnsblCooldown
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


class User(UserMixin, db.Model):
    """Application user with hashed password storage."""

    __tablename__ = "users"

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True, autoincrement=True)
    username: db.Mapped[str] = db.mapped_column(db.String(80), unique=True, nullable=False)
    password_hash: db.Mapped[str] = db.mapped_column(db.String(256), nullable=False)
    created_at: db.Mapped[datetime] = db.mapped_column(
        db.DateTime(timezone=True), default=_utcnow, nullable=False
    )
    is_active: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------
    domains: db.Mapped[list[Domain]] = db.relationship(
        "Domain", foreign_keys="Domain.added_by", back_populates="added_by_user", lazy="dynamic"
    )

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------

    def set_password(self, password: str) -> None:
        """Hash *password* and store the result."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Return True if *password* matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r}>"


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


class Domain(db.Model):
    """A monitored hostname / domain."""

    __tablename__ = "domains"

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True)
    hostname: db.Mapped[str] = db.mapped_column(db.String(255), unique=True, nullable=False)
    added_by: db.Mapped[int | None] = db.mapped_column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )
    added_at: db.Mapped[datetime] = db.mapped_column(
        db.DateTime(timezone=True), default=_utcnow, nullable=False
    )
    is_active: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    notes: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    last_checked_at: db.Mapped[datetime | None] = db.mapped_column(
        db.DateTime(timezone=True), nullable=True
    )
    last_ok_at: db.Mapped[datetime | None] = db.mapped_column(
        db.DateTime(timezone=True), nullable=True
    )
    current_status: db.Mapped[str] = db.mapped_column(
        db.String(20), default="pending", nullable=False
    )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------
    added_by_user: db.Mapped[User | None] = db.relationship(
        "User", foreign_keys=[added_by], back_populates="domains"
    )
    dkim_selectors: db.Mapped[list[DkimSelector]] = db.relationship(
        "DkimSelector",
        back_populates="domain",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    check_results: db.Mapped[list[CheckResult]] = db.relationship(
        "CheckResult",
        back_populates="domain",
        cascade="all, delete-orphan",
        lazy="dynamic",
        order_by="CheckResult.checked_at.desc()",
    )
    flap_states: db.Mapped[list[FlapState]] = db.relationship(
        "FlapState",
        back_populates="domain",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    change_logs: db.Mapped[list[ChangeLog]] = db.relationship(
        "ChangeLog",
        back_populates="domain",
        cascade="all, delete-orphan",
        lazy="dynamic",
        order_by="ChangeLog.detected_at.desc()",
    )

    def __repr__(self) -> str:
        return f"<Domain id={self.id} hostname={self.hostname!r} status={self.current_status!r}>"


# ---------------------------------------------------------------------------
# DkimSelector
# ---------------------------------------------------------------------------


class DkimSelector(db.Model):
    """A DKIM selector associated with a domain."""

    __tablename__ = "dkim_selectors"
    __table_args__ = (db.UniqueConstraint("domain_id", "selector", name="uq_domain_selector"),)

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True)
    domain_id: db.Mapped[int] = db.mapped_column(
        db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False
    )
    selector: db.Mapped[str] = db.mapped_column(db.String(100), nullable=False)
    is_active: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    added_at: db.Mapped[datetime] = db.mapped_column(
        db.DateTime(timezone=True), default=_utcnow, nullable=False
    )

    domain: db.Mapped[Domain] = db.relationship("Domain", back_populates="dkim_selectors")

    def __repr__(self) -> str:
        return f"<DkimSelector id={self.id} domain_id={self.domain_id} selector={self.selector!r}>"


# ---------------------------------------------------------------------------
# CheckResult
# ---------------------------------------------------------------------------


class CheckResult(db.Model):
    """Snapshot result of a single domain check run."""

    __tablename__ = "check_results"
    __table_args__ = (
        db.Index("ix_check_results_domain_checked", "domain_id", "checked_at"),
    )

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True)
    domain_id: db.Mapped[int] = db.mapped_column(
        db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False
    )
    checked_at: db.Mapped[datetime] = db.mapped_column(
        db.DateTime(timezone=True), default=_utcnow, nullable=False
    )
    trigger_type: db.Mapped[str] = db.mapped_column(db.String(20), nullable=False)  # manual/scheduled

    overall_status: db.Mapped[str] = db.mapped_column(db.String(20), nullable=False)

    spf_status: db.Mapped[str | None] = db.mapped_column(db.String(20), nullable=True)
    spf_record: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    spf_details: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    dmarc_status: db.Mapped[str | None] = db.mapped_column(db.String(20), nullable=True)
    dmarc_record: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    dmarc_details: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    dkim_status: db.Mapped[str | None] = db.mapped_column(db.String(20), nullable=True)
    dkim_records: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    reputation_status: db.Mapped[str | None] = db.mapped_column(db.String(20), nullable=True)
    reputation_details: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    mx_records: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON list of {priority, exchange}
    mx_provider: db.Mapped[str | None] = db.mapped_column(db.String(100), nullable=True)
    registrar: db.Mapped[str | None] = db.mapped_column(db.String(200), nullable=True)
    registrar_details: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    mx_geolocation: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON list of server locations
    law25_status: db.Mapped[str | None] = db.mapped_column(db.String(20), nullable=True)

    mta_sts_status: db.Mapped[str | None] = db.mapped_column(db.String(20), nullable=True)
    mta_sts_record: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    mta_sts_details: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    bimi_status: db.Mapped[str | None] = db.mapped_column(db.String(20), nullable=True)
    bimi_record: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    bimi_details: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    tls_status: db.Mapped[str | None] = db.mapped_column(db.String(20), nullable=True)
    tls_details: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    dns_errors: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)  # JSON string

    execution_time_ms: db.Mapped[int | None] = db.mapped_column(db.Integer, nullable=True)

    domain: db.Mapped[Domain] = db.relationship("Domain", back_populates="check_results")

    # ------------------------------------------------------------------
    # JSON helpers
    # ------------------------------------------------------------------

    def get_spf_details(self) -> dict:
        """Deserialise spf_details JSON, returning an empty dict on failure."""
        return _load_json(self.spf_details)

    def get_dmarc_details(self) -> dict:
        """Deserialise dmarc_details JSON, returning an empty dict on failure."""
        return _load_json(self.dmarc_details)

    def get_dkim_records(self) -> list:
        """Deserialise dkim_records JSON, returning an empty list on failure."""
        return _load_json(self.dkim_records, default=[])

    def get_reputation_details(self) -> dict:
        """Deserialise reputation_details JSON, returning an empty dict on failure."""
        return _load_json(self.reputation_details)

    def get_dns_errors(self) -> list:
        """Deserialise dns_errors JSON, returning an empty list on failure."""
        return _load_json(self.dns_errors, default=[])

    def get_mx_records(self) -> list:
        """Deserialise mx_records JSON, returning an empty list on failure."""
        return _load_json(self.mx_records, default=[])

    def get_registrar_details(self) -> dict:
        """Deserialise registrar_details JSON, returning an empty dict on failure."""
        return _load_json(self.registrar_details)

    def get_mx_geolocation(self) -> list:
        """Deserialise mx_geolocation JSON, returning an empty list on failure."""
        return _load_json(self.mx_geolocation, default=[])

    def get_mta_sts_details(self) -> dict:
        """Deserialise mta_sts_details JSON, returning an empty dict on failure."""
        return _load_json(self.mta_sts_details)

    def get_bimi_details(self) -> dict:
        """Deserialise bimi_details JSON, returning an empty dict on failure."""
        return _load_json(self.bimi_details)

    def get_tls_details(self) -> dict:
        """Deserialise tls_details JSON, returning an empty dict on failure."""
        return _load_json(self.tls_details)

    def __repr__(self) -> str:
        return (
            f"<CheckResult id={self.id} domain_id={self.domain_id}"
            f" status={self.overall_status!r} checked_at={self.checked_at}>"
        )


# ---------------------------------------------------------------------------
# FlapState
# ---------------------------------------------------------------------------


class FlapState(db.Model):
    """Tracks consecutive failures per check type to implement anti-flapping."""

    __tablename__ = "flap_states"
    __table_args__ = (
        db.UniqueConstraint("domain_id", "check_type", name="uq_flap_domain_type"),
    )

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True)
    domain_id: db.Mapped[int] = db.mapped_column(
        db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False
    )
    check_type: db.Mapped[str] = db.mapped_column(
        db.String(20), nullable=False
    )  # spf / dmarc / dkim / reputation
    consecutive_failures: db.Mapped[int] = db.mapped_column(db.Integer, default=0, nullable=False)
    last_failure_at: db.Mapped[datetime | None] = db.mapped_column(
        db.DateTime(timezone=True), nullable=True
    )
    last_success_at: db.Mapped[datetime | None] = db.mapped_column(
        db.DateTime(timezone=True), nullable=True
    )

    domain: db.Mapped[Domain] = db.relationship("Domain", back_populates="flap_states")

    def __repr__(self) -> str:
        return (
            f"<FlapState id={self.id} domain_id={self.domain_id}"
            f" check_type={self.check_type!r} failures={self.consecutive_failures}>"
        )


# ---------------------------------------------------------------------------
# ChangeLog
# ---------------------------------------------------------------------------


class ChangeLog(db.Model):
    """Records detected changes in DNS records between consecutive checks."""

    __tablename__ = "change_logs"
    __table_args__ = (
        db.Index("ix_change_logs_domain_detected", "domain_id", "detected_at"),
    )

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True)
    domain_id: db.Mapped[int] = db.mapped_column(
        db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False
    )
    detected_at: db.Mapped[datetime] = db.mapped_column(
        db.DateTime(timezone=True), default=_utcnow, nullable=False
    )
    check_type: db.Mapped[str] = db.mapped_column(db.String(20), nullable=False)
    field_changed: db.Mapped[str] = db.mapped_column(db.String(100), nullable=False)
    old_value: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    new_value: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    severity: db.Mapped[str] = db.mapped_column(
        db.String(20), nullable=False
    )  # info / warning / critical

    domain: db.Mapped[Domain] = db.relationship("Domain", back_populates="change_logs")

    def __repr__(self) -> str:
        return (
            f"<ChangeLog id={self.id} domain_id={self.domain_id}"
            f" check_type={self.check_type!r} field={self.field_changed!r}"
            f" severity={self.severity!r}>"
        )


# ---------------------------------------------------------------------------
# DnsSettings  (singleton row, id=1)
# ---------------------------------------------------------------------------


class DnsSettings(db.Model):
    """Global DNS resolver configuration (singleton - always id=1)."""

    __tablename__ = "dns_settings"

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True, default=1)
    resolvers: db.Mapped[str] = db.mapped_column(
        db.Text,
        nullable=False,
        default=json.dumps(["8.8.8.8", "1.1.1.1", "9.9.9.9"]),
    )
    timeout_seconds: db.Mapped[float] = db.mapped_column(db.Float, default=5.0, nullable=False)
    retries: db.Mapped[int] = db.mapped_column(db.Integer, default=3, nullable=False)
    flap_threshold: db.Mapped[int] = db.mapped_column(db.Integer, default=2, nullable=False)
    display_timezone: db.Mapped[str] = db.mapped_column(
        db.String(50), default="UTC", nullable=False
    )
    check_concurrency: db.Mapped[int] = db.mapped_column(
        db.Integer, default=5, nullable=False
    )
    managed_domains: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    updated_at: db.Mapped[datetime | None] = db.mapped_column(
        db.DateTime(timezone=True), nullable=True
    )
    updated_by: db.Mapped[int | None] = db.mapped_column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )

    graph_tenant_id: db.Mapped[str | None] = db.mapped_column(db.String(200), nullable=True)
    graph_client_id: db.Mapped[str | None] = db.mapped_column(db.String(200), nullable=True)
    graph_client_secret: db.Mapped[str | None] = db.mapped_column(db.String(500), nullable=True)
    graph_mailbox: db.Mapped[str | None] = db.mapped_column(db.String(200), nullable=True)
    graph_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=False, nullable=False)

    # ------------------------------------------------------------------
    # Feature toggles (all default to True / enabled)
    # ------------------------------------------------------------------
    check_spf_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_dmarc_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_dkim_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_mx_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_reputation_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_registrar_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_geolocation_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_mta_sts_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_bimi_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)
    check_tls_enabled: db.Mapped[bool] = db.mapped_column(db.Boolean, default=True, nullable=False)

    # ------------------------------------------------------------------
    # Data retention
    # ------------------------------------------------------------------
    data_retention_days: db.Mapped[int] = db.mapped_column(
        db.Integer, default=90, nullable=False
    )

    updated_by_user: db.Mapped[User | None] = db.relationship(
        "User", foreign_keys=[updated_by], lazy="joined"
    )

    # ------------------------------------------------------------------
    # Resolver list helpers
    # ------------------------------------------------------------------

    def get_resolvers(self) -> list[str]:
        """Return the resolver list as a Python list."""
        return _load_json(self.resolvers, default=["8.8.8.8", "1.1.1.1"])

    def set_resolvers(self, resolver_list: list[str]) -> None:
        """Serialise and store *resolver_list*."""
        self.resolvers = json.dumps(resolver_list)

    def get_managed_domains(self) -> set[str]:
        """Return the set of managed hostnames (lowercased, whitespace-stripped)."""
        if not self.managed_domains:
            return set()
        return {line.strip().lower() for line in self.managed_domains.splitlines() if line.strip()}

    def __repr__(self) -> str:
        return (
            f"<DnsSettings id={self.id} timeout={self.timeout_seconds}"
            f" retries={self.retries} flap_threshold={self.flap_threshold}>"
        )


# ---------------------------------------------------------------------------
# DnsblCooldown
# ---------------------------------------------------------------------------


class DnsblCooldown(db.Model):
    """Tracks query-refused responses per DNSBL provider.

    After ``COOLDOWN_THRESHOLD`` consecutive refusals the provider is put on
    cooldown for ``COOLDOWN_HOURS`` hours to avoid flooding it with requests
    that will be denied anyway.
    """

    __tablename__ = "dnsbl_cooldowns"

    COOLDOWN_THRESHOLD: int = 3
    COOLDOWN_HOURS: int = 24

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True)
    dnsbl: db.Mapped[str] = db.mapped_column(db.String(200), unique=True, nullable=False)
    consecutive_refusals: db.Mapped[int] = db.mapped_column(db.Integer, default=0, nullable=False)
    last_refused_at: db.Mapped[datetime | None] = db.mapped_column(
        db.DateTime(timezone=True), nullable=True
    )
    cooldown_until: db.Mapped[datetime | None] = db.mapped_column(
        db.DateTime(timezone=True), nullable=True
    )

    def is_on_cooldown(self) -> bool:
        """Return True if this provider should be skipped right now."""
        if self.cooldown_until is None:
            return False
        # SQLite strips timezone info; compare naive-to-naive (UTC assumed)
        now = datetime.utcnow()
        deadline = self.cooldown_until.replace(tzinfo=None) if self.cooldown_until.tzinfo else self.cooldown_until
        return now < deadline

    def __repr__(self) -> str:
        return (
            f"<DnsblCooldown dnsbl={self.dnsbl!r}"
            f" refusals={self.consecutive_refusals}"
            f" cooldown_until={self.cooldown_until}>"
        )


# ---------------------------------------------------------------------------
# DmarcReport
# ---------------------------------------------------------------------------


class DmarcReport(db.Model):
    """DMARC aggregate report (RFC 7489)."""

    __tablename__ = "dmarc_reports"
    __table_args__ = (
        db.UniqueConstraint("report_id", "org_name", name="uq_dmarc_report_id_org"),
    )

    id: db.Mapped[int] = db.mapped_column(db.Integer, primary_key=True)
    report_id: db.Mapped[str] = db.mapped_column(db.String(200), nullable=False)
    org_name: db.Mapped[str] = db.mapped_column(db.String(200), nullable=False)
    policy_domain: db.Mapped[str] = db.mapped_column(db.String(255), nullable=False)
    begin_date: db.Mapped[datetime] = db.mapped_column(db.DateTime(timezone=True), nullable=False)
    end_date: db.Mapped[datetime] = db.mapped_column(db.DateTime(timezone=True), nullable=False)
    total_messages: db.Mapped[int] = db.mapped_column(db.Integer, default=0, nullable=False)
    pass_count: db.Mapped[int] = db.mapped_column(db.Integer, default=0, nullable=False)
    fail_count: db.Mapped[int] = db.mapped_column(db.Integer, default=0, nullable=False)
    records_json: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)
    ingested_at: db.Mapped[datetime] = db.mapped_column(
        db.DateTime(timezone=True), default=_utcnow, nullable=False
    )
    source: db.Mapped[str] = db.mapped_column(db.String(20), nullable=False)  # 'manual' | 'auto'
    domain_id: db.Mapped[int | None] = db.mapped_column(
        db.Integer, db.ForeignKey("domains.id", ondelete="SET NULL"), nullable=True
    )
    email_subject: db.Mapped[str | None] = db.mapped_column(db.String(500), nullable=True)
    policy_published_json: db.Mapped[str | None] = db.mapped_column(db.Text, nullable=True)

    domain: db.Mapped[Domain | None] = db.relationship("Domain")

    def get_records(self) -> list:
        """Deserialise records_json, returning an empty list on failure."""
        return _load_json(self.records_json, default=[])

    def get_policy_published(self) -> dict:
        """Deserialise policy_published_json."""
        return _load_json(self.policy_published_json)

    def __repr__(self) -> str:
        return (
            f"<DmarcReport id={self.id} report_id={self.report_id!r}"
            f" org={self.org_name!r} domain={self.policy_domain!r}>"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_json(value: str | None, *, default: object = None) -> object:
    """Safely deserialise a JSON string, returning *default* on any error."""
    if default is None:
        default = {}
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default
