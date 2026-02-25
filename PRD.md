# SPF/DMARC/DKIM Watcher - PRD

## Overview

Outil de surveillance des configurations email (SPF, DMARC, DKIM) pour une liste de domaines. Interface web simple, protegee par mot de passe, qui valide quotidiennement l'etat des enregistrements DNS et la reputation anti-spam. MVP / preuve de concept deployable sur PythonAnywhere.

## Problem Statement

Les configurations SPF, DMARC et DKIM changent silencieusement, expirent ou sont mal configurees sans que les administrateurs ne le remarquent. Les politiques faibles (p=none, ~all) laissent les domaines vulnerables au spoofing. Il n'existe pas d'outil simple, self-hosted et gratuit pour surveiller ces configurations de facon continue avec historique et alertes.

## Target Users

- **Administrateurs systeme** gerant plusieurs domaines email
- **Equipes securite** validant la posture email de l'organisation
- **MSP / consultants** surveillant les domaines de leurs clients

---

## Agent Assignments

| Phase | Agent | Deliverable |
|-------|-------|-------------|
| 1. Foundation | **backend-architect** | App skeleton, models, auth, config, DB init |
| 2. DNS Engine | **python-expert** | All DNS checking logic, resolver, anti-flap |
| 3. Web Interface | **fullstack-developer** | Routes, templates, forms, dashboard UI |
| 4. History & Analytics | **frontend-architect** | History, diffs, charts, API endpoints, observability |
| 5. Integration & QA | **quality-engineer** | Scheduled task, security hardening, tests, deployment |

### Execution Order

```
        Agent 1 (Foundation)
               |
      +--------+--------+
      |                 |
 Agent 2 (DNS)    Agent 3 (Web)     <-- parallel
      |                 |
      +--------+--------+
               |
        Agent 4 (History)
               |
        Agent 5 (QA & Ops)
```

### Model Optimization Strategy

Each feature has an assigned model based on task complexity to minimize token cost:

| Model | When to use | Features | Token cost |
|-------|-------------|----------|------------|
| **Opus** | RFC compliance, crypto, security review, complex state machines, DNS parsing | 7 | Highest |
| **Sonnet** | Standard CRUD, templates, moderate logic, orchestration, standard tests | 18 | Medium |
| **Haiku** | Boilerplate config, trivial scripts, simple forms, simple CRUD, docs | 12 | Lowest |

**Per-feature model map:**

| Feature | Model | Rationale |
|---------|-------|-----------|
| F01 App Factory | Sonnet | Standard Flask pattern |
| F02 Config | Haiku | Simple env var config |
| F03 Models | Sonnet | 7 models with relationships |
| F04 DB Init | Haiku | Short idempotent script |
| F05 Auth | Sonnet | Standard Flask-Login pattern |
| F06 Admin Script | Haiku | Simple CLI tool |
| F07 Base Template | Sonnet | Bootstrap layout + nav logic |
| F08 WSGI | Haiku | Trivial 3-line file |
| F09 DNS Resolver | **Opus** | Complex retry/failover/error classification |
| F10 SPF Validation | **Opus** | RFC 7208 compliance, mechanism parsing |
| F11 DMARC Validation | **Opus** | Multi-field validation, policy analysis |
| F12 DKIM Validation | **Opus** | Cryptographic key analysis |
| F13 Reputation | Sonnet | Straightforward DNSBL queries |
| F14 Check Engine | Sonnet | Orchestration, moderate logic |
| F15 Anti-Flapping | Sonnet | State machine, moderate complexity |
| F16 Dashboard | Sonnet | Table + badges, CRUD actions |
| F17 Add Domain | Haiku | Simple form + validation |
| F18 Delete Domain | Haiku | Simple POST action |
| F19 Manual Check | Haiku | Button triggers existing engine |
| F20 Domain Detail | Sonnet | Multi-section display page |
| F21 DKIM Selectors | Haiku | Simple CRUD list |
| F22 Settings Page | Haiku | Simple form + validation |
| F23 Email Import | Sonnet | File parsing, regex, dedup logic |
| F24 Change Detection | **Opus** | Complex diff logic, severity classification |
| F25 History Page | Sonnet | Template + Chart.js integration |
| F26 Changes Page | Sonnet | Filtered list with pagination |
| F27 JSON API | Sonnet | Standard REST endpoints |
| F28 Chart.js | Sonnet | Frontend JS chart config |
| F29 AJAX Refresh | Haiku | Simple polling script |
| F30 Health Page | Sonnet | Metrics aggregation queries |
| F31 Scheduled Script | Sonnet | Error handling + app context |
| F32 Logging | Haiku | Standard Python logging setup |
| F33 Security Hardening | **Opus** | Security audit, OWASP review |
| F34 Tests - Checker | **Opus** | Complex DNS mocking, edge cases |
| F35 Tests - Routes | Sonnet | Standard Flask test client |
| F36 Tests - Diff/Ingest | Sonnet | Moderate test scenarios |
| F37 Deployment Guide | Haiku | Documentation text |

---

## Technical Requirements

### Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | >= 3.10 |
| Framework | Flask | >= 3.1 |
| ORM | Flask-SQLAlchemy | >= 3.1 |
| Auth | Flask-Login + Werkzeug | >= 0.6 |
| CSRF | Flask-WTF | >= 1.2 |
| Database | SQLite3 | (built-in) |
| DNS | dnspython | >= 2.7 |
| SPF/DMARC | checkdmarc | >= 5.14 |
| DKIM | dnspython + cryptography | >= 42.0 |
| Reputation | pydnsbl | >= 1.1 |
| Frontend | Bootstrap 5 + Chart.js | CDN |
| Hosting | PythonAnywhere | Hacker plan ($5/mo) |

### requirements.txt

```
Flask>=3.1.0
Flask-SQLAlchemy>=3.1.0
Flask-Login>=0.6.3
Flask-WTF>=1.2.0
dnspython>=2.7.0
checkdmarc>=5.14.0
cryptography>=42.0.0
pydnsbl>=1.1.7
Werkzeug>=3.1.0
bcrypt>=4.0.0
```

### Constraints

- **PythonAnywhere**: Paid Hacker plan required for unrestricted outbound DNS (UDP/53)
- **SQLite3**: Single-writer; WAL mode for concurrent read during scheduled writes
- **No WebSockets**: PythonAnywhere does not support them; use AJAX polling
- **Scheduled tasks**: PythonAnywhere cron (standalone script), not Celery

---

## Directory Structure

```
spf-dmarc-dkim-watcher/
|
+-- app/
|   +-- __init__.py              # Flask app factory
|   +-- config.py                # Configuration
|   +-- models.py                # All SQLAlchemy models (7 tables)
|   |
|   +-- auth/
|   |   +-- __init__.py
|   |   +-- routes.py            # Login/logout
|   |   +-- forms.py             # LoginForm
|   |
|   +-- dashboard/
|   |   +-- __init__.py
|   |   +-- routes.py            # Domain CRUD, manual check
|   |   +-- forms.py             # AddDomainForm, ImportFileForm
|   |
|   +-- checker/
|   |   +-- __init__.py
|   |   +-- resolver.py          # Robust DNS resolver wrapper
|   |   +-- spf.py               # SPF validation
|   |   +-- dmarc.py             # DMARC validation
|   |   +-- dkim.py              # DKIM key validation
|   |   +-- reputation.py        # DNSBL lookups
|   |   +-- engine.py            # Orchestrate all checks
|   |   +-- anti_flap.py         # Consecutive failure tracking
|   |
|   +-- history/
|   |   +-- __init__.py
|   |   +-- routes.py            # History views, change log
|   |   +-- diff_engine.py       # Detect changes between checks
|   |
|   +-- settings/
|   |   +-- __init__.py
|   |   +-- routes.py            # DNS config view
|   |   +-- forms.py             # SettingsForm
|   |
|   +-- ingest/
|   |   +-- __init__.py
|   |   +-- routes.py            # File upload
|   |   +-- parser.py            # Extract domains from email list
|   |
|   +-- api/
|   |   +-- __init__.py
|   |   +-- routes.py            # JSON endpoints for charts/AJAX
|   |
|   +-- templates/
|   |   +-- base.html
|   |   +-- login.html
|   |   +-- dashboard.html
|   |   +-- domain_detail.html
|   |   +-- domain_history.html
|   |   +-- changes.html
|   |   +-- settings.html
|   |   +-- import.html
|   |   +-- health.html
|   |
|   +-- static/
|       +-- css/style.css
|       +-- js/charts.js
|       +-- js/dashboard.js
|
+-- tests/
|   +-- __init__.py
|   +-- test_spf.py
|   +-- test_dmarc.py
|   +-- test_dkim.py
|   +-- test_resolver.py
|   +-- test_anti_flap.py
|   +-- test_diff_engine.py
|   +-- test_ingest.py
|   +-- test_routes.py
|
+-- scheduled_check.py           # PythonAnywhere daily task
+-- create_admin.py              # CLI: create first admin
+-- init_db.py                   # CLI: create tables
+-- wsgi.py                      # WSGI entry point
+-- requirements.txt
+-- CLAUDE.md
+-- PRD.md
```

---

## Database Schema

### Table: `users`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| username | TEXT | UNIQUE NOT NULL |
| password_hash | TEXT | NOT NULL |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| is_active | BOOLEAN | DEFAULT 1 |

### Table: `domains`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| hostname | TEXT | UNIQUE NOT NULL |
| added_by | INTEGER | FK -> users.id |
| added_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| is_active | BOOLEAN | DEFAULT 1 |
| notes | TEXT | NULLABLE |
| last_checked_at | TIMESTAMP | NULLABLE |
| last_ok_at | TIMESTAMP | NULLABLE |
| current_status | TEXT | DEFAULT 'pending' |

### Table: `dkim_selectors`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| domain_id | INTEGER | FK -> domains.id CASCADE |
| selector | TEXT | NOT NULL |
| is_active | BOOLEAN | DEFAULT 1 |
| added_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| | | UNIQUE(domain_id, selector) |

Default selectors on domain creation: `default`, `google`, `selector1`, `selector2`, `k1`, `dkim`, `mail`, `s1`, `s2`, `protonmail`.

### Table: `check_results`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| domain_id | INTEGER | FK -> domains.id CASCADE |
| checked_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| trigger_type | TEXT | NOT NULL ('manual'/'scheduled') |
| overall_status | TEXT | NOT NULL (ok/warning/critical/error) |
| spf_status | TEXT | |
| spf_record | TEXT | NULLABLE |
| spf_details | TEXT | NULLABLE (JSON) |
| dmarc_status | TEXT | |
| dmarc_record | TEXT | NULLABLE |
| dmarc_details | TEXT | NULLABLE (JSON) |
| dkim_status | TEXT | |
| dkim_records | TEXT | NULLABLE (JSON) |
| reputation_status | TEXT | |
| reputation_details | TEXT | NULLABLE (JSON) |
| dns_errors | TEXT | NULLABLE (JSON) |
| execution_time_ms | INTEGER | |

Index: `(domain_id, checked_at DESC)`

### Table: `flap_state`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| domain_id | INTEGER | FK -> domains.id CASCADE |
| check_type | TEXT | NOT NULL (spf/dmarc/dkim/reputation) |
| consecutive_failures | INTEGER | DEFAULT 0 |
| last_failure_at | TIMESTAMP | NULLABLE |
| last_success_at | TIMESTAMP | NULLABLE |
| | | UNIQUE(domain_id, check_type) |

### Table: `change_log`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| domain_id | INTEGER | FK -> domains.id CASCADE |
| detected_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| check_type | TEXT | NOT NULL |
| field_changed | TEXT | NOT NULL |
| old_value | TEXT | NULLABLE |
| new_value | TEXT | NULLABLE |
| severity | TEXT | NOT NULL (info/warning/critical) |

Index: `(domain_id, detected_at DESC)`

### Table: `dns_settings`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PK (singleton, id=1) |
| resolvers | TEXT | NOT NULL (JSON array) |
| timeout_seconds | REAL | DEFAULT 5.0 |
| retries | INTEGER | DEFAULT 3 |
| flap_threshold | INTEGER | DEFAULT 2 |
| updated_at | TIMESTAMP | |
| updated_by | INTEGER | FK -> users.id |

---

## Features

---

### Phase 1: Foundation (Agent 1 - backend-architect)

---

#### Feature: F01 - Flask Application Factory
**Priority:** P0
**Agent:** backend-architect
**Model:** Sonnet
**Description:** Create Flask app factory with blueprint registration, configuration loading, and database initialization.

**Acceptance Criteria:**
- [ ] `create_app()` function in `app/__init__.py`
- [ ] Loads config from `app/config.py` (SECRET_KEY, SQLALCHEMY_DATABASE_URI, WTF_CSRF_ENABLED)
- [ ] Registers all 6 blueprints (auth, dashboard, history, settings, ingest, api)
- [ ] Initializes Flask-SQLAlchemy, Flask-Login, Flask-WTF
- [ ] SQLite3 path configurable via environment variable

**Verification Steps:**
1. `python -c "from app import create_app; app = create_app(); print(app.blueprints.keys())"`
2. All 6 blueprints listed

**Dependencies:** None

---

#### Feature: F02 - Configuration Module
**Priority:** P0
**Agent:** backend-architect
**Model:** Haiku
**Description:** Centralized configuration with sensible defaults and environment variable overrides.

**Acceptance Criteria:**
- [ ] SECRET_KEY from env var, error if not set in production
- [ ] SQLALCHEMY_DATABASE_URI defaults to `sqlite:///watcher.db`
- [ ] SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SAMESITE = 'Lax'
- [ ] MAX_CONTENT_LENGTH = 1MB (file uploads)
- [ ] Debug mode toggleable via env var

**Verification Steps:**
1. App starts with default config
2. Env vars override defaults

**Dependencies:** None

---

#### Feature: F03 - SQLAlchemy Models
**Priority:** P0
**Agent:** backend-architect
**Model:** Sonnet
**Description:** Define all 7 database models with relationships, indexes, and constraints.

**Acceptance Criteria:**
- [ ] All 7 tables defined per schema above
- [ ] Foreign keys with CASCADE delete on domain-related tables
- [ ] Composite unique constraints on `dkim_selectors` and `flap_state`
- [ ] Indexes on `(domain_id, checked_at DESC)` for check_results and change_log
- [ ] JSON columns use TEXT type with serialization helpers

**Verification Steps:**
1. `python init_db.py` creates all tables without errors
2. `sqlite3 watcher.db ".schema"` shows expected structure

**Dependencies:** F01

---

#### Feature: F04 - Database Initialization Script
**Priority:** P0
**Agent:** backend-architect
**Model:** Haiku
**Description:** `init_db.py` script that creates all tables and seeds default dns_settings.

**Acceptance Criteria:**
- [ ] Creates all tables if they don't exist
- [ ] Seeds `dns_settings` with id=1, resolvers=["8.8.8.8","1.1.1.1","9.9.9.9"], timeout=5.0, retries=3, flap_threshold=2
- [ ] Idempotent (safe to run multiple times)
- [ ] Enables WAL mode on SQLite

**Verification Steps:**
1. Run twice without error
2. `dns_settings` has exactly 1 row

**Dependencies:** F03

---

#### Feature: F05 - User Authentication System
**Priority:** P0
**Agent:** backend-architect
**Model:** Sonnet
**Description:** Login/logout with Flask-Login, bcrypt password hashing, CSRF protection.

**Acceptance Criteria:**
- [ ] Login page at `/login` with username/password form
- [ ] Passwords hashed with Werkzeug's `generate_password_hash` (pbkdf2:sha256)
- [ ] Flask-Login session management with `@login_required` decorator
- [ ] Logout at `/logout` clears session
- [ ] CSRF token on login form via Flask-WTF
- [ ] Failed login shows generic error "Invalid credentials"
- [ ] Redirect to `/login` for unauthenticated requests

**Verification Steps:**
1. Access `/` redirects to `/login`
2. Login with valid credentials redirects to dashboard
3. Login with invalid credentials shows error
4. Logout returns to login page

**Dependencies:** F03

---

#### Feature: F06 - Admin User Creation Script
**Priority:** P0
**Agent:** backend-architect
**Model:** Haiku
**Description:** `create_admin.py` CLI script to create the first admin user.

**Acceptance Criteria:**
- [ ] Prompts for username and password interactively
- [ ] Validates password minimum length (8 characters)
- [ ] Hashes password before storage
- [ ] Prevents duplicate usernames
- [ ] Can also accept `--username` and `--password` flags for non-interactive use

**Verification Steps:**
1. Run script, create user, login via web
2. Running with duplicate username shows error

**Dependencies:** F03, F05

---

#### Feature: F07 - Base HTML Template
**Priority:** P0
**Agent:** backend-architect
**Model:** Sonnet
**Description:** Bootstrap 5 base template with navigation, flash messages, and responsive layout.

**Acceptance Criteria:**
- [ ] Bootstrap 5 via CDN (CSS + JS)
- [ ] Navigation bar: Dashboard, Changes, Import, Settings, Logout
- [ ] Flash message rendering (success, warning, danger, info)
- [ ] Responsive viewport meta tag
- [ ] Block placeholders: title, content, scripts
- [ ] Footer with app name

**Verification Steps:**
1. All pages inherit from base.html
2. Nav links are correct and highlighted for current page
3. Flash messages render with correct styling

**Dependencies:** F01

---

#### Feature: F08 - WSGI Entry Point
**Priority:** P0
**Agent:** backend-architect
**Model:** Haiku
**Description:** `wsgi.py` for PythonAnywhere deployment.

**Acceptance Criteria:**
- [ ] Imports and calls `create_app()`
- [ ] Exports `app` variable for WSGI server
- [ ] Compatible with PythonAnywhere WSGI configuration

**Verification Steps:**
1. `python wsgi.py` starts the app without errors
2. PythonAnywhere web tab can point to this file

**Dependencies:** F01

---

### Phase 2: DNS Engine (Agent 2 - python-expert)

---

#### Feature: F09 - Robust DNS Resolver Wrapper
**Priority:** P0
**Agent:** python-expert
**Model:** Opus
**Description:** Configurable DNS resolver with timeout, retries, multiple nameservers, and error classification.

**Acceptance Criteria:**
- [ ] Loads settings from `dns_settings` table (resolvers, timeout, retries)
- [ ] Supports multiple nameservers with failover
- [ ] Configurable per-query timeout and total lifetime
- [ ] TCP fallback for truncated UDP responses
- [ ] Classifies errors: NXDOMAIN, SERVFAIL, Timeout, NoAnswer, other
- [ ] Returns structured result: `{success, records, error_type, error_message}`
- [ ] Thread-safe (each call creates own resolver instance or uses thread-local)

**Verification Steps:**
1. Resolves known domains successfully
2. Returns classified error for non-existent domains
3. Falls back to next nameserver on timeout

**Dependencies:** F04

---

#### Feature: F10 - SPF Record Validation
**Priority:** P0
**Agent:** python-expert
**Model:** Opus
**Description:** Fetch and validate SPF records using checkdmarc + custom logic.

**Acceptance Criteria:**
- [ ] Queries TXT records, filters for `v=spf1`
- [ ] Detects multiple SPF records (error condition)
- [ ] Parses mechanisms: ip4, ip6, include, a, mx, ptr, exists, redirect
- [ ] Counts DNS lookup mechanisms (max 10 per RFC 7208)
- [ ] Identifies qualifier: `-all` (hard fail, OK), `~all` (soft fail, WARNING), `?all` (neutral, WARNING), `+all` (pass all, CRITICAL), missing `all` (CRITICAL)
- [ ] Returns: `{status, record, policy, mechanisms[], lookup_count, warnings[], valid}`

**Verification Steps:**
1. Test with domain having `-all` -> status OK
2. Test with domain having `~all` -> status WARNING
3. Test with domain having no SPF -> status CRITICAL
4. Test with > 10 lookups -> warning

**Dependencies:** F09

---

#### Feature: F11 - DMARC Record Validation
**Priority:** P0
**Agent:** python-expert
**Model:** Opus
**Description:** Fetch and validate DMARC records with full field analysis.

**Acceptance Criteria:**
- [ ] Queries TXT for `_dmarc.{domain}`, filters for `v=DMARC1`
- [ ] Parses all tag=value pairs
- [ ] Validates `p=`: none -> WARNING, quarantine -> OK, reject -> OK, missing -> CRITICAL
- [ ] Validates `sp=`: same logic, inherits from `p=` if absent
- [ ] Validates `rua=`: checks mailto: URI format
- [ ] Validates `ruf=`: checks mailto: URI format
- [ ] Warns if `ruf` present but `rua` absent
- [ ] Notes `pct=`: warns if < 100
- [ ] Notes `aspf=` (r/s) and `adkim=` (r/s)
- [ ] Notes `fo=` (0/1/d/s)
- [ ] Returns: `{status, record, p, sp, rua, ruf, pct, aspf, adkim, fo, warnings[], valid}`

**Verification Steps:**
1. Test with `p=reject` -> OK
2. Test with `p=none` -> WARNING
3. Test with no DMARC record -> CRITICAL
4. Test with ruf but no rua -> warning

**Dependencies:** F09

---

#### Feature: F12 - DKIM Key Validation
**Priority:** P0
**Agent:** python-expert
**Model:** Opus
**Description:** Fetch and validate DKIM public keys for configured selectors.

**Acceptance Criteria:**
- [ ] For each active selector: queries TXT for `{selector}._domainkey.{domain}`
- [ ] Parses DKIM record: v=, k=, p=, t= tags
- [ ] Detects empty `p=` tag (key revoked)
- [ ] Decodes base64 public key, determines RSA key length via `cryptography` library
- [ ] Status: >= 2048 bits OK, 1024 bits WARNING, < 1024 bits CRITICAL, revoked CRITICAL
- [ ] Accepts `k=ed25519` as valid algorithm
- [ ] Aggregate DKIM status = worst across all selectors with valid records
- [ ] Returns: `[{selector, status, record, key_length, algorithm, valid, error}]`

**Verification Steps:**
1. Test with known Google selector -> valid key, 2048 bits
2. Test with non-existent selector -> NXDOMAIN, skip gracefully
3. Test with revoked key (empty p=) -> CRITICAL

**Dependencies:** F09

---

#### Feature: F13 - Domain Reputation Check
**Priority:** P1
**Agent:** python-expert
**Model:** Sonnet
**Description:** Check domain against DNS-based blacklists (DNSBL).

**Acceptance Criteria:**
- [ ] Queries at least 3 DNSBL servers: dbl.spamhaus.org, multi.uribl.com, multi.surbl.com
- [ ] A record response = listed (WARNING), NXDOMAIN = clean
- [ ] Timeout on DNSBL query does not block other checks
- [ ] Returns: `{status, listed_on[], clean_on[], errors[]}`

**Verification Steps:**
1. Test with known clean domain -> OK
2. Test with known listed domain -> WARNING
3. DNSBL timeout does not crash engine

**Dependencies:** F09

---

#### Feature: F14 - Check Orchestration Engine
**Priority:** P0
**Agent:** python-expert
**Model:** Sonnet
**Description:** Orchestrate all checks for one domain, aggregate results, save to database.

**Acceptance Criteria:**
- [ ] Runs SPF, DMARC, DKIM, reputation checks sequentially for a domain
- [ ] Computes `overall_status` = worst of individual statuses
- [ ] Measures `execution_time_ms`
- [ ] Saves `check_results` row
- [ ] Updates `domains.last_checked_at`, `domains.current_status`
- [ ] Updates `domains.last_ok_at` if overall_status is 'ok'
- [ ] Accepts `trigger_type` parameter ('manual' or 'scheduled')
- [ ] Handles exceptions gracefully per check (one failure doesn't skip others)

**Verification Steps:**
1. Run engine on a domain -> check_results row created
2. Domain record updated with new status
3. One check failing doesn't prevent others from running

**Dependencies:** F10, F11, F12, F13

---

#### Feature: F15 - Anti-Flapping State Machine
**Priority:** P0
**Agent:** python-expert
**Model:** Sonnet
**Description:** Prevent transient DNS failures from triggering false critical alerts.

**Acceptance Criteria:**
- [ ] Maintains `flap_state` per domain per check_type
- [ ] On success: reset `consecutive_failures` to 0, update `last_success_at`
- [ ] On failure: increment `consecutive_failures`, update `last_failure_at`
- [ ] Status display logic:
  - `consecutive_failures == 0`: show actual status
  - `0 < consecutive_failures < threshold`: cap at WARNING
  - `consecutive_failures >= threshold`: show actual status (CRITICAL allowed)
- [ ] Threshold loaded from `dns_settings.flap_threshold`

**Verification Steps:**
1. First DNS timeout -> WARNING (not CRITICAL)
2. Second consecutive timeout -> CRITICAL (threshold=2)
3. Success after failure -> reset, show OK

**Dependencies:** F09, F03

---

### Phase 3: Web Interface (Agent 3 - fullstack-developer)

---

#### Feature: F16 - Dashboard Page
**Priority:** P0
**Agent:** fullstack-developer
**Model:** Sonnet
**Description:** Main page showing all domains with color-coded status badges.

**Acceptance Criteria:**
- [ ] Table: hostname, SPF status, DMARC status, DKIM status, reputation, overall status, last checked
- [ ] Status badges: green (OK), yellow (WARNING), red (CRITICAL), grey (pending/error)
- [ ] "Add Domain" button/form at top
- [ ] "Check" button per domain row (triggers manual check)
- [ ] "Check All" button
- [ ] "Delete" button per domain (confirmation dialog)
- [ ] Sorted by hostname ascending
- [ ] Shows total count and summary (X ok, Y warning, Z critical)
- [ ] Login required

**Verification Steps:**
1. Dashboard shows all active domains
2. Status badges reflect current_status correctly
3. Add domain form works with validation
4. Delete requires confirmation

**Dependencies:** F05, F07, F14

---

#### Feature: F17 - Add Domain
**Priority:** P0
**Agent:** fullstack-developer
**Model:** Haiku
**Description:** Add a domain to the monitoring list.

**Acceptance Criteria:**
- [ ] Form field with hostname validation (valid domain format)
- [ ] Normalizes to lowercase, strips whitespace
- [ ] Rejects duplicates with user-friendly message
- [ ] Creates domain record with `added_by` = current user
- [ ] Auto-creates default DKIM selectors (10 common selectors)
- [ ] Optional notes field
- [ ] CSRF protection
- [ ] Flash success message, redirect to dashboard

**Verification Steps:**
1. Add valid domain -> appears in dashboard
2. Add duplicate -> error message
3. Add invalid format -> validation error

**Dependencies:** F03, F05

---

#### Feature: F18 - Delete Domain
**Priority:** P0
**Agent:** fullstack-developer
**Model:** Haiku
**Description:** Remove a domain from monitoring (soft delete).

**Acceptance Criteria:**
- [ ] POST request with domain ID
- [ ] Sets `is_active = False` (does not delete data)
- [ ] Requires confirmation (JavaScript confirm dialog)
- [ ] CSRF protection
- [ ] Flash success message
- [ ] Domain no longer appears on dashboard

**Verification Steps:**
1. Delete domain -> removed from dashboard
2. Data still in database (soft delete)

**Dependencies:** F03, F05

---

#### Feature: F19 - Manual Domain Check
**Priority:** P0
**Agent:** fullstack-developer
**Model:** Haiku
**Description:** Trigger an immediate check for one or all domains from the dashboard.

**Acceptance Criteria:**
- [ ] "Check" button per domain triggers check for that domain
- [ ] "Check All" button triggers check for all active domains
- [ ] Shows loading indicator during check
- [ ] Refreshes status after completion
- [ ] Sets `trigger_type = 'manual'`
- [ ] CSRF protection on POST

**Verification Steps:**
1. Click "Check" -> domain status updates
2. Click "Check All" -> all domains checked

**Dependencies:** F14, F16

---

#### Feature: F20 - Domain Detail Page
**Priority:** P0
**Agent:** fullstack-developer
**Model:** Sonnet
**Description:** Full breakdown of the latest check results for a domain.

**Acceptance Criteria:**
- [ ] Accessible at `/domains/<id>`
- [ ] Shows: hostname, overall status, last checked timestamp
- [ ] SPF section: raw record, policy (-all/~all), mechanism count, warnings
- [ ] DMARC section: raw record, p=, sp=, rua=, ruf=, pct=, aspf=, adkim=, fo=, warnings
- [ ] DKIM section: per-selector results (selector name, key length, algorithm, status)
- [ ] Reputation section: listed/clean blacklists
- [ ] DNS errors section (if any)
- [ ] Execution time
- [ ] Link to history page

**Verification Steps:**
1. All sections populated from latest check_results
2. Missing records shown as "No record found"
3. Warnings highlighted

**Dependencies:** F14, F16

---

#### Feature: F21 - DKIM Selector Management
**Priority:** P1
**Agent:** fullstack-developer
**Model:** Haiku
**Description:** Add/remove DKIM selectors per domain.

**Acceptance Criteria:**
- [ ] Accessible from domain detail page
- [ ] List current selectors with active/inactive toggle
- [ ] Add new selector form with validation
- [ ] Remove selector (soft delete)
- [ ] CSRF protection

**Verification Steps:**
1. Add custom selector -> appears in list
2. Deactivate selector -> not checked on next run

**Dependencies:** F03, F20

---

#### Feature: F22 - Settings Page
**Priority:** P0
**Agent:** fullstack-developer
**Model:** Haiku
**Description:** Configure DNS resolver parameters.

**Acceptance Criteria:**
- [ ] Form fields: DNS resolvers (comma-separated IPs), timeout (seconds), retries (count), flap threshold
- [ ] Validates IP address format for resolvers
- [ ] Validates numeric ranges (timeout 1-30, retries 1-10, threshold 1-5)
- [ ] Saves to `dns_settings` table
- [ ] Shows current values pre-filled
- [ ] CSRF protection

**Verification Steps:**
1. Change resolver IPs -> saved and used on next check
2. Invalid IP format -> validation error

**Dependencies:** F04, F05

---

#### Feature: F23 - Email List Import
**Priority:** P1
**Agent:** fullstack-developer
**Model:** Sonnet
**Description:** Upload a file containing email addresses, extract unique domains, add new ones.

**Acceptance Criteria:**
- [ ] Upload form accepting .txt and .csv files
- [ ] Max file size 1MB
- [ ] Parses emails using regex: extracts domain part after @
- [ ] Deduplicates domains
- [ ] Skips domains already in the system
- [ ] Adds new domains with default DKIM selectors
- [ ] Shows summary: X new domains added, Y already existed, Z invalid lines
- [ ] CSRF protection, file validation

**Verification Steps:**
1. Upload file with 10 emails from 5 domains, 2 already exist -> 3 added
2. Upload non-.txt/.csv file -> rejected
3. Upload > 1MB file -> rejected

**Dependencies:** F17

---

### Phase 4: History & Analytics (Agent 4 - frontend-architect)

---

#### Feature: F24 - Change Detection Engine
**Priority:** P0
**Agent:** frontend-architect
**Model:** Opus
**Description:** Compare consecutive check results and detect changes in DNS records.

**Acceptance Criteria:**
- [ ] After each check, compares current vs previous check_results for same domain
- [ ] Detects changes in: spf_record, dmarc_record (and individual fields), dkim key changes
- [ ] Classifies severity:
  - CRITICAL: policy downgrade (reject -> none), key revoked
  - WARNING: policy change (reject -> quarantine), key length decrease
  - INFO: record text change with same effective policy
- [ ] Writes to `change_log` table
- [ ] Skips comparison for first-ever check

**Verification Steps:**
1. SPF record changes -> change_log entry created
2. DMARC policy none->reject -> info entry
3. DMARC policy reject->none -> critical entry

**Dependencies:** F14

---

#### Feature: F25 - Domain History Page
**Priority:** P0
**Agent:** frontend-architect
**Model:** Sonnet
**Description:** Timeline view of check results and changes for a specific domain.

**Acceptance Criteria:**
- [ ] Accessible at `/domains/<id>/history`
- [ ] Chart.js line/bar chart: status over time (OK=green, WARNING=yellow, CRITICAL=red)
- [ ] Last 30 data points by default
- [ ] Change log table below chart: date, field changed, old value, new value, severity
- [ ] Shows last checked timestamp and last OK timestamp

**Verification Steps:**
1. Chart renders with correct color coding
2. Change log shows recent changes
3. Empty history shows appropriate message

**Dependencies:** F24, F20

---

#### Feature: F26 - Global Changes Page
**Priority:** P1
**Agent:** frontend-architect
**Model:** Sonnet
**Description:** Recent changes across all monitored domains.

**Acceptance Criteria:**
- [ ] Accessible at `/changes`
- [ ] Table: date, domain, check type, field changed, old -> new, severity
- [ ] Sorted by date descending
- [ ] Filterable by severity (info/warning/critical)
- [ ] Paginated (25 per page)
- [ ] Links to domain detail page

**Verification Steps:**
1. Shows changes from all domains
2. Severity filter works
3. Pagination works

**Dependencies:** F24

---

#### Feature: F27 - JSON API for Charts
**Priority:** P0
**Agent:** frontend-architect
**Model:** Sonnet
**Description:** API endpoints returning JSON data for Chart.js and AJAX dashboard refresh.

**Acceptance Criteria:**
- [ ] `GET /api/domains/<id>/history` -> `{labels[], datasets: {ok[], warning[], critical[]}}`
- [ ] `GET /api/domains/<id>/status` -> `{overall_status, spf_status, dmarc_status, dkim_status, reputation_status, last_checked}`
- [ ] `GET /api/dashboard/summary` -> `{total, ok, warning, critical, pending}`
- [ ] All endpoints require authentication (return 401 if not logged in)
- [ ] JSON responses with proper content-type

**Verification Steps:**
1. API returns valid JSON
2. Unauthenticated request returns 401
3. Chart data matches database records

**Dependencies:** F05, F03

---

#### Feature: F28 - Chart.js Integration
**Priority:** P1
**Agent:** frontend-architect
**Model:** Sonnet
**Description:** Client-side chart rendering for domain history.

**Acceptance Criteria:**
- [ ] Chart.js loaded via CDN in base template
- [ ] `charts.js` module fetches data from API, renders chart
- [ ] Stacked bar or line chart with color-coded statuses
- [ ] Responsive, works on mobile
- [ ] Shows last 30 checks by default
- [ ] Tooltip shows date and full status on hover

**Verification Steps:**
1. Chart renders correctly in domain history page
2. Chart is responsive on different screen sizes

**Dependencies:** F27

---

#### Feature: F29 - AJAX Dashboard Refresh
**Priority:** P2
**Agent:** frontend-architect
**Model:** Haiku
**Description:** Auto-refresh dashboard status without full page reload.

**Acceptance Criteria:**
- [ ] `dashboard.js` polls `/api/dashboard/summary` every 60 seconds
- [ ] Updates status badges and summary counts
- [ ] Visual indicator when refresh is in progress
- [ ] Stops polling when tab is not visible (Page Visibility API)

**Verification Steps:**
1. Status changes reflected without page reload
2. Polling stops when switching tabs

**Dependencies:** F27

---

#### Feature: F30 - Health Page
**Priority:** P1
**Agent:** frontend-architect
**Model:** Sonnet
**Description:** Observability page showing system health, metrics, and logs.

**Acceptance Criteria:**
- [ ] Accessible at `/health` (login required)
- [ ] Shows: total domains monitored, domains checked today, DNS errors today
- [ ] Shows: last scheduled run timestamp, last scheduled run duration
- [ ] Shows: database file size
- [ ] Shows: configured DNS resolvers and their reachability status
- [ ] Simple structured log viewer: last 50 check events (domain, status, timestamp, errors)

**Verification Steps:**
1. Metrics reflect actual database state
2. Page loads within 2 seconds
3. Log entries show recent activity

**Dependencies:** F03, F14

---

### Phase 5: Integration & QA (Agent 5 - quality-engineer)

---

#### Feature: F31 - Scheduled Check Script
**Priority:** P0
**Agent:** quality-engineer
**Model:** Sonnet
**Description:** Standalone Python script for PythonAnywhere daily scheduled task.

**Acceptance Criteria:**
- [ ] Imports `app.checker.engine` and `app.models`
- [ ] Creates Flask app context for database access
- [ ] Iterates all active domains, runs full check on each
- [ ] Sets `trigger_type = 'scheduled'`
- [ ] Logs start/end time and results to stdout (PythonAnywhere captures this)
- [ ] Handles exceptions per domain (one failure doesn't stop others)
- [ ] Exits with code 0 on success, 1 on fatal error
- [ ] Can accept `--domain` flag to check a single domain

**Verification Steps:**
1. Run script manually -> all domains checked
2. One domain failure doesn't stop others
3. Logs are readable and structured

**Dependencies:** F14

---

#### Feature: F32 - Structured Logging
**Priority:** P1
**Agent:** quality-engineer
**Model:** Haiku
**Description:** Consistent logging across the application using Python's logging module.

**Acceptance Criteria:**
- [ ] Logger configured in app factory with format: `%(asctime)s %(levelname)s %(name)s %(message)s`
- [ ] Log levels: DEBUG for DNS queries, INFO for check results, WARNING for issues, ERROR for failures
- [ ] Checker modules use named loggers (e.g., `checker.spf`, `checker.dmarc`)
- [ ] Web routes log significant actions (login, domain add/delete, check trigger)
- [ ] Logs to stdout/stderr (PythonAnywhere captures)
- [ ] No sensitive data in logs (no passwords, no full DNS records with keys)

**Verification Steps:**
1. Logs appear in PythonAnywhere server log
2. Log format is consistent and parseable
3. No sensitive data leaked

**Dependencies:** F01

---

#### Feature: F33 - Security Hardening
**Priority:** P0
**Agent:** quality-engineer
**Model:** Opus
**Description:** Security review and hardening across all modules.

**Acceptance Criteria:**
- [ ] All forms have CSRF tokens
- [ ] All user inputs validated and sanitized (domain names, settings values, file uploads)
- [ ] SQL injection impossible (parameterized queries via SQLAlchemy)
- [ ] XSS prevention: Jinja2 autoescaping enabled (default)
- [ ] File upload restrictions: .txt/.csv only, max 1MB, no path traversal
- [ ] Session security: HTTPOnly cookies, SameSite=Lax
- [ ] No debug mode in production
- [ ] SECRET_KEY not hardcoded
- [ ] Password hash uses Werkzeug pbkdf2:sha256 with salt
- [ ] Rate limiting on check endpoints (max 1 check per domain per 60 seconds)

**Verification Steps:**
1. CSRF token present on every form
2. SQL injection attempt via domain name fails safely
3. File upload of .exe rejected
4. Rapid check requests rate-limited

**Dependencies:** All previous features

---

#### Feature: F34 - Unit Tests - Checker Module
**Priority:** P0
**Agent:** quality-engineer
**Model:** Opus
**Description:** Tests for all checker modules using mocked DNS responses.

**Acceptance Criteria:**
- [ ] `test_spf.py`: test hard fail, soft fail, neutral, missing record, multiple records, >10 lookups
- [ ] `test_dmarc.py`: test all policy values, missing fields, rua/ruf validation, pct < 100
- [ ] `test_dkim.py`: test valid key, short key, revoked key, missing selector, ed25519
- [ ] `test_resolver.py`: test timeout, NXDOMAIN, SERVFAIL, TCP fallback
- [ ] `test_anti_flap.py`: test state transitions (stable -> degraded -> confirmed -> stable)
- [ ] All DNS calls mocked (no real network in tests)
- [ ] Test runner: `pytest tests/`

**Verification Steps:**
1. `pytest tests/` passes with 0 failures
2. All checker edge cases covered

**Dependencies:** F09-F15

---

#### Feature: F35 - Unit Tests - Web Routes
**Priority:** P1
**Agent:** quality-engineer
**Model:** Sonnet
**Description:** Tests for authentication and main web routes.

**Acceptance Criteria:**
- [ ] `test_routes.py`: test login/logout, dashboard access, add/delete domain, settings save
- [ ] Test unauthenticated access redirects to login
- [ ] Test CSRF validation
- [ ] Flask test client used (no real server)

**Verification Steps:**
1. `pytest tests/test_routes.py` passes

**Dependencies:** F16-F23

---

#### Feature: F36 - Unit Tests - Diff Engine & Ingest
**Priority:** P1
**Agent:** quality-engineer
**Model:** Sonnet
**Description:** Tests for change detection and email list import.

**Acceptance Criteria:**
- [ ] `test_diff_engine.py`: test SPF change detection, DMARC policy downgrade, DKIM key change
- [ ] `test_ingest.py`: test email parsing, domain extraction, deduplication, invalid lines

**Verification Steps:**
1. `pytest tests/test_diff_engine.py tests/test_ingest.py` passes

**Dependencies:** F23, F24

---

#### Feature: F37 - PythonAnywhere Deployment Guide
**Priority:** P1
**Agent:** quality-engineer
**Model:** Haiku
**Description:** Step-by-step deployment instructions.

**Acceptance Criteria:**
- [ ] Document in code comments or README section (not separate file)
- [ ] Steps: upload files, create virtualenv, install requirements, init DB, create admin, configure WSGI, add scheduled task
- [ ] Note: Hacker plan required for DNS queries
- [ ] SQLite path must use absolute path on PythonAnywhere

**Verification Steps:**
1. Following the steps results in working deployment

**Dependencies:** All features

---

## Timeline (MVP)

| Milestone | Agent(s) | Features | Status |
|-----------|----------|----------|--------|
| M1: Foundation | Agent 1 | F01-F08 | Pending |
| M2: DNS Engine | Agent 2 | F09-F15 | Pending |
| M3: Web Interface | Agent 3 | F16-F23 | Pending |
| M4: History & Analytics | Agent 4 | F24-F30 | Pending |
| M5: Integration & QA | Agent 5 | F31-F37 | Pending |

**Total features:** 37
**Feature breakdown:** P0: 22, P1: 12, P2: 1, P3: 2

---

## Key Architectural Decisions

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Flask over Django | Flask | Lighter for MVP, no admin overhead, PythonAnywhere native |
| SQLite3 | SQLite3 | PythonAnywhere constraint, zero config, MVP sufficient |
| Denormalized status on domains | Yes | Dashboard loads fast without JOINs |
| JSON TEXT columns for details | Yes | Flexible per check type, SQLite JSON1 available |
| Common selectors brute-force for DKIM | Yes | No discovery protocol exists; covers ~90% of cases |
| PythonAnywhere scheduled task | Yes | No background workers needed |
| Chart.js via CDN | Yes | No build step, interactive, lightweight |
| checkdmarc for SPF+DMARC | Yes | Actively maintained, covers both protocols |
| pydnsbl for reputation | Yes | Free, no API key, async, 50+ blacklists |

---

## Future Enhancements (Post-MVP)

- Email notifications on status changes
- Multi-user support with roles
- DMARC aggregate report ingestion (parsedmarc)
- VirusTotal API integration for deeper reputation
- Export reports as PDF
- Webhook integrations
- Domain grouping/tagging
- MX record validation
- BIMI record validation
- DNS-over-HTTPS fallback for restricted environments
