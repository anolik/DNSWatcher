# Workflow

## Execution Order
```
        Phase 1 (Foundation)
               |
      +--------+--------+
      |                 |
 Phase 2 (DNS)    Phase 3 (Web)     <-- parallel
      |                 |
      +--------+--------+
               |
        Phase 4 (History)
               |
        Phase 5 (QA & Ops)
```

---

## Phase 1: Foundation
**Agent:** backend-architect
**Checkpoint:** Git commit after all Phase 1 features pass

### Task 1.1: App Factory & Config
**Feature IDs:** F01, F02
**Model:** F01=Sonnet, F02=Haiku
**Files:** `app/__init__.py`, `app/config.py`
**Done when:** `create_app()` returns Flask app with 6 blueprints registered

### Task 1.2: Database Models
**Feature IDs:** F03
**Model:** Sonnet
**Files:** `app/models.py`
**Done when:** All 7 tables defined with relationships, indexes, constraints

### Task 1.3: Database Init Script
**Feature IDs:** F04
**Model:** Haiku
**Files:** `init_db.py`
**Done when:** `python init_db.py` creates tables + seeds dns_settings, idempotent

### Task 1.4: Authentication System
**Feature IDs:** F05, F06
**Model:** F05=Sonnet, F06=Haiku
**Files:** `app/auth/routes.py`, `app/auth/forms.py`, `app/auth/__init__.py`, `create_admin.py`
**Done when:** Login/logout works, admin user created via CLI

### Task 1.5: Base Template & WSGI
**Feature IDs:** F07, F08
**Model:** F07=Sonnet, F08=Haiku
**Files:** `app/templates/base.html`, `app/templates/login.html`, `wsgi.py`
**Done when:** Bootstrap 5 layout with nav, flash messages, WSGI starts

---

## Phase 2: DNS Engine
**Agent:** python-expert
**Depends on:** Phase 1
**Checkpoint:** Git commit after all Phase 2 features pass

### Task 2.1: DNS Resolver Wrapper
**Feature IDs:** F09
**Model:** Opus
**Files:** `app/checker/resolver.py`, `app/checker/__init__.py`
**Done when:** Configurable resolver with timeout, retry, failover, error classification

### Task 2.2: SPF Validation
**Feature IDs:** F10
**Model:** Opus
**Files:** `app/checker/spf.py`
**Done when:** SPF records fetched, parsed, policy identified, lookup count checked

### Task 2.3: DMARC Validation
**Feature IDs:** F11
**Model:** Opus
**Files:** `app/checker/dmarc.py`
**Done when:** DMARC records parsed, all fields validated (p, sp, rua, ruf, pct, aspf, adkim, fo)

### Task 2.4: DKIM Key Validation
**Feature IDs:** F12
**Model:** Opus
**Files:** `app/checker/dkim.py`
**Done when:** DKIM keys fetched per selector, key length checked, algorithm validated

### Task 2.5: Domain Reputation
**Feature IDs:** F13
**Model:** Sonnet
**Files:** `app/checker/reputation.py`
**Done when:** DNSBL queries return listed/clean status per domain

### Task 2.6: Check Engine & Anti-Flapping
**Feature IDs:** F14, F15
**Model:** Sonnet
**Files:** `app/checker/engine.py`, `app/checker/anti_flap.py`
**Done when:** Full domain check runs, results saved, anti-flapping prevents false criticals

---

## Phase 3: Web Interface
**Agent:** fullstack-developer
**Depends on:** Phase 1
**Runs in parallel with:** Phase 2
**Checkpoint:** Git commit after all Phase 3 features pass

### Task 3.1: Dashboard Page
**Feature IDs:** F16, F17, F18, F19
**Model:** F16=Sonnet, F17=Haiku, F18=Haiku, F19=Haiku
**Files:** `app/dashboard/routes.py`, `app/dashboard/forms.py`, `app/dashboard/__init__.py`, `app/templates/dashboard.html`
**Done when:** Domain table with status badges, add/delete/check actions work

### Task 3.2: Domain Detail & DKIM Selectors
**Feature IDs:** F20, F21
**Model:** F20=Sonnet, F21=Haiku
**Files:** `app/templates/domain_detail.html`
**Done when:** Full check breakdown displayed, DKIM selectors manageable

### Task 3.3: Settings Page
**Feature IDs:** F22
**Model:** Haiku
**Files:** `app/settings/routes.py`, `app/settings/forms.py`, `app/settings/__init__.py`, `app/templates/settings.html`
**Done when:** DNS resolver config editable and saved

### Task 3.4: Email Import
**Feature IDs:** F23
**Model:** Sonnet
**Files:** `app/ingest/routes.py`, `app/ingest/parser.py`, `app/ingest/__init__.py`, `app/templates/import.html`
**Done when:** File upload extracts domains, deduplicates, adds to database

---

## Phase 4: History & Analytics
**Agent:** frontend-architect
**Depends on:** Phase 2 + Phase 3
**Checkpoint:** Git commit after all Phase 4 features pass

### Task 4.1: Change Detection Engine
**Feature IDs:** F24
**Model:** Opus
**Files:** `app/history/diff_engine.py`, `app/history/__init__.py`
**Done when:** Record changes detected, classified by severity, saved to change_log

### Task 4.2: History & Changes Pages
**Feature IDs:** F25, F26
**Model:** Sonnet
**Files:** `app/history/routes.py`, `app/templates/domain_history.html`, `app/templates/changes.html`
**Done when:** Per-domain timeline + global change log pages render correctly

### Task 4.3: JSON API & Charts
**Feature IDs:** F27, F28, F29
**Model:** F27=Sonnet, F28=Sonnet, F29=Haiku
**Files:** `app/api/routes.py`, `app/api/__init__.py`, `app/static/js/charts.js`, `app/static/js/dashboard.js`
**Done when:** Chart.js renders history, AJAX refreshes dashboard

### Task 4.4: Health Page
**Feature IDs:** F30
**Model:** Sonnet
**Files:** `app/templates/health.html`
**Done when:** Metrics, DNS resolver status, and recent logs displayed

---

## Phase 5: Integration & QA
**Agent:** quality-engineer
**Depends on:** All previous phases
**Checkpoint:** Git commit after all Phase 5 features pass

### Task 5.1: Scheduled Check Script
**Feature IDs:** F31
**Model:** Sonnet
**Files:** `scheduled_check.py`
**Done when:** Script runs all active domains, handles errors, logs results

### Task 5.2: Structured Logging
**Feature IDs:** F32
**Model:** Haiku
**Files:** Logging config in `app/__init__.py`
**Done when:** Named loggers, consistent format, no sensitive data

### Task 5.3: Security Hardening
**Feature IDs:** F33
**Model:** Opus
**Files:** Across all modules
**Done when:** CSRF on all forms, input validation, rate limiting, session security

### Task 5.4: Unit Tests - Checker Module
**Feature IDs:** F34
**Model:** Opus
**Files:** `tests/test_spf.py`, `tests/test_dmarc.py`, `tests/test_dkim.py`, `tests/test_resolver.py`, `tests/test_anti_flap.py`
**Done when:** All checker edge cases covered with mocked DNS, pytest passes

### Task 5.5: Unit Tests - Web & Diff
**Feature IDs:** F35, F36
**Model:** Sonnet
**Files:** `tests/test_routes.py`, `tests/test_diff_engine.py`, `tests/test_ingest.py`
**Done when:** Route tests pass, diff engine tests pass, ingest tests pass

### Task 5.6: Deployment Guide
**Feature IDs:** F37
**Model:** Haiku
**Files:** Comments in `wsgi.py` and `scheduled_check.py`
**Done when:** PythonAnywhere deployment steps documented in code
