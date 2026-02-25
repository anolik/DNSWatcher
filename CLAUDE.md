# SPF/DMARC/DKIM Watcher

## Identity
- **Name:** SPF/DMARC/DKIM Watcher
- **Purpose:** Monitor email authentication DNS configurations (SPF, DMARC, DKIM) and domain spam reputation for a list of domains, with daily automated checks, change detection, and history tracking.
- **Type:** MVP / Proof of Concept
- **Language:** French UI labels acceptable, English code

## Tech Stack
| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | >= 3.10 |
| Framework | Flask | >= 3.1 |
| ORM | Flask-SQLAlchemy | >= 3.1 |
| Auth | Flask-Login + Werkzeug | >= 0.6 |
| CSRF | Flask-WTF | >= 1.2 |
| Database | SQLite3 | built-in |
| DNS | dnspython | >= 2.7 |
| SPF/DMARC | checkdmarc | >= 5.14 |
| DKIM | dnspython + cryptography | >= 42.0 |
| Reputation | pydnsbl | >= 1.1 |
| Frontend | Bootstrap 5 + Chart.js | CDN |
| Hosting | PythonAnywhere | Hacker plan |

## Startup Ritual
```bash
pwd && ls -la
cat CLAUDE.md
cat WORKFLOW.md
cat .agent/feature_list.json
cat .agent/claude-progress.txt
git log --oneline -10
grep -c '"passes": false' .agent/feature_list.json
```

## Coding Standards
- **Python Style:** PEP 8, 4-space indent, snake_case
- **Max line length:** 120 characters
- **Imports:** stdlib first, third-party second, local third, separated by blank lines
- **Type hints:** Use on all function signatures
- **Docstrings:** Google style, required on all public functions
- **Templates:** Jinja2 with autoescaping enabled
- **JavaScript:** Vanilla JS, no build step, ES6+
- **SQL:** Parameterized queries only (via SQLAlchemy ORM)
- **Passwords:** Werkzeug pbkdf2:sha256 hashing only
- **Error handling:** Specific exceptions, never bare `except:`
- **Logging:** Use `logging` module with named loggers per module
- **Tests:** pytest, all DNS calls mocked

## Project Structure
```
app/                    # Flask application package
  __init__.py           # App factory
  config.py             # Configuration
  models.py             # SQLAlchemy models (7 tables)
  auth/                 # Authentication blueprint
  dashboard/            # Domain management blueprint
  checker/              # DNS checking engine (pure logic)
  history/              # History and change tracking blueprint
  settings/             # DNS resolver config blueprint
  ingest/               # Email list import blueprint
  api/                  # JSON API blueprint
  templates/            # Jinja2 templates
  static/               # CSS and JS
tests/                  # pytest test suite
.agent/                 # Agent tracking files
scheduled_check.py      # PythonAnywhere daily task script
create_admin.py         # CLI: create first admin user
init_db.py              # CLI: initialize database
wsgi.py                 # WSGI entry point
```

## Constraints
- **PythonAnywhere Hacker plan** ($5/mo) required for outbound DNS queries
- **No WebSockets** - use AJAX polling for dashboard refresh
- **No Celery** - use PythonAnywhere scheduled tasks
- **SQLite3** - WAL mode for concurrent reads during scheduled writes
- **DKIM selectors** must be known (no enumeration protocol); brute-force common selectors
- **File uploads** max 1MB, .txt/.csv only

## Agent Team (5 Agents)
| # | Agent | Role |
|---|-------|------|
| 1 | backend-architect | Foundation: app factory, models, auth, config |
| 2 | python-expert | DNS Engine: resolver, SPF, DMARC, DKIM, reputation, anti-flap |
| 3 | fullstack-developer | Web Interface: routes, templates, forms, dashboard |
| 4 | frontend-architect | History & Analytics: diffs, charts, API, health |
| 5 | quality-engineer | QA & Ops: tests, security, scheduling, deployment |

## Model Selection
- **Opus:** RFC compliance, crypto, security audit, complex state machines (F09-F12, F24, F33, F34)
- **Sonnet:** Standard CRUD, templates, moderate logic (F01, F03, F05, F07, F13-F16, F20, F23, F25-F28, F30, F31, F35, F36)
- **Haiku:** Boilerplate, simple config, trivial scripts (F02, F04, F06, F08, F17-F19, F21, F22, F29, F32, F37)

## Skills
- `project-planning` -> PRD.md
- `project-init` -> Setup (this step)
- `project-coding` -> Implementation
- `project-optimization` -> Quality checkup
