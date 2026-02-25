"""
F08 - WSGI entry point for SPF/DMARC/DKIM Watcher.

PythonAnywhere and other WSGI hosts import this module and look for
the ``app`` variable.  The development server can also be started by
running this file directly.
"""

from __future__ import annotations

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
