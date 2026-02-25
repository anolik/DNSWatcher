"""
F08 - WSGI entry point for SPF/DMARC/DKIM Watcher.

PythonAnywhere and other WSGI hosts import this module and look for
the ``app`` variable.  The development server can also be started by
running this file directly.

=============================================================================
PYTHONANYWHERE DEPLOYMENT GUIDE
=============================================================================

1. UPLOAD FILES
   Upload the entire project directory to your PythonAnywhere home folder,
   for example: /home/<username>/watcher/

   Use the PythonAnywhere Files tab, git clone, or scp.

2. CREATE VIRTUAL ENVIRONMENT
   Open a PythonAnywhere Bash console and run:

     mkvirtualenv --python=python3.10 watcher
     workon watcher

   Python 3.10+ is required.  Adjust the version to match what is available
   on your PythonAnywhere account.

3. INSTALL DEPENDENCIES
     cd /home/<username>/watcher
     pip install -r requirements.txt

4. INITIALISE THE DATABASE
   Run the database setup script once to create all tables:

     python /home/<username>/watcher/init_db.py

   The default SQLite database will be created at:
     /home/<username>/watcher/instance/watcher.db

   IMPORTANT: Always use an absolute path for the SQLite database on
   PythonAnywhere.  In your environment or config, set:
     DATABASE_URL=sqlite:////home/<username>/watcher/instance/watcher.db
   Note the four slashes: three for the protocol prefix plus one for the
   absolute filesystem path.

5. CREATE THE ADMIN USER
   Create your first administrator account:

     python /home/<username>/watcher/create_admin.py \
       --username admin \
       --password <your-secure-password>

   Choose a strong password and change it after the first login.

6. SET ENVIRONMENT VARIABLES
   In the PythonAnywhere Web tab, scroll to "Environment variables" and add:

     SECRET_KEY=<a-long-random-string>
     DATABASE_URL=sqlite:////home/<username>/watcher/instance/watcher.db

   You can generate a SECRET_KEY with:
     python -c "import secrets; print(secrets.token_hex(32))"

   Never commit the SECRET_KEY to version control.

7. CONFIGURE THE WSGI FILE
   In the PythonAnywhere Web tab:
   - Click "Add a new web app"
   - Choose "Manual configuration" and select Python 3.10
   - Set the virtualenv path: /home/<username>/.virtualenvs/watcher
   - Click the WSGI configuration file link and replace its entire content
     with the following:

     import sys
     import os

     project_home = '/home/<username>/watcher'
     if project_home not in sys.path:
         sys.path.insert(0, project_home)

     os.environ['SECRET_KEY'] = '<your-secret-key>'
     os.environ['DATABASE_URL'] = 'sqlite:////home/<username>/watcher/instance/watcher.db'

     from wsgi import app as application  # noqa: F401

8. ADD THE SCHEDULED DAILY CHECK
   In the PythonAnywhere "Tasks" tab, add a daily scheduled task:

     Command : /home/<username>/.virtualenvs/watcher/bin/python \
               /home/<username>/watcher/scheduled_check.py
     Hour    : 06   (or any off-peak hour in UTC)
     Minute  : 00

   This runs the SPF/DMARC/DKIM checks for all active domains once per day.

9. PYTHONANYWHERE PLAN REQUIREMENTS
   The Hacker plan ($5/month) or higher is REQUIRED.

   The free plan blocks outbound TCP/UDP connections except to a whitelist.
   DNS resolution uses UDP port 53, which is blocked on the free plan.
   Without outbound DNS, all checks will fail with timeout errors.

10. RELOAD THE WEB APP
    In the PythonAnywhere Web tab, click the green "Reload" button after
    all configuration steps are complete.

11. VERIFY DEPLOYMENT
    Visit https://<username>.pythonanywhere.com in a browser.
    Log in with the admin credentials created in step 5.
    Add a test domain and run a manual check to confirm DNS resolution works.

=============================================================================
LOCAL DEVELOPMENT
=============================================================================

Run the Flask development server with:

  export SECRET_KEY=dev-only-not-for-production
  python wsgi.py

The app will be available at http://127.0.0.1:5000/

For testing:

  pip install pytest pytest-cov
  pytest tests/ -v
  pytest tests/ --cov=app --cov-report=term-missing

=============================================================================
"""

from __future__ import annotations

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
