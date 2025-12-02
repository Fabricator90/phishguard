PhishGuard

Flask API + Chrome MV3 extension for real-time phishing risk detection.
The extension sends page/link URLs; the API serves a trained model and returns a label + score.


Files for the Extension
Google Drive (packaged assets):
https://drive.google.com/drive/folders/1yR-pS1MigUfD7Lxv-qdisMeh9a8LW1GN?usp=drive_link










What’s inside
Backend: Flask (app factory), JWT auth, Alembic/Flask-Migrate, SQLAlchemy (Postgres/SQLite)
Model serving: phish_rf.joblib + imputer_phi.joblib (tracked with Git LFS)
Features: 12 features w/ NaN-safe imputation, HTTPS/TLD heuristics
Data: /api/report persists reports for the dashboard
Dashboard: Revamped templates/base.html, templates/dashboard.html, and templates/index.html
Deploy: Render (Web Service + Postgres). Portable Git-LFS during build.



Quick start (Windows, PowerShell)
# 1) Clone & enter
git clone https://github.com/<your-username>/phishguard.git
cd phishguard

# 2) Create venv & install deps
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 3) (First time) pull model artifacts via Git LFS
git lfs install
git lfs pull

# 4) Create .env (see below), then initialize DB
python -m flask --app wsgi.py db upgrade

# 5) Run the API (dev)
python -m flask --app wsgi.py run --debug --port 5000




Alternative run command (same result):
$env:FLASK_APP="wsgi.py"
flask run --reload --port 5000



.env (minimal for local dev)
# Flask
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=change-me

# Database (SQLite for local)
SQLALCHEMY_DATABASE_URI=sqlite:///phishguard.sqlite3

# Model behavior
PHISH_THRESHOLD=0.90
PHISH_NAN_DEFAULT=0.5

# JWT for /api
JWT_SECRET_KEY=change-me-too

# Email (Mailtrap or disable)
MAIL_SERVER=live.smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USE_TLS=true
MAIL_USERNAME=smtp@mailtrap.io
MAIL_PASSWORD=<your-mailtrap-password>
MAIL_DEFAULT_SENDER="PhishGuard <noreply@phishguard.shop>"
MAIL_SUPPRESS_SEND=false

# Tokens for email flows
SECURITY_EMAIL_SALT=confirm-salt-CHANGE-ME
SECURITY_RESET_SALT=reset-salt-CHANGE-ME
TOKEN_MAX_AGE=86400



Chrome Extension (dev)
Open chrome://extensions, enable Developer mode.
Load unpacked → select phishguard_chrome_extension_v2/.
Edit phishguard_chrome_extension_v2/config.js:
// For local dev:
const CONFIG = { API_BASE: "http://127.0.0.1:5000" };
// For prod:
// const CONFIG = { API_BASE: "https://www.phishguard.shop" };
Open the popup → Log in → “Scan this page”.



REST API (quick)
Auth
POST /api/login → { access_token, refresh_token }
POST /api/refresh → { access_token }
GET /api/me (Bearer)


Scoring
POST /api/check → { url, label, score }
GET /api/health → model/meta diagnostics

Reports
POST /api/report (persist one)
GET /api/reports?limit=50



Deploy on Render
Build Command
bash scripts/render-build.sh
(Downloads portable Git-LFS, runs git lfs pull, then pip install -r requirements.txt.)
Start Command
PYTHONPATH=. FLASK_APP=wsgi.py python -m flask db upgrade && \
python -m gunicorn --preload -w 1 -k gthread --threads 4 --timeout 120 -b 0.0.0.0:$PORT wsgi:app



Key environment variables (prod)
SECRET_KEY
JWT_SECRET_KEY
SQLALCHEMY_DATABASE_URI (Postgres), e.g.
postgresql+psycopg://<user>:<pass>@<host>/<db>?sslmode=require
MAIL_* (if you want registration/reset emails)
SECURITY_EMAIL_SALT, SECURITY_RESET_SALT, TOKEN_MAX_AGE
PHISH_THRESHOLD (prod default is often 0.85)
PHISH_NAN_DEFAULT=0.5


Models not loading → ensure git lfs pull fetched .joblib files.
DB URL errors → use the postgresql+psycopg:// driver prefix.
Migration errors → run python -m flask --app wsgi.py db upgrade.
Emails fail → confirm MAIL_* settings and Mailtrap domain verification; set MAIL_SUPPRESS_SEND=true to disable sending in dev.



Changelog (Oct 2025)
Revamped UI templates: base.html, dashboard.html, index.html
Hardened email flows (confirmation + reset) using salts and timed tokens
Widened users.password_hash to 255 (Alembic migration)
Render build now uses portable Git-LFS; Start command runs DB migrations automatically


Commit & push to GitHub
# From repo root
git add -A
git commit -m "docs: update README with local run steps and deploy notes"
git push origin main.


License
MIT (see LICENSE)