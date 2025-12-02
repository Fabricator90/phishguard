# app/__init__.py
import os
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

from .extensions import db, login_manager, mail, migrate, jwt
from .auth.routes import auth_bp
from .main.routes import bp as main_bp          # "/" and "/dashboard"
from .api.routes import api_bp                  # /api/*
from .predictions.predict import bp as ml_bp    # /api/health, /api/debug_check, ...

def create_app():
    # Load .env from project root (useful in local dev)
    base_dir = os.path.abspath(os.path.dirname(__file__))
    load_dotenv(os.path.join(os.path.dirname(base_dir), ".env"))

    app = Flask(__name__, instance_relative_config=False)

    # Read all settings from config.py:Config (JWT, DB, mail, model paths, etc.)
    app.config.from_object("config.Config")

    # ---------- CORS ----------
    # Allow your site and (optionally) your Chrome extension ID.
    env = (os.getenv("FLASK_ENV") or "").lower()
    is_dev = env == "development" or (os.getenv("FLASK_DEBUG") or "").lower() in ("1", "true", "yes")

    allowed = [o.strip() for o in (app.config.get("CORS_ALLOWED_ORIGINS") or "").split(",") if o.strip()]
    ext_id = (app.config.get("CHROME_EXTENSION_ID") or "").strip()
    if ext_id:
        allowed.append(f"chrome-extension://{ext_id}")

    if is_dev and not allowed:
        # Relaxed in dev
        allowed = ["*", "chrome-extension://*"]
    elif not allowed:
        # Safe defaults for prod if not provided
        allowed = ["https://phishguard.shop", "https://www.phishguard.shop"]

    CORS(
        app,
        resources={r"/api/*": {"origins": allowed}},
        allow_headers=["Authorization", "Content-Type"],
        methods=["GET", "POST", "OPTIONS"],
        supports_credentials=False,
    )

    # ---------- Init extensions ----------
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    mail.init_app(app)
    jwt.init_app(app)

    # ---------- Blueprints ----------
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(ml_bp)

    return app
