# config.py
import os
from datetime import timedelta
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))

def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")

class Config:
    # Core
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-key-please-change"
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI") or \
        "sqlite:///" + os.path.join(basedir, "phishguard.sqlite3")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT — make *sure* we read tokens from the Authorization header
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or SECRET_KEY
    JWT_TOKEN_LOCATION = ["headers"]      # <-- critical
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"
    JWT_ACCESS_TOKEN_EXPIRES  = timedelta(hours=6)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=14)

    # Mail
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.environ.get("MAIL_PORT") or 25)
    MAIL_USE_TLS = _env_bool("MAIL_USE_TLS", False)
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@example.com")
    MAIL_SUPPRESS_SEND = _env_bool("MAIL_SUPPRESS_SEND", False)

    # CORS / Extension
    CHROME_EXTENSION_ID = os.environ.get("CHROME_EXTENSION_ID", "")
    # Optionally allow overriding origins in env (comma-separated)
    CORS_ALLOWED_ORIGINS = os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        "https://phishguard.shop,http://127.0.0.1:5000"
    )

    # Model paths and settings
    PHISH_MODEL_PATH = os.environ.get("PHISH_MODEL_PATH")
    PHISH_IMPUTER_PATH = os.environ.get("PHISH_IMPUTER_PATH")
    PHISH_FEATURE_ORDER_PATH = os.environ.get("PHISH_FEATURE_ORDER_PATH")
    PHISH_TLD_FREQ_PATH = os.environ.get("PHISH_TLD_FREQ_PATH")
    PHISH_THRESHOLD_PATH = os.environ.get("PHISH_THRESHOLD_PATH")
    PHISH_THRESHOLD = float(os.environ.get("PHISH_THRESHOLD", 0.90))
    PHISH_NAN_DEFAULT = float(os.environ.get("PHISH_NAN_DEFAULT", 0.5))
