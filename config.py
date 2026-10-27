"""
config.py - all settings live here.

Secrets (like SECRET_KEY) are NEVER written in this file. They are read from
environment variables, which you set in a local ".env" file (see .env.example).
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Load variables from ".env" if python-dotenv is installed.
try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")
except ImportError:  # python-dotenv is optional; real environment variables still work
    pass


class BaseConfig:
    """Settings shared by every environment."""

    # Read from the environment. create_app() refuses to start without it.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # SQLite file. An empty DATABASE_PATH falls back to instance/portal.sqlite3
    DATABASE = os.environ.get("DATABASE_PATH") or str(BASE_DIR / "instance" / "portal.sqlite3")

    # --- Session cookie hardening ---
    SESSION_COOKIE_NAME = "ssp_session"
    SESSION_COOKIE_HTTPONLY = True      # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Lax"     # browser will not send it on cross-site POSTs
    SESSION_COOKIE_SECURE = False       # local dev runs on plain http; production turns this on
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # idle timeout (refreshes on each request)

    # --- Request limits ---
    MAX_CONTENT_LENGTH = 16 * 1024      # reject request bodies bigger than 16 KB

    # --- Login throttling (see security.py) ---
    LOGIN_MAX_ATTEMPTS = 5              # failures allowed per username in the window
    LOGIN_MAX_ATTEMPTS_PER_IP = 20      # failures allowed per IP address in the window
    LOGIN_WINDOW_SECONDS = 15 * 60

    # --- Passwords ---
    PASSWORD_HASH_METHOD = os.environ.get("PASSWORD_HASH_METHOD", "scrypt")
    PASSWORD_MIN_LENGTH = 10

    CSRF_ENABLED = True
    HSTS_ENABLED = False
    DEBUG = False
    TESTING = False


class DevelopmentConfig(BaseConfig):
    # Debug stays OFF unless you deliberately opt in. The Werkzeug debugger can run
    # arbitrary code, so it must never be reachable from a network.
    DEBUG = os.environ.get("ENABLE_DEBUG", "0") == "1"


class ProductionConfig(BaseConfig):
    DEBUG = False                       # forced off, ignores ENABLE_DEBUG
    SESSION_COOKIE_SECURE = True        # cookie only travels over HTTPS
    HSTS_ENABLED = True


class TestingConfig(BaseConfig):
    TESTING = True
    # A throw-away random key per test run. Nothing real is stored here.
    SECRET_KEY = secrets.token_hex(32)


CONFIGS = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name=None):
    name = (name or os.environ.get("APP_ENV") or "development").lower()
    try:
        return CONFIGS[name]
    except KeyError:
        raise RuntimeError(f"Unknown APP_ENV '{name}'. Use development, production or testing.")
