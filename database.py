"""
database.py - SQLite connection handling and the audit log helper.

RULE FOR THE WHOLE PROJECT: every SQL statement uses "?" placeholders and passes
values as a separate tuple. User input is never glued into SQL text.
"""
import re
import sqlite3
from pathlib import Path

from flask import current_app, g, has_request_context, request

SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"


def get_db():
    """One connection per request, stored on Flask's `g` object."""
    if "db" not in g:
        path = Path(current_app.config["DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    """Create tables (safe to run more than once)."""
    db = get_db()
    db.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
    db.commit()


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def audit(event, user_id=None, detail=""):
    """Record a security event. Control characters are stripped so nobody can forge
    extra log lines by putting newlines in a username."""
    ip = request.remote_addr if has_request_context() else None
    clean = _CONTROL_CHARS.sub(" ", str(detail))[:200]
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (event, user_id, ip, detail) VALUES (?, ?, ?, ?)",
        (event, user_id, ip, clean),
    )
    db.commit()
