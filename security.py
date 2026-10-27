"""
security.py - the reusable security building blocks:

  * CSRF protection        (synchronizer-token pattern)
  * login rate limiting    (stored in SQLite, survives restarts)
  * access-control decorators
  * input validation
  * security response headers
"""
import hmac
import re
import secrets
import time
from functools import wraps

from flask import abort, current_app, flash, g, redirect, request, session, url_for

from database import audit, get_db

# --------------------------------------------------------------------------- CSRF
# Every state-changing request (POST) must carry a secret token that only pages
# served by this site know. A malicious site cannot read it, so it cannot forge
# a valid request. The names ("csrf_token", "X-CSRFToken") match Flask-WTF, so you
# can swap in Flask-WTF's CSRFProtect later without touching the templates.

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def csrf_token():
    """Return this session's token, creating it on first use."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def check_csrf():
    """Runs before every request. Aborts with 400 if a POST has no valid token."""
    if not current_app.config["CSRF_ENABLED"] or request.method in SAFE_METHODS:
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken", "")
    expected = session.get("_csrf", "")
    # compare_digest avoids leaking information through comparison timing
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        audit("csrf_rejected", session.get("user_id"), f"{request.method} {request.path}")
        abort(400)


# ------------------------------------------------------------------ Rate limiting
def _buckets(username):
    ip = request.remote_addr or "unknown"
    return f"user:{username.lower()[:64]}", f"ip:{ip}"


def _count_recent(bucket, since):
    row = get_db().execute(
        "SELECT COUNT(*) AS n FROM login_attempts WHERE bucket = ? AND attempted_at > ?",
        (bucket, since),
    ).fetchone()
    return row["n"]


def is_rate_limited(username):
    """True if this username or this IP has too many recent failed logins."""
    cfg = current_app.config
    now = int(time.time())
    since = now - cfg["LOGIN_WINDOW_SECONDS"]
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE attempted_at <= ?", (since,))  # housekeeping
    db.commit()
    user_bucket, ip_bucket = _buckets(username)
    return (
        _count_recent(user_bucket, since) >= cfg["LOGIN_MAX_ATTEMPTS"]
        or _count_recent(ip_bucket, since) >= cfg["LOGIN_MAX_ATTEMPTS_PER_IP"]
    )


def record_failed_login(username):
    now = int(time.time())
    db = get_db()
    for bucket in _buckets(username):
        db.execute("INSERT INTO login_attempts (bucket, attempted_at) VALUES (?, ?)", (bucket, now))
    db.commit()


def clear_failed_logins(username):
    """After a successful login, forgive that username only. The IP counter is kept so
    an attacker cannot reset it by logging in to their own account."""
    user_bucket, _ = _buckets(username)
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE bucket = ?", (user_bucket,))
    db.commit()


# ----------------------------------------------------------- Access control checks
# The server decides who you are from the signed session cookie, then re-reads your
# role from the database on every request (see load_current_user in app.py).
# Hiding a link in the menu is NOT access control; these decorators are.

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapper


def require_role(role):
    """Returns None if the current user has the role, otherwise a response to send back."""
    print("DEBUG ROLE:", g.user["role"] if g.user else None)
    print("DEBUG NEEDS:", role)
    if g.user is None:
        flash("Please sign in to continue.", "info")
        return redirect(url_for("auth.admin_login" if role == "admin" else "auth.login"))
    if g.user["role"] != role:
        audit("access_denied", g.user["id"], f"needs {role}: {request.method} {request.path}")
        abort(403)
    return None


def role_required(role):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            denied = require_role(role)
            if denied is not None:
                return denied
            return view(*args, **kwargs)

        return wrapper

    return decorator


# --------------------------------------------------------------- Input validation
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s<>\"']{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^[0-9+\- ]{7,15}$")
COURSES = ("BCA", "BBA-CA", "BSc-CS")
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789", "1234567890", "qwerty123",
    "qwertyuiop", "iloveyou1", "admin12345", "welcome123", "letmein123", "abc123456",
}


def clean_line(value, max_len):
    """Single-line text: remove control characters, collapse spaces, cap the length."""
    value = re.sub(r"[\x00-\x1f\x7f]", " ", value or "")
    return " ".join(value.split())[:max_len]


def clean_block(value, max_len):
    """Multi-line text (notice bodies): keep newlines, drop other control characters."""
    value = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value or "")
    return value.strip()[:max_len]


def validate_password(password, username=""):
    """Returns an error message, or None if the password is acceptable."""
    min_len = current_app.config["PASSWORD_MIN_LENGTH"]
    if len(password) < min_len:
        return f"Password must be at least {min_len} characters long."
    if len(password) > 128:
        return "Password must be 128 characters or fewer."
    if not (re.search(r"[A-Za-z]", password) and re.search(r"[0-9]", password)):
        return "Password must contain at least one letter and one number."
    if password.lower() in COMMON_PASSWORDS:
        return "That password is too common. Choose something less guessable."
    if username and username.lower() in password.lower():
        return "Password must not contain your username."
    return None


def validate_full_name(name):
    if not (2 <= len(name) <= 80) or not all(c.isalpha() or c in " .'-" for c in name):
        return "Name must be 2-80 characters: letters, spaces, dots, hyphens and apostrophes only."
    return None


def validate_phone(phone):
    if phone and not PHONE_RE.match(phone):
        return "Phone must be 7-15 characters: digits, spaces, + and - only."
    return None


def validate_address(address):
    if len(address) > 200:
        return "Address must be 200 characters or fewer."
    if re.search(r"[<>]", address):
        return "Address must not contain < or >."
    return None


def parse_number(raw, low, high, label):
    """Returns (value, error)."""
    try:
        value = float(str(raw).strip())
    except ValueError:
        return None, f"{label} must be a number."
    if not (low <= value <= high):  # also rejects NaN
        return None, f"{label} must be between {low:g} and {high:g}."
    return value, None


# ---------------------------------------------------------------- Response headers
def add_security_headers(response):
    h = response.headers
    # Scripts, styles, images and forms may only come from this same site.
    h["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "same-origin"
    h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if current_app.config["HSTS_ENABLED"]:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Signed-in pages must not be stored by the browser (stops the Back button
    # re-showing private data after logout).
    if g.get("user") is not None or request.endpoint in ("auth.login", "auth.admin_login"):
        h["Cache-Control"] = "no-store"
    return response
