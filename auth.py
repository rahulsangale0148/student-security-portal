"""
auth.py - registration, student login, admin login, logout, password change.
"""
import secrets
import sqlite3
from datetime import date

from flask import (Blueprint, current_app, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from database import audit, get_db
from security import (EMAIL_RE, USERNAME_RE, clear_failed_logins, clean_line, is_rate_limited,
                      login_required, record_failed_login, validate_full_name,
                      validate_password)

bp = Blueprint("auth", __name__)

# One message for every kind of login failure, so an attacker cannot tell whether
# the username exists, the password was wrong, or the account is disabled.
GENERIC_LOGIN_ERROR = "Incorrect username or password."

_dummy_hash = None


def hash_password(password):
    return generate_password_hash(password, method=current_app.config["PASSWORD_HASH_METHOD"])


def _dummy_password_hash():
    """A hash of a random value. Checked when the username does not exist so that
    'unknown user' takes about as long as 'wrong password' (defeats timing probes)."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_hex(16))
    return _dummy_hash


def _login(required_role, template, home_endpoint):
    if g.user is not None:
        return redirect(url_for(home_endpoint if g.user["role"] == required_role else "public.home"))

    if request.method == "GET":
        return render_template(template)

    username = clean_line(request.form.get("username"), 64)
    password = (request.form.get("password") or "")[:128]  # cap length: hashing huge inputs is slow

    if is_rate_limited(username):
        audit("login_rate_limited", None, f"user={username}")
        response = current_app.make_response(render_template(
            template, error="Too many failed attempts. Please wait 15 minutes and try again."))
        response.status_code = 429
        response.headers["Retry-After"] = str(current_app.config["LOGIN_WINDOW_SECONDS"])
        return response

    user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    stored_hash = user["password_hash"] if user else _dummy_password_hash()
    password_ok = check_password_hash(stored_hash, password)

    if not (user and password_ok and user["is_active"] and user["role"] == required_role):
        record_failed_login(username)
        audit("login_failed", user["id"] if user else None, f"user={username}")
        return render_template(template, error=GENERIC_LOGIN_ERROR, username=username)

    # Success. Start a brand-new session so any pre-login session id/token is discarded
    # (prevents session fixation).
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    clear_failed_logins(username)
    audit("login_success", user["id"], f"role={user['role']}")
    flash("Signed in successfully.", "success")
    return redirect(url_for(home_endpoint))


@bp.route("/login", methods=["GET", "POST"])
def login():
    return _login("student", "auth/login.html", "student.dashboard")


@bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return _login("admin", "auth/admin_login.html", "admin.dashboard")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("public.home"))
    if request.method == "GET":
        return render_template("auth/register.html", form={}, errors={})

    form = {
        "full_name": clean_line(request.form.get("full_name"), 80),
        "username": clean_line(request.form.get("username"), 30),
        "email": clean_line(request.form.get("email"), 254),
    }
    password = (request.form.get("password") or "")[:128]
    confirm = (request.form.get("confirm_password") or "")[:128]

    errors = {}
    if err := validate_full_name(form["full_name"]):
        errors["full_name"] = err
    if not USERNAME_RE.match(form["username"]):
        errors["username"] = "Username must be 3-30 characters: letters, numbers and underscores."
    if not EMAIL_RE.match(form["email"]):
        errors["email"] = "Enter a valid email address."
    if err := validate_password(password, form["username"]):
        errors["password"] = err
    elif password != confirm:
        errors["confirm_password"] = "The two passwords do not match."

    if errors:
        return render_template("auth/register.html", form=form, errors=errors), 400

    db = get_db()
    try:
        with db:  # one transaction: both rows are saved, or neither
            cur = db.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'student')",
                (form["username"], form["email"], hash_password(password)),
            )
            user_id = cur.lastrowid
            cur = db.execute(
                "INSERT INTO students (user_id, full_name) VALUES (?, ?)",
                (user_id, form["full_name"]),
            )
            student_id = cur.lastrowid
            db.execute(
                "UPDATE students SET student_code = ? WHERE id = ?",
                (f"SSP{date.today().year}{student_id:04d}", student_id),
            )
    except sqlite3.IntegrityError:
        errors["username"] = "That username or email address is already registered."
        return render_template("auth/register.html", form=form, errors=errors), 400

    audit("register", user_id, f"user={form['username']}")
    flash("Account created. You can sign in now.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/logout", methods=["POST"])  # POST + CSRF token: a stray link cannot log you out
def logout():
    if g.user is not None:
        audit("logout", g.user["id"])
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("public.home"))


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("auth/change_password.html", errors={})

    current = (request.form.get("current_password") or "")[:128]
    new = (request.form.get("new_password") or "")[:128]
    confirm = (request.form.get("confirm_password") or "")[:128]

    errors = {}
    if not check_password_hash(g.user["password_hash"], current):
        errors["current_password"] = "Your current password is not correct."
    elif err := validate_password(new, g.user["username"]):
        errors["new_password"] = err
    elif new != confirm:
        errors["confirm_password"] = "The two passwords do not match."
    if errors:
        audit("password_change_failed", g.user["id"])
        return render_template("auth/change_password.html", errors=errors), 400

    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), g.user["id"]))
    db.commit()
    user_id = g.user["id"]
    session.clear()                      # force a fresh sign-in with the new password
    audit("password_changed", user_id)
    flash("Password changed. Please sign in again.", "success")
    return redirect(url_for("auth.login"))
