"""
=====================================================================================
 SECURITY TRAINING LAB  -  DELIBERATELY VULNERABLE  -  LOCAL USE ONLY
=====================================================================================
This is NOT the Student Security Portal. It is a separate, throw-away application
with its own database (lab.sqlite3), its own port (5001) and fictional data.

Every exercise has two routes:
    .../vulnerable   a deliberately insecure version (labelled TRAINING-ONLY)
    .../fixed        the secure version of the same feature

Safety rails built into this file:
  * Refuses to run unless LAB_ENABLED=1 is set (disabled by default).
  * Only ever binds to 127.0.0.1 and rejects requests that do not come from loopback.
  * Never enables Flask debug mode.
  * Uses a random secret key generated at startup; nothing is hard-coded or reused
    from the main portal.
  * The database is rebuilt from scratch every time the lab starts.

Run (PowerShell, from the security-lab folder):
    $env:LAB_ENABLED = "1"
    python lab_app.py
"""
import hashlib
import os
import secrets
import sqlite3
import sys
import time
import traceback
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

LAB_DIR = Path(__file__).resolve().parent
DEFAULT_DB = LAB_DIR / "lab.sqlite3"
HOST, PORT = "127.0.0.1", 5001
LOOPBACK = {"127.0.0.1", "::1"}
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}

# Fictional lab-only accounts. These passwords protect nothing real; they exist so
# the authentication exercises have something to test against.
LAB_USERS = [
    ("lab_student1", "sunshine1", "student", "Lab Student One"),
    ("lab_student2", "sunshine1", "student", "Lab Student Two"),   # same password on purpose (A04)
    ("lab_admin", "labadmin-9X", "admin", "Lab Admin"),
]
LAB_STUDENTS = [("Aditi Rao", "BCA"), ("Karan Mehta", "BCA"), ("Neha Kulkarni", "BBA-CA"),
                ("Vikram Shah", "BSc-CS"), ("Isha Menon", "BCA")]
LAB_RECORDS = [  # (owner username, title, note)
    ("lab_student1", "Student1 private note", "LAB-DATA: this note belongs to lab_student1 only."),
    ("lab_student2", "Student2 private note", "LAB-DATA: this note belongs to lab_student2 only."),
    ("lab_admin", "Admin private note", "LAB-DATA: this note belongs to lab_admin only."),
]


# ------------------------------------------------------------------- database
def build_db(path):
    """Create a brand-new lab database with fictional data."""
    path = Path(path)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE lab_users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, display_name TEXT, role TEXT,
            password_md5 TEXT,            -- A04 TRAINING-ONLY: unsalted MD5
            password_hash TEXT);          -- the secure alternative (scrypt, salted)
        CREATE TABLE lab_students (id INTEGER PRIMARY KEY, name TEXT, course TEXT);
        CREATE TABLE lab_records (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, note TEXT);
        CREATE TABLE lab_attempts (username TEXT, at INTEGER);
    """)
    for username, password, role, display in LAB_USERS:
        conn.execute(
            "INSERT INTO lab_users (username, display_name, role, password_md5, password_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, display, role, hashlib.md5(password.encode()).hexdigest(),
             generate_password_hash(password)))
    conn.executemany("INSERT INTO lab_students (name, course) VALUES (?, ?)", LAB_STUDENTS)
    for owner, title, note in LAB_RECORDS:
        conn.execute("INSERT INTO lab_records (owner_id, title, note) "
                     "SELECT id, ?, ? FROM lab_users WHERE username = ?", (title, note, owner))
    conn.commit()
    conn.close()


def db():
    if "db" not in g:
        from flask import current_app
        g.db = sqlite3.connect(current_app.config["LAB_DB"])
        g.db.row_factory = sqlite3.Row
    return g.db


# ------------------------------------------------------------------ app factory
def create_lab_app(db_path=None, enabled=None):
    if enabled is None:
        enabled = os.environ.get("LAB_ENABLED") == "1"
    if not enabled:
        raise RuntimeError(
            "The security lab is DISABLED. It contains deliberately vulnerable code. "
            "To run it on your own computer, set LAB_ENABLED=1 (see security-lab/README.md).")

    app = Flask(__name__)
    app.config["LAB_DB"] = str(db_path or DEFAULT_DB)
    app.config["SECRET_KEY"] = secrets.token_hex(32)     # random per run, never stored
    app.config["DEBUG"] = False
    build_db(app.config["LAB_DB"])

    @app.teardown_appcontext
    def close(_exc=None):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.before_request
    def loopback_only():
        """Defence in depth: even if started on the wrong interface, refuse outsiders."""
        if request.remote_addr not in LOOPBACK:
            abort(403)
        if request.host.rsplit(":", 1)[0] not in ALLOWED_HOSTS and request.host not in ALLOWED_HOSTS:
            abort(400)  # blocks DNS-rebinding style requests

    @app.context_processor
    def inject():
        return {"lab_user": current_user()}

    register_routes(app)
    return app


def current_user():
    uid = session.get("lab_user_id")
    if uid is None:
        return None
    return db().execute("SELECT id, username, display_name, role FROM lab_users WHERE id = ?",
                        (uid,)).fetchone()


def page(title, owasp, kind, intro, **extra):
    """kind is 'vulnerable' or 'fixed'. Both are shown with a clear label."""
    return render_template("lab_page.html", title=title, owasp=owasp, kind=kind, intro=intro, **extra)


# ------------------------------------------------------------------------ routes
def register_routes(app):

    # ---- index and "act as" helper ------------------------------------------------
    @app.route("/")
    def index():
        return render_template("lab_index.html", exercises=EXERCISES)

    @app.route("/lab/session/<username>", methods=["POST"])
    def act_as(username):
        """Lab convenience: become a lab user without a password (needed for A01 exercises)."""
        row = db().execute("SELECT id FROM lab_users WHERE username = ?", (username,)).fetchone()
        if row is None:
            abort(404)
        session.clear()
        session["lab_user_id"] = row["id"]
        return redirect(url_for("index"))

    @app.route("/lab/session/end", methods=["POST"])
    def end_session():
        session.clear()
        return redirect(url_for("index"))

    # ======================================================== A05 Injection: SQL
    @app.route("/lab/injection/search/vulnerable")
    def sqli_search_vulnerable():
        q = request.args.get("q", "")
        # TRAINING-ONLY VULNERABILITY: user input is pasted into the SQL text.
        sql = f"SELECT id, name, course FROM lab_students WHERE name LIKE '%{q}%'"
        rows, error = None, None
        try:
            rows = db().execute(sql).fetchall()
        except sqlite3.Error as exc:
            error = f"SQL error: {exc}"           # also leaks internals (A10)
        return page("Student search", "A05 Injection (SQL)", "vulnerable",
                    "Search lab students by name. The query is built by string concatenation.",
                    form={"action": url_for("sqli_search_vulnerable"), "method": "get",
                          "fields": [{"name": "q", "label": "Name contains", "value": q}], "button": "Search"},
                    shown_sql=sql, error=error, table=_table(rows, ["id", "name", "course"]))

    @app.route("/lab/injection/search/fixed")
    def sqli_search_fixed():
        q = request.args.get("q", "")
        sql = "SELECT id, name, course FROM lab_students WHERE name LIKE ? ESCAPE '\\'"
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = db().execute(sql, (like,)).fetchall()      # FIX: parameterized query
        return page("Student search", "A05 Injection (SQL)", "fixed",
                    "Same feature, but the input is passed as a bound parameter.",
                    form={"action": url_for("sqli_search_fixed"), "method": "get",
                          "fields": [{"name": "q", "label": "Name contains", "value": q}], "button": "Search"},
                    shown_sql=sql, table=_table(rows, ["id", "name", "course"]))

    @app.route("/lab/injection/login/vulnerable", methods=["GET", "POST"])
    def sqli_login_vulnerable():
        result = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            digest = hashlib.md5(password.encode()).hexdigest()
            # TRAINING-ONLY VULNERABILITY: username is concatenated into the SQL.
            sql = f"SELECT id, username, role FROM lab_users WHERE username = '{username}' AND password_md5 = '{digest}'"
            try:
                row = db().execute(sql).fetchone()
                result = (f"Signed in as {row['username']} ({row['role']})" if row else "Login failed.")
            except sqlite3.Error as exc:
                result = f"SQL error: {exc}"
            return page("SQL login", "A05 Injection (SQL)", "vulnerable",
                        "A login form whose username goes straight into the query.",
                        form=_login_form("sqli_login_vulnerable"), shown_sql=sql, result=result)
        return page("SQL login", "A05 Injection (SQL)", "vulnerable",
                    "A login form whose username goes straight into the query.",
                    form=_login_form("sqli_login_vulnerable"))

    @app.route("/lab/injection/login/fixed", methods=["GET", "POST"])
    def sqli_login_fixed():
        result, sql = None, None
        if request.method == "POST":
            sql = "SELECT id, username, role, password_hash FROM lab_users WHERE username = ?"
            row = db().execute(sql, (request.form.get("username", ""),)).fetchone()
            ok = row is not None and check_password_hash(row["password_hash"], request.form.get("password", ""))
            result = f"Signed in as {row['username']} ({row['role']})" if ok else "Incorrect username or password."
        return page("SQL login", "A05 Injection (SQL)", "fixed",
                    "Parameterized query plus a salted password hash check.",
                    form=_login_form("sqli_login_fixed"), shown_sql=sql, result=result)

    # ================================================================ A05 XSS
    @app.route("/lab/xss/vulnerable")
    def xss_vulnerable():
        name = request.args.get("name", "")
        # TRAINING-ONLY VULNERABILITY: Markup() tells Jinja "this is already safe HTML".
        greeting = Markup(f"Hello, {name}!") if name else None
        return page("Greeting", "A05 Injection (reflected XSS)", "vulnerable",
                    "Reflects the name you send without escaping it.",
                    form={"action": url_for("xss_vulnerable"), "method": "get",
                          "fields": [{"name": "name", "label": "Your name", "value": name}], "button": "Greet me"},
                    result_html=greeting)

    @app.route("/lab/xss/fixed")
    def xss_fixed():
        name = request.args.get("name", "")
        return page("Greeting", "A05 Injection (reflected XSS)", "fixed",
                    "Same page; Jinja auto-escaping turns < and > into harmless text.",
                    form={"action": url_for("xss_fixed"), "method": "get",
                          "fields": [{"name": "name", "label": "Your name", "value": name}], "button": "Greet me"},
                    result=f"Hello, {name}!" if name else None)

    # ================================================ A01 Broken Access Control
    @app.route("/lab/access/records/<int:record_id>/vulnerable")
    def idor_vulnerable(record_id):
        if current_user() is None:
            return page("Private notes", "A01 Broken Access Control (IDOR)", "vulnerable",
                        "Use 'Act as' (top right) to sign in as a lab user first.", result="Not signed in.")
        # TRAINING-ONLY VULNERABILITY: logged in, but ownership is never checked.
        row = db().execute("SELECT id, title, note FROM lab_records WHERE id = ?", (record_id,)).fetchone()
        if row is None:
            abort(404)
        return page("Private notes", "A01 Broken Access Control (IDOR)", "vulnerable",
                    f"Record {record_id}. Change the number in the URL.",
                    table=_table([row], ["id", "title", "note"]))

    @app.route("/lab/access/records/<int:record_id>/fixed")
    def idor_fixed(record_id):
        user = current_user()
        if user is None:
            return page("Private notes", "A01 Broken Access Control (IDOR)", "fixed",
                        "Use 'Act as' (top right) to sign in as a lab user first.", result="Not signed in."), 401
        # FIX: the owner must match the signed-in user. A missing record and someone
        # else's record give the same 404, so ids cannot be probed.
        row = db().execute("SELECT id, title, note FROM lab_records WHERE id = ? AND owner_id = ?",
                           (record_id, user["id"])).fetchone()
        if row is None:
            abort(404)
        return page("Private notes", "A01 Broken Access Control (IDOR)", "fixed",
                    f"Record {record_id} (yours).", table=_table([row], ["id", "title", "note"]))

    @app.route("/lab/access/admin-panel/vulnerable")
    def admin_vulnerable():
        if current_user() is None:
            return page("Admin panel", "A01 Broken Access Control (missing role check)", "vulnerable",
                        "Use 'Act as' first.", result="Not signed in.")
        # TRAINING-ONLY VULNERABILITY: any signed-in user is allowed; role is never checked.
        rows = db().execute("SELECT id, username, role FROM lab_users").fetchall()
        return page("Admin panel", "A01 Broken Access Control (missing role check)", "vulnerable",
                    "Lists every lab account. Intended for admins only.",
                    table=_table(rows, ["id", "username", "role"]))

    @app.route("/lab/access/admin-panel/fixed")
    def admin_fixed():
        user = current_user()
        if user is None:
            return page("Admin panel", "A01 Broken Access Control (missing role check)", "fixed",
                        "Use 'Act as' first.", result="Not signed in."), 401
        if user["role"] != "admin":                      # FIX: server-side role check
            abort(403)
        rows = db().execute("SELECT id, username, role FROM lab_users").fetchall()
        return page("Admin panel", "A01 Broken Access Control (missing role check)", "fixed",
                    "Same page with a server-side role check.", table=_table(rows, ["id", "username", "role"]))

    # ============================================= A07 Authentication Failures
    @app.route("/lab/auth/login/vulnerable", methods=["GET", "POST"])
    def auth_vulnerable():
        result = None
        if request.method == "POST":
            username = request.form.get("username", "")
            row = db().execute("SELECT * FROM lab_users WHERE username = ?", (username,)).fetchone()
            if row is None:
                result = "No account with that username."            # TRAINING-ONLY: user enumeration
            elif hashlib.md5(request.form.get("password", "").encode()).hexdigest() != row["password_md5"]:
                result = "Wrong password for that account."           # different message again
            else:
                session["lab_user_id"] = row["id"]
                result = f"Welcome {row['username']}."
            # TRAINING-ONLY: no attempt limit at all.
        return page("Login", "A07 Authentication Failures", "vulnerable",
                    "Compare the messages for a real and a fake username. Try many wrong passwords.",
                    form=_login_form("auth_vulnerable"), result=result)

    @app.route("/lab/auth/login/fixed", methods=["GET", "POST"])
    def auth_fixed():
        result, status = None, 200
        if request.method == "POST":
            username = request.form.get("username", "")[:64]
            now = int(time.time())
            conn = db()
            conn.execute("DELETE FROM lab_attempts WHERE at < ?", (now - 300,))
            recent = conn.execute("SELECT COUNT(*) AS n FROM lab_attempts WHERE username = ?",
                                  (username.lower(),)).fetchone()["n"]
            if recent >= 5:                                           # FIX: throttle
                result, status = "Too many attempts. Wait 5 minutes.", 429
            else:
                row = conn.execute("SELECT * FROM lab_users WHERE username = ?", (username,)).fetchone()
                stored = row["password_hash"] if row else generate_password_hash("dummy-value")
                ok = check_password_hash(stored, request.form.get("password", "")[:128]) and row is not None
                if ok:
                    session.clear()
                    session["lab_user_id"] = row["id"]
                    result = f"Welcome {row['username']}."
                else:
                    conn.execute("INSERT INTO lab_attempts (username, at) VALUES (?, ?)", (username.lower(), now))
                    conn.commit()
                    result = "Incorrect username or password."        # FIX: one generic message
        return page("Login", "A07 Authentication Failures", "fixed",
                    "One generic message, salted hashes and a 5-attempt limit.",
                    form=_login_form("auth_fixed"), result=result), status

    # ============================================== A04 Cryptographic Failures
    @app.route("/lab/crypto/vulnerable")
    def crypto_vulnerable():
        rows = db().execute("SELECT username, password_md5 AS stored_value FROM lab_users").fetchall()
        return page("Stored passwords", "A04 Cryptographic Failures", "vulnerable",
                    "Unsalted MD5. Look at lab_student1 and lab_student2: identical hashes reveal identical passwords, "
                    "and MD5 is fast to brute-force.",
                    table=_table(rows, ["username", "stored_value"]))

    @app.route("/lab/crypto/fixed")
    def crypto_fixed():
        rows = db().execute("SELECT username, password_hash AS stored_value FROM lab_users").fetchall()
        shown = [{"username": r["username"], "stored_value": r["stored_value"][:40] + "..."} for r in rows]
        return page("Stored passwords", "A04 Cryptographic Failures", "fixed",
                    "Salted scrypt. The same password produces different stored values.",
                    table={"columns": ["username", "stored_value"], "rows": [[r["username"], r["stored_value"]] for r in shown]})

    # ================================================ A02 Security Misconfiguration
    @app.route("/lab/misconfig/vulnerable")
    def misconfig_vulnerable():
        response = app.make_response(page(
            "Server information", "A02 Security Misconfiguration", "vulnerable",
            "Check the response headers in Burp, then open /lab/misconfig/config-dump.",
            result="This response has no security headers and advertises internals."))
        # TRAINING-ONLY: verbose banner, wildcard CORS, no CSP / frame / sniffing protection.
        response.headers["Server"] = "LabServer/0.1 (debug build)"
        response.headers["X-Powered-By"] = "Flask on Python " + sys.version.split()[0]
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    @app.route("/lab/misconfig/config-dump")
    def misconfig_dump():
        # TRAINING-ONLY: exposes configuration, including the (random, per-run) secret key.
        rows = [[k, str(v)] for k, v in sorted(app.config.items()) if k in ("SECRET_KEY", "DEBUG", "LAB_DB")]
        return page("Configuration dump", "A02 Security Misconfiguration", "vulnerable",
                    "A forgotten diagnostics page. The secret key signs session cookies.",
                    table={"columns": ["setting", "value"], "rows": rows})

    @app.route("/lab/misconfig/fixed")
    def misconfig_fixed():
        response = app.make_response(page(
            "Server information", "A02 Security Misconfiguration", "fixed",
            "Security headers present, no version banner, no diagnostics page.",
            result="Compare the headers with the vulnerable version."))
        h = response.headers
        h["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "same-origin"
        h["Cache-Control"] = "no-store"
        return response

    # ============================== A10 Mishandling of Exceptional Conditions
    @app.route("/lab/errors/divide/vulnerable")
    def errors_vulnerable():
        divisor = request.args.get("divisor", "1")
        try:
            result = f"100 / {divisor} = {100 / int(divisor)}"
        except Exception:
            # TRAINING-ONLY VULNERABILITY: the stack trace (file paths, code) goes to the visitor.
            return page("Calculator", "A10 Mishandling of Exceptional Conditions", "vulnerable",
                        "Try 0 and then abc as the divisor.",
                        form=_divisor_form("errors_vulnerable", divisor),
                        result=traceback.format_exc()), 500
        return page("Calculator", "A10 Mishandling of Exceptional Conditions", "vulnerable",
                    "Try 0 and then abc as the divisor.", form=_divisor_form("errors_vulnerable", divisor),
                    result=result)

    @app.route("/lab/errors/divide/fixed")
    def errors_fixed():
        divisor = request.args.get("divisor", "1")
        try:
            value = int(divisor)
            if value == 0:
                raise ZeroDivisionError
            result, status = f"100 / {value} = {100 / value}", 200
        except (ValueError, ZeroDivisionError):
            # FIX: validate input, return a generic message, keep details in the server log.
            ref = secrets.token_hex(4)
            app.logger.warning("calculator rejected input (ref %s)", ref)
            result, status = f"Enter a whole number other than zero. (Reference {ref})", 400
        return page("Calculator", "A10 Mishandling of Exceptional Conditions", "fixed",
                    "Input is validated and errors are generic.", form=_divisor_form("errors_fixed", divisor),
                    result=result), status

    @app.route("/lab/errors/fail-open/vulnerable")
    def failopen_vulnerable():
        level = request.args.get("clearance", "")
        try:
            allowed = int(level) >= 5
        except Exception:
            allowed = True       # TRAINING-ONLY VULNERABILITY: failing OPEN. An error grants access.
        return page("Restricted report", "A10 Mishandling of Exceptional Conditions (fail-open)", "vulnerable",
                    "Needs clearance 5 or higher. Try 1, 7, and then something that is not a number.",
                    form={"action": url_for("failopen_vulnerable"), "method": "get",
                          "fields": [{"name": "clearance", "label": "Clearance level", "value": level}], "button": "Open report"},
                    result="ACCESS GRANTED: restricted lab report." if allowed else "Access denied.")

    @app.route("/lab/errors/fail-open/fixed")
    def failopen_fixed():
        level = request.args.get("clearance", "")
        try:
            allowed = int(level) >= 5
        except ValueError:
            allowed = False      # FIX: fail CLOSED. Anything unexpected means "no".
        return page("Restricted report", "A10 Mishandling of Exceptional Conditions (fail-open)", "fixed",
                    "Same check; an unreadable value denies access.",
                    form={"action": url_for("failopen_fixed"), "method": "get",
                          "fields": [{"name": "clearance", "label": "Clearance level", "value": level}], "button": "Open report"},
                    result="ACCESS GRANTED: restricted lab report." if allowed else "Access denied.")


# ------------------------------------------------------------------------ helpers
def _table(rows, columns):
    if rows is None:
        return None
    return {"columns": columns, "rows": [[r[c] for c in columns] for r in rows]}


def _login_form(endpoint):
    return {"action": url_for(endpoint), "method": "post", "button": "Sign in",
            "fields": [{"name": "username", "label": "Username", "value": ""},
                       {"name": "password", "label": "Password", "value": "", "type": "password"}]}


def _divisor_form(endpoint, value):
    return {"action": url_for(endpoint), "method": "get", "button": "Calculate",
            "fields": [{"name": "divisor", "label": "Divide 100 by", "value": value}]}


# Index page content: (OWASP id, topic, vulnerable endpoint, fixed endpoint)
EXERCISES = [
    ("A01", "IDOR: other users' private notes", "idor_vulnerable", "idor_fixed", {"record_id": 1}),
    ("A01", "Missing role check on admin panel", "admin_vulnerable", "admin_fixed", {}),
    ("A02", "Verbose headers and config dump", "misconfig_vulnerable", "misconfig_fixed", {}),
    ("A04", "Unsalted MD5 password storage", "crypto_vulnerable", "crypto_fixed", {}),
    ("A05", "SQL injection in a search box", "sqli_search_vulnerable", "sqli_search_fixed", {}),
    ("A05", "SQL injection in a login form", "sqli_login_vulnerable", "sqli_login_fixed", {}),
    ("A05", "Reflected cross-site scripting", "xss_vulnerable", "xss_fixed", {}),
    ("A07", "Account enumeration and no throttling", "auth_vulnerable", "auth_fixed", {}),
    ("A10", "Stack trace shown to visitors", "errors_vulnerable", "errors_fixed", {}),
    ("A10", "Failing open on an error", "failopen_vulnerable", "failopen_fixed", {}),
]


if __name__ == "__main__":
    try:
        lab = create_lab_app()
    except RuntimeError as exc:
        print(f"\n{exc}\n")
        sys.exit(1)
    print(f"Security lab running at http://{HOST}:{PORT}  (local only, deliberately vulnerable)")
    lab.run(host=HOST, port=PORT, debug=False)   # host/debug are fixed on purpose
