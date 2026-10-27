"""
app.py - builds and runs the Student Security Portal.

Run it:            python app.py
Or with Flask CLI: flask --app app run
Set up database:   flask --app app init-db
Create an admin:   flask --app app create-admin
Demo students:     flask --app app seed-demo
"""
import logging
from datetime import date
from logging.handlers import RotatingFileHandler
from pathlib import Path

import click
from flask import Flask, g, render_template, session
from werkzeug.exceptions import HTTPException

import admin
import auth
import public
import student
from config import get_config
from database import close_db, get_db, init_db
from security import (EMAIL_RE, USERNAME_RE, add_security_headers, check_csrf, csrf_token,
                      validate_password)

# Plain-language text for each error page. Deliberately vague: no stack traces,
# file paths, SQL or library versions are ever shown to the visitor.
ERROR_TEXT = {
    400: ("Request could not be verified",
          "Go back, reload the page and try again. Forms expire when you sign out or your session ends."),
    403: ("Access denied", "Your account does not have permission to open this page."),
    404: ("Page not found", "The page you asked for does not exist."),
    405: ("Method not allowed", "That action is not available on this page."),
    413: ("Request too large", "The data you sent was too large."),
    429: ("Too many requests", "Please wait a few minutes and try again."),
    500: ("Something went wrong", "An unexpected error happened. It has been logged. Please try again later."),
}


def create_app(config_name=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config(config_name))

    # Refuse to start with a missing or weak secret. The secret signs session cookies;
    # anyone who knows it can forge a login.
    key = app.config.get("SECRET_KEY")
    if not key or len(key) < 32:
        raise RuntimeError(
            "SECRET_KEY is missing or shorter than 32 characters. Copy .env.example to .env and "
            "set SECRET_KEY to the output of: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    _configure_logging(app)

    app.teardown_appcontext(close_db)
    app.before_request(load_current_user)
    app.before_request(check_csrf)
    app.after_request(add_security_headers)

    @app.context_processor
    def template_globals():
        return {"csrf_token": csrf_token, "app_name": "Student Security Portal",
                "current_year": date.today().year}

    for module in (public, auth, student, admin):
        app.register_blueprint(module.bp)

    _register_error_handlers(app)
    _register_cli(app)
    return app


def load_current_user():
    """Decide who is making this request. The role is re-read from the database every
    time, so disabling an account or changing a role takes effect immediately."""
    from flask import request
    g.user = None
    if request.endpoint == "static":
        return
    user_id = session.get("user_id")
    if user_id is not None:
        user = get_db().execute(
            "SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)).fetchone()
        if user is None:
            session.clear()
        else:
            g.user = user


def _configure_logging(app):
    if app.config["TESTING"]:
        return
    log_path = Path(app.instance_path) / "app.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_path, maxBytes=512_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def _register_error_handlers(app):
    def show(code):
        title, message = ERROR_TEXT.get(code, ERROR_TEXT[500])
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return show(error.code or 500)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        # Full details go to the server log only; the visitor gets the generic page.
        app.logger.exception("Unhandled exception")
        return show(500)


def _register_cli(app):
    @app.cli.command("init-db")
    def init_db_command():
        """Create the database tables."""
        init_db()
        click.echo(f"Database ready: {app.config['DATABASE']}")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def create_admin_command(username, email, password):
        """Create an admin account. The password is typed at a hidden prompt."""
        from auth import hash_password
        if not USERNAME_RE.match(username):
            raise click.ClickException("Username must be 3-30 letters, numbers or underscores.")
        if not EMAIL_RE.match(email):
            raise click.ClickException("That email address does not look valid.")
        if err := validate_password(password, username):
            raise click.ClickException(err)
        init_db()
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (username, email, hash_password(password)))
            db.commit()
        except Exception:
            raise click.ClickException("That username or email already exists.")
        click.echo(f"Admin '{username}' created. Sign in at /admin/login")

    @app.cli.command("seed-demo")
    @click.option("--password", prompt="Password to give ALL demo students", hide_input=True,
                  confirmation_prompt=True)
    def seed_demo_command(password):
        """Add fictional demo students and notices (handy for access-control testing)."""
        from auth import hash_password
        if err := validate_password(password):
            raise click.ClickException(err)
        init_db()
        db = get_db()
        demo = [
            ("Aarav Sharma", "aarav_demo", 92.5, [91, 88, 95, 84, 90]),
            ("Diya Patel", "diya_demo", 78.0, [72, 80, 69, 77, 85]),
            ("Kabir Nair", "kabir_demo", 64.5, [58, 63, 71, 60, 66]),
            ("Meera Iyer", "meera_demo", 88.0, [89, 93, 87, 90, 82]),
            ("Rohan Desai", "rohan_demo", 71.0, [75, 68, 74, 70, 79]),
        ]
        subjects = ["Web Technologies", "Python Programming", "Database Management",
                    "Computer Networks", "Cyber Security Basics"]
        created = 0
        password_hash = hash_password(password)
        for i, (name, username, attendance, scores) in enumerate(demo, start=1):
            if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                continue
            with db:
                uid = db.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'student')",
                    (username, f"{username}@example.test", password_hash)).lastrowid
                sid = db.execute(
                    "INSERT INTO students (user_id, full_name, phone, address, attendance_pct) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (uid, name, f"900000000{i}", f"{i} Sample Street, Fictional City",
                     attendance)).lastrowid
                db.execute("UPDATE students SET student_code = ? WHERE id = ?",
                           (f"SSP{date.today().year}{sid:04d}", sid))
                for subject, score in zip(subjects, scores):
                    db.execute("INSERT INTO marks (student_id, subject, score) VALUES (?, ?, ?)",
                               (sid, subject, score))
            created += 1
        if not db.execute("SELECT 1 FROM notices LIMIT 1").fetchone():
            db.executemany("INSERT INTO notices (title, body) VALUES (?, ?)", [
                ("Welcome to the portal", "This is a fictional notice for the demo environment."),
                ("Practical exams", "Practical exam timetable will be shared by the department soon."),
            ])
            db.commit()
        click.echo(f"Added {created} fictional demo student(s). All use the password you just typed.")


if __name__ == "__main__":
    application = create_app()
    # 127.0.0.1 = reachable only from this computer. Do not change this to 0.0.0.0.
    application.run(host="127.0.0.1", port=5000, debug=application.config["DEBUG"])
