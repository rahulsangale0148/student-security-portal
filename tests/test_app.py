"""
Automated tests for the Student Security Portal.

Run from the project folder:   python -m unittest discover -s tests -v

Every test gets its own temporary database file, so your real development data in
instance/portal.sqlite3 is never touched.
"""
import os
import re
import shutil
import sqlite3
import tempfile
import unittest

from werkzeug.security import check_password_hash

import config
from app import create_app
from auth import GENERIC_LOGIN_ERROR, hash_password
from database import init_db

PASSWORD = "Str0ngPass99"
ADMIN_PASSWORD = "Adm1nPass1234"


def extract_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token found in page"
    return match.group(1)


class PortalTestCase(unittest.TestCase):
    """Creates a fresh app + empty temp database for every test."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.sqlite3")
        self.app = create_app("testing")
        self.app.config["DATABASE"] = self.db_path
        with self.app.app_context():
            init_db()
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ---- helpers -----------------------------------------------------------
    def sql(self, query, params=()):
        """Run a query directly against the test database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(query, params).fetchall()
            conn.commit()
            return rows
        finally:
            conn.close()

    def token(self, client, path="/login"):
        return extract_token(client.get(path).get_data(as_text=True))

    def register(self, client, username="alice", full_name="Alice Fictional", password=PASSWORD,
                 email=None, confirm=None):
        return client.post("/register", data={
            "csrf_token": self.token(client, "/register"),
            "full_name": full_name, "username": username,
            "email": email or f"{username}@example.test",
            "password": password, "confirm_password": confirm if confirm is not None else password,
        })

    def login(self, client, username="alice", password=PASSWORD, path="/login"):
        return client.post(path, data={
            "csrf_token": self.token(client, path), "username": username, "password": password})

    def make_student(self, username="alice", full_name="Alice Fictional"):
        client = self.app.test_client()
        self.register(client, username, full_name)
        self.login(client, username)
        return client

    def make_admin(self, username="boss"):
        with self.app.app_context():
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (username, f"{username}@example.test", hash_password(ADMIN_PASSWORD)))
            conn.commit()
            conn.close()
        client = self.app.test_client()
        self.login(client, username, ADMIN_PASSWORD, path="/admin/login")
        return client


# ============================================================ Registration & login
class RegistrationTests(PortalTestCase):
    def test_register_creates_student_with_student_id(self):
        response = self.register(self.app.test_client())
        self.assertEqual(response.status_code, 302)
        row = self.sql("SELECT s.student_code, u.role FROM students s JOIN users u ON u.id = s.user_id")[0]
        self.assertTrue(re.fullmatch(r"SSP\d{4}\d{4}", row["student_code"]))
        self.assertEqual(row["role"], "student")

    def test_duplicate_username_rejected(self):
        self.register(self.app.test_client())
        response = self.register(self.app.test_client(), email="other@example.test")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.sql("SELECT id FROM users")), 1)

    def test_weak_passwords_rejected(self):
        for bad in ("short1", "alllettersnodigits", "1234567890123", "password123"):
            response = self.register(self.app.test_client(), username="bob", password=bad)
            self.assertEqual(response.status_code, 400, bad)
        self.assertEqual(len(self.sql("SELECT id FROM users")), 0)

    def test_password_containing_username_rejected(self):
        response = self.register(self.app.test_client(), username="alice", password="alice12345678")
        self.assertEqual(response.status_code, 400)

    def test_password_mismatch_rejected(self):
        response = self.register(self.app.test_client(), confirm="Different1234")
        self.assertEqual(response.status_code, 400)

    def test_invalid_username_email_and_name_rejected(self):
        c = self.app.test_client()
        self.assertEqual(self.register(c, username="bad name!").status_code, 400)
        self.assertEqual(self.register(c, username="okname", email="not-an-email").status_code, 400)
        self.assertEqual(self.register(c, username="okname2", full_name="<script>alert(1)</script>").status_code, 400)
        self.assertEqual(len(self.sql("SELECT id FROM users")), 0)

    def test_cannot_register_as_admin_by_adding_role_field(self):
        c = self.app.test_client()
        c.post("/register", data={
            "csrf_token": self.token(c, "/register"), "full_name": "Eve Fictional", "username": "eve",
            "email": "eve@example.test", "password": PASSWORD, "confirm_password": PASSWORD,
            "role": "admin", "is_active": "1"})
        self.assertEqual(self.sql("SELECT role FROM users WHERE username = 'eve'")[0]["role"], "student")


class LoginTests(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.register(self.app.test_client())

    def test_valid_login_reaches_dashboard(self):
        c = self.app.test_client()
        response = self.login(c)
        self.assertEqual(response.status_code, 302)
        page = c.get("/student/dashboard")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Alice Fictional", page.data)

    def test_wrong_password_and_unknown_user_give_identical_error(self):
        wrong_pw = self.login(self.app.test_client(), "alice", "Wrong-password-1")
        unknown = self.login(self.app.test_client(), "nobody", "Wrong-password-1")
        for response in (wrong_pw, unknown):
            self.assertEqual(response.status_code, 200)
            self.assertIn(GENERIC_LOGIN_ERROR.encode(), response.data)
        # The only difference allowed is the echoed username field.
        strip = lambda r, name: r.get_data(as_text=True).replace(name, "X")
        strip_token = lambda t: re.sub(r'value="[A-Za-z0-9_\-]{40,}"', 'value="T"', t)
        self.assertEqual(strip_token(strip(wrong_pw, "alice")), strip_token(strip(unknown, "nobody")))

    def test_disabled_account_cannot_login_and_gets_generic_error(self):
        self.sql("UPDATE users SET is_active = 0 WHERE username = 'alice'")
        response = self.login(self.app.test_client())
        self.assertIn(GENERIC_LOGIN_ERROR.encode(), response.data)

    def test_disabled_account_loses_existing_session(self):
        c = self.app.test_client()
        self.login(c)
        self.assertEqual(c.get("/student/dashboard").status_code, 200)
        self.sql("UPDATE users SET is_active = 0 WHERE username = 'alice'")
        self.assertEqual(c.get("/student/dashboard").status_code, 302)

    def test_logout_ends_session(self):
        c = self.app.test_client()
        self.login(c)
        response = c.post("/logout", data={"csrf_token": self.token(c, "/student/dashboard")})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(c.get("/student/dashboard").status_code, 302)

    def test_logout_requires_post(self):
        c = self.app.test_client()
        self.login(c)
        self.assertEqual(c.get("/logout").status_code, 405)

    def test_student_cannot_use_admin_login(self):
        c = self.app.test_client()
        response = self.login(c, path="/admin/login")
        self.assertIn(GENERIC_LOGIN_ERROR.encode(), response.data)
        self.assertEqual(c.get("/admin/").status_code, 302)

    def test_session_is_replaced_at_login(self):
        c = self.app.test_client()
        before = self.token(c, "/login")          # token issued to the anonymous session
        c.post("/login", data={"csrf_token": before, "username": "alice", "password": PASSWORD})
        after = self.token(c, "/student/dashboard")
        self.assertNotEqual(before, after)

    def test_change_password_requires_current_password(self):
        c = self.app.test_client()
        self.login(c)
        bad = c.post("/account/password", data={
            "csrf_token": self.token(c, "/account/password"), "current_password": "Nope-nope-123",
            "new_password": "NewPassw0rd99", "confirm_password": "NewPassw0rd99"})
        self.assertEqual(bad.status_code, 400)
        good = c.post("/account/password", data={
            "csrf_token": self.token(c, "/account/password"), "current_password": PASSWORD,
            "new_password": "NewPassw0rd99", "confirm_password": "NewPassw0rd99"})
        self.assertEqual(good.status_code, 302)
        self.assertEqual(c.get("/student/dashboard").status_code, 302)  # signed out
        self.assertEqual(self.login(self.app.test_client(), password="NewPassw0rd99").status_code, 302)


class RateLimitTests(PortalTestCase):
    def test_login_blocked_after_repeated_failures_even_with_correct_password(self):
        self.register(self.app.test_client())
        limit = self.app.config["LOGIN_MAX_ATTEMPTS"]
        c = self.app.test_client()
        for _ in range(limit):
            self.assertEqual(self.login(c, password="Wrong-password-1").status_code, 200)
        blocked = self.login(c, password=PASSWORD)           # correct password, still refused
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Retry-After", blocked.headers)
        self.assertEqual(c.get("/student/dashboard").status_code, 302)

    def test_failures_are_logged(self):
        c = self.app.test_client()
        self.login(c, "ghost", "Wrong-password-1")
        events = [r["event"] for r in self.sql("SELECT event FROM audit_log")]
        self.assertIn("login_failed", events)


# ====================================================================== Passwords
class PasswordHashingTests(PortalTestCase):
    def test_password_is_hashed_and_salted(self):
        self.register(self.app.test_client())
        stored = self.sql("SELECT password_hash FROM users")[0]["password_hash"]
        self.assertNotIn(PASSWORD, stored)
        self.assertRegex(stored, r"^(scrypt|pbkdf2):")
        self.assertTrue(check_password_hash(stored, PASSWORD))
        self.assertFalse(check_password_hash(stored, "wrong"))

    def test_same_password_gives_different_hashes(self):
        self.register(self.app.test_client(), "alice")
        self.register(self.app.test_client(), "carol", "Carol Fictional")
        hashes = [r["password_hash"] for r in self.sql("SELECT password_hash FROM users")]
        self.assertEqual(len(set(hashes)), 2)

    def test_no_plaintext_password_anywhere_in_database_file(self):
        self.register(self.app.test_client())
        with open(self.db_path, "rb") as fh:
            self.assertNotIn(PASSWORD.encode(), fh.read())


# ========================================================================== CSRF
class CsrfTests(PortalTestCase):
    def test_post_without_token_is_rejected(self):
        response = self.app.test_client().post("/register", data={
            "full_name": "No Token", "username": "notoken", "email": "n@example.test",
            "password": PASSWORD, "confirm_password": PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.sql("SELECT id FROM users")), 0)

    def test_post_with_wrong_token_is_rejected(self):
        c = self.app.test_client()
        c.get("/register")
        response = c.post("/register", data={"csrf_token": "forged", "username": "x"})
        self.assertEqual(response.status_code, 400)

    def test_token_from_another_session_is_rejected(self):
        victim_token = self.token(self.app.test_client(), "/register")
        attacker = self.app.test_client()
        attacker.get("/register")
        response = attacker.post("/register", data={"csrf_token": victim_token})
        self.assertEqual(response.status_code, 400)

    def test_login_post_without_token_is_rejected(self):
        self.register(self.app.test_client())
        response = self.app.test_client().post("/login", data={"username": "alice", "password": PASSWORD})
        self.assertEqual(response.status_code, 400)

    def test_profile_update_without_token_is_rejected(self):
        c = self.make_student()
        response = c.post("/student/profile", data={"full_name": "Hacked Name"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.sql("SELECT full_name FROM students")[0]["full_name"], "Alice Fictional")

    def test_admin_delete_without_token_is_rejected(self):
        self.make_student()
        admin = self.make_admin()
        response = admin.post("/admin/students/1/delete")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.sql("SELECT id FROM students")), 1)

    def test_token_header_is_also_accepted(self):
        c = self.app.test_client()
        token = self.token(c, "/register")
        response = c.post("/register", data={"username": "x"}, headers={"X-CSRFToken": token})
        self.assertEqual(response.status_code, 400)   # passes CSRF, fails normal validation
        self.assertNotIn(b"could not be verified", response.data)


# ============================================================ Access control
class AccessControlTests(PortalTestCase):
    ADMIN_URLS = ["/admin/", "/admin/students", "/admin/students/1", "/admin/notices", "/admin/audit"]

    def test_anonymous_users_are_sent_to_login(self):
        c = self.app.test_client()
        for url in ["/student/dashboard", "/student/profile", "/account/password"]:
            response = c.get(url)
            self.assertEqual(response.status_code, 302, url)
            self.assertIn("/login", response.headers["Location"])
        for url in self.ADMIN_URLS:
            response = c.get(url)
            self.assertEqual(response.status_code, 302, url)
            self.assertIn("/admin/login", response.headers["Location"])

    def test_students_cannot_open_admin_pages(self):
        student = self.make_student()
        for url in self.ADMIN_URLS:
            self.assertEqual(student.get(url).status_code, 403, url)

    def test_students_cannot_perform_admin_actions(self):
        student = self.make_student()
        token = self.token(student, "/student/dashboard")
        actions = ["/admin/students/1/delete", "/admin/students/1/toggle-active",
                   "/admin/students/1/edit", "/admin/students/1/marks", "/admin/notices"]
        for url in actions:
            response = student.post(url, data={"csrf_token": token, "title": "x", "body": "x"})
            self.assertEqual(response.status_code, 403, url)
        self.assertEqual(len(self.sql("SELECT id FROM students")), 1)

    def test_denied_access_is_audited(self):
        student = self.make_student()
        student.get("/admin/")
        self.assertIn("access_denied", [r["event"] for r in self.sql("SELECT event FROM audit_log")])

    def test_admin_can_open_admin_pages(self):
        self.make_student()
        admin = self.make_admin()
        for url in self.ADMIN_URLS:
            self.assertEqual(admin.get(url).status_code, 200, url)

    def test_admin_cannot_use_student_dashboard(self):
        admin = self.make_admin()
        self.assertEqual(admin.get("/student/dashboard").status_code, 403)

    def test_student_sees_only_their_own_record(self):
        alice = self.make_student("alice", "Alice Fictional")
        self.make_student("bobby", "Bobby Fictional")
        page = alice.get("/student/dashboard").get_data(as_text=True)
        self.assertIn("Alice Fictional", page)
        self.assertNotIn("Bobby Fictional", page)

    def test_query_parameters_cannot_select_another_student(self):
        alice = self.make_student("alice", "Alice Fictional")
        self.make_student("bobby", "Bobby Fictional")
        for url in ("/student/dashboard?id=2", "/student/dashboard?student_id=2", "/student/profile?user_id=2"):
            self.assertNotIn("Bobby Fictional", alice.get(url).get_data(as_text=True), url)

    def test_profile_update_ignores_protected_fields(self):
        c = self.make_student()
        self.sql("UPDATE students SET attendance_pct = 50 WHERE id = 1")
        c.post("/student/profile", data={
            "csrf_token": self.token(c, "/student/profile"), "full_name": "Alice Renamed",
            "phone": "9999999999", "address": "1 Test Road",
            "attendance_pct": "100", "student_code": "HACKED", "user_id": "99", "role": "admin"})
        row = self.sql("SELECT s.*, u.role FROM students s JOIN users u ON u.id = s.user_id")[0]
        self.assertEqual(row["full_name"], "Alice Renamed")
        self.assertEqual(row["attendance_pct"], 50)
        self.assertNotEqual(row["student_code"], "HACKED")
        self.assertEqual(row["role"], "student")

    def test_profile_validation_errors(self):
        c = self.make_student()
        response = c.post("/student/profile", data={
            "csrf_token": self.token(c, "/student/profile"), "full_name": "A",
            "phone": "abc", "address": "<script>"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.sql("SELECT full_name FROM students")[0]["full_name"], "Alice Fictional")


class AdminFeatureTests(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.make_student()
        self.admin = self.make_admin()

    def post(self, url, **data):
        data["csrf_token"] = self.token(self.admin, "/admin/students")
        return self.admin.post(url, data=data)

    def test_admin_edits_student_record(self):
        response = self.post("/admin/students/1/edit", full_name="Alice Edited", phone="9000000000",
                             address="2 Road", course="BCA", year_of_study="3", attendance_pct="81.5")
        self.assertEqual(response.status_code, 302)
        row = self.sql("SELECT * FROM students WHERE id = 1")[0]
        self.assertEqual((row["full_name"], row["attendance_pct"]), ("Alice Edited", 81.5))

    def test_admin_edit_rejects_bad_values(self):
        for bad in ({"attendance_pct": "150"}, {"attendance_pct": "nan"}, {"year_of_study": "9"},
                    {"course": "Hacking101"}, {"full_name": "<b>x</b>"}):
            data = dict(full_name="Alice Edited", phone="", address="", course="BCA",
                        year_of_study="3", attendance_pct="80")
            data.update(bad)
            self.assertEqual(self.post("/admin/students/1/edit", **data).status_code, 400, bad)
        self.assertEqual(self.sql("SELECT full_name FROM students")[0]["full_name"], "Alice Fictional")

    def test_admin_adds_and_removes_marks_and_student_sees_them(self):
        self.post("/admin/students/1/marks", subject="Python", score="88", max_score="100")
        self.assertEqual(len(self.sql("SELECT id FROM marks")), 1)
        student = self.app.test_client()
        self.login(student)
        self.assertIn(b"Python", student.get("/student/dashboard").data)
        self.post("/admin/students/1/marks/1/delete")
        self.assertEqual(len(self.sql("SELECT id FROM marks")), 0)

    def test_marks_higher_than_maximum_rejected(self):
        self.post("/admin/students/1/marks", subject="Python", score="120", max_score="100")
        self.assertEqual(len(self.sql("SELECT id FROM marks")), 0)

    def test_mark_cannot_be_deleted_through_wrong_student(self):
        self.post("/admin/students/1/marks", subject="Python", score="80", max_score="100")
        self.make_student("carol", "Carol Fictional")
        self.post("/admin/students/2/marks/1/delete")        # mark 1 belongs to student 1
        self.assertEqual(len(self.sql("SELECT id FROM marks")), 1)

    def test_admin_disables_account(self):
        self.post("/admin/students/1/toggle-active")
        self.assertEqual(self.sql("SELECT is_active FROM users WHERE username = 'alice'")[0]["is_active"], 0)
        self.assertIn(GENERIC_LOGIN_ERROR.encode(), self.login(self.app.test_client()).data)

    def test_admin_deletes_student(self):
        response = self.post("/admin/students/1/delete")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.sql("SELECT id FROM students"), [])
        self.assertEqual(self.sql("SELECT id FROM users WHERE username = 'alice'"), [])

    def test_unknown_student_gives_404(self):
        self.assertEqual(self.admin.get("/admin/students/999").status_code, 404)

    def test_admin_actions_are_audited(self):
        self.post("/admin/students/1/toggle-active")
        events = [r["event"] for r in self.sql("SELECT event FROM audit_log")]
        self.assertIn("admin_toggle_active", events)

    def test_admin_notice_appears_for_students(self):
        self.post("/admin/notices", title="Holiday", body="Campus closed Monday")
        student = self.app.test_client()
        self.login(student)
        page = student.get("/student/dashboard").get_data(as_text=True)
        self.assertIn("Holiday", page)


# ====================================================== Injection and XSS handling
class InjectionAndXssTests(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.make_student("alice", "Alice Fictional")
        self.make_student("bobby", "Bobby Fictional")
        self.admin = self.make_admin()

    def search(self, q):
        return self.admin.get("/admin/students", query_string={"q": q})

    def test_sql_injection_strings_in_search_return_nothing_and_do_not_error(self):
        for payload in ("' OR '1'='1", "' OR 1=1--", "x'; DROP TABLE students;--", '" OR ""="',
                        "' UNION SELECT username, password_hash, 1, 1, 1, 1, 1, 1, 1 FROM users--"):
            response = self.search(payload)
            self.assertEqual(response.status_code, 200, payload)
            page = response.get_data(as_text=True)
            self.assertNotIn("Alice Fictional", page, payload)
            self.assertNotIn("scrypt:", page, payload)
        self.assertEqual(len(self.sql("SELECT id FROM students")), 2)  # table still exists

    def test_search_wildcards_are_literal(self):
        page = self.search("%").get_data(as_text=True)
        self.assertNotIn("Alice Fictional", page)

    def test_normal_search_works(self):
        page = self.search("alice").get_data(as_text=True)
        self.assertIn("Alice Fictional", page)
        self.assertNotIn("Bobby Fictional", page)

    def test_sql_injection_in_login_does_not_bypass(self):
        c = self.app.test_client()
        response = self.login(c, "alice' OR '1'='1' --", "anything-1234")
        self.assertIn(GENERIC_LOGIN_ERROR.encode(), response.data)
        response = self.login(c, "admin'--", "x")
        self.assertIn(GENERIC_LOGIN_ERROR.encode(), response.data)

    def test_notice_html_is_escaped_on_output(self):
        payload = "<script>alert(1)</script>"
        self.admin.post("/admin/notices", data={
            "csrf_token": self.token(self.admin, "/admin/notices"), "title": "Test notice", "body": payload})
        for page in (self.admin.get("/admin/notices"),):
            text = page.get_data(as_text=True)
            self.assertNotIn(payload, text)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)
        student = self.app.test_client()
        self.login(student, "alice")
        text = student.get("/student/dashboard").get_data(as_text=True)
        self.assertNotIn(payload, text)

    def test_search_term_is_escaped_when_echoed(self):
        text = self.search('"><img src=x onerror=alert(1)>').get_data(as_text=True)
        self.assertNotIn("<img src=x", text)

    def test_username_echo_on_failed_login_is_escaped(self):
        c = self.app.test_client()
        text = self.login(c, '"><script>alert(1)</script>', "x").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", text)

    def test_audit_log_neutralises_newlines_and_markup(self):
        c = self.app.test_client()
        self.login(c, "fake\nINJECTED line <b>bold</b>", "x")
        detail = self.sql("SELECT detail FROM audit_log WHERE event = 'login_failed' ORDER BY id DESC")[0]["detail"]
        self.assertNotIn("\n", detail)
        page = self.admin.get("/admin/audit").get_data(as_text=True)
        self.assertNotIn("<b>bold</b>", page)


# =============================================== Configuration & security headers
class SecurityConfigurationTests(PortalTestCase):
    def test_secret_key_comes_from_environment_not_source(self):
        with open(config.__file__, encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn('os.environ.get("SECRET_KEY")', source)
        self.assertNotRegex(source, r"SECRET_KEY\s*=\s*[\"'][^\"']{8,}[\"']")

    def test_app_refuses_to_start_without_a_strong_secret(self):
        original = config.TestingConfig.SECRET_KEY
        try:
            for bad in (None, "", "too-short"):
                config.TestingConfig.SECRET_KEY = bad
                with self.assertRaises(RuntimeError):
                    create_app("testing")
        finally:
            config.TestingConfig.SECRET_KEY = original

    def test_debug_is_off_in_production_even_if_requested(self):
        os.environ["ENABLE_DEBUG"] = "1"
        try:
            self.assertFalse(config.ProductionConfig.DEBUG)
            self.assertTrue(config.ProductionConfig.SESSION_COOKIE_SECURE)
            self.assertTrue(config.ProductionConfig.HSTS_ENABLED)
        finally:
            del os.environ["ENABLE_DEBUG"]

    def test_default_config_has_debug_off(self):
        self.assertFalse(config.BaseConfig.DEBUG)
        self.assertFalse(self.app.config["DEBUG"])

    def test_session_cookie_flags(self):
        self.assertTrue(self.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(self.app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        c = self.app.test_client()
        cookie = c.get("/login").headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_security_headers_present(self):
        headers = self.app.test_client().get("/").headers
        csp = headers["Content-Security-Policy"]
        for directive in ("default-src 'self'", "script-src 'self'", "frame-ancestors 'none'",
                          "object-src 'none'", "form-action 'self'"):
            self.assertIn(directive, csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("Referrer-Policy", headers)
        self.assertIn("Permissions-Policy", headers)

    def test_signed_in_pages_are_not_cacheable(self):
        c = self.make_student()
        self.assertEqual(c.get("/student/dashboard").headers["Cache-Control"], "no-store")

    def test_templates_use_no_inline_script_or_style(self):
        c = self.make_student()
        for url in ("/", "/login", "/register", "/security-assessment", "/student/dashboard", "/student/profile"):
            html = c.get(url).get_data(as_text=True)
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)", url)
            self.assertNotRegex(html, r"\sstyle=", url)
            self.assertNotRegex(html, r"\son[a-z]+=", url)

    def test_no_external_resources_are_loaded(self):
        html = self.app.test_client().get("/").get_data(as_text=True)
        self.assertNotRegex(html, r"(src|href)=\"https?://")

    def test_oversized_request_rejected(self):
        c = self.app.test_client()
        response = c.post("/login", data={"csrf_token": "x", "username": "a" * 50000})
        self.assertEqual(response.status_code, 413)

    def test_error_pages_do_not_leak_details(self):
        response = self.app.test_client().get("/does-not-exist")
        self.assertEqual(response.status_code, 404)
        text = response.get_data(as_text=True)
        for leak in ("Traceback", "werkzeug", "Flask", "sqlite", ".py"):
            self.assertNotIn(leak, text)

    def test_unhandled_exception_returns_generic_500(self):
        app = create_app("testing")
        app.config["DATABASE"] = self.db_path
        app.config["PROPAGATE_EXCEPTIONS"] = False

        @app.route("/boom")
        def boom():
            raise ValueError("secret internal detail C:\\\\path\\\\app.py")

        with self.assertLogs(app.logger, level="ERROR"):
            response = app.test_client().get("/boom")
        self.assertEqual(response.status_code, 500)
        text = response.get_data(as_text=True)
        self.assertNotIn("secret internal detail", text)
        self.assertNotIn("Traceback", text)

    def test_no_default_credentials_exist(self):
        self.assertEqual(self.sql("SELECT id FROM users"), [])

    def test_wrong_http_method_is_rejected(self):
        self.assertEqual(self.app.test_client().get("/logout").status_code, 405)


class CommandLineTests(PortalTestCase):
    def test_create_admin_command_hashes_password(self):
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["create-admin", "--username", "rootuser", "--email", "root@example.test"],
                               input=f"{ADMIN_PASSWORD}\n{ADMIN_PASSWORD}\n")
        self.assertEqual(result.exit_code, 0, result.output)
        row = self.sql("SELECT role, password_hash FROM users WHERE username = 'rootuser'")[0]
        self.assertEqual(row["role"], "admin")
        self.assertNotIn(ADMIN_PASSWORD, row["password_hash"])
        self.assertTrue(check_password_hash(row["password_hash"], ADMIN_PASSWORD))
        c = self.app.test_client()
        self.assertEqual(self.login(c, "rootuser", ADMIN_PASSWORD, path="/admin/login").status_code, 302)

    def test_create_admin_rejects_weak_password(self):
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["create-admin", "--username", "rootuser", "--email", "root@example.test"],
                               input="short\nshort\n")
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(self.sql("SELECT id FROM users"), [])

    def test_seed_demo_adds_fictional_students_only(self):
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["seed-demo"], input=f"{PASSWORD}\n{PASSWORD}\n")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(self.sql("SELECT id FROM students")), 5)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM users WHERE email NOT LIKE '%@example.test'")[0]["n"], 0)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")[0]["n"], 0)


if __name__ == "__main__":
    unittest.main()
