"""
Tests for the SECURITY LAB (not the main portal).

They do two jobs:
  1. Prove the lab's safety rails work (disabled by default, loopback only, own database).
  2. Demonstrate, for every exercise, that the VULNERABLE route really shows the
     weakness and the FIXED route does not. A weakness is only claimed in the lab
     README because one of these tests observed it.

Run from the security-lab folder:   python -m unittest discover -s tests -v
"""
import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import lab_app  # noqa: E402


class LabTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "lab-test.sqlite3")
        self.app = lab_app.create_lab_app(db_path=self.db_path, enabled=True)
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def text(self, url, **kw):
        return self.client.get(url, **kw).get_data(as_text=True)

    def act_as(self, username):
        self.client.post(f"/lab/session/{username}")


class SafetyRailTests(LabTestCase):
    def test_lab_is_disabled_by_default(self):
        old = os.environ.pop("LAB_ENABLED", None)
        try:
            with self.assertRaises(RuntimeError):
                lab_app.create_lab_app(db_path=self.db_path)
            os.environ["LAB_ENABLED"] = "0"
            with self.assertRaises(RuntimeError):
                lab_app.create_lab_app(db_path=self.db_path)
        finally:
            os.environ.pop("LAB_ENABLED", None)
            if old is not None:
                os.environ["LAB_ENABLED"] = old

    def test_lab_uses_its_own_database_not_the_portal_one(self):
        portal_db = Path(lab_app.LAB_DIR).parent / "instance" / "portal.sqlite3"
        self.assertNotEqual(Path(self.app.config["LAB_DB"]).resolve(), portal_db.resolve())
        self.assertEqual(lab_app.DEFAULT_DB.name, "lab.sqlite3")

    def test_binds_only_to_loopback_and_debug_is_off(self):
        self.assertEqual(lab_app.HOST, "127.0.0.1")
        self.assertFalse(self.app.config["DEBUG"])

    def test_non_loopback_clients_are_refused(self):
        response = self.client.get("/", environ_overrides={"REMOTE_ADDR": "192.168.1.50"})
        self.assertEqual(response.status_code, 403)

    def test_foreign_host_header_is_refused(self):
        response = self.client.get("/", headers={"Host": "evil.example"})
        self.assertEqual(response.status_code, 400)

    def test_secret_key_is_random_per_start(self):
        other = lab_app.create_lab_app(db_path=os.path.join(self.tmp, "other.sqlite3"), enabled=True)
        self.assertNotEqual(self.app.config["SECRET_KEY"], other.config["SECRET_KEY"])

    def test_every_vulnerable_page_is_labelled(self):
        for owasp, topic, vuln, fixed, args in lab_app.EXERCISES:
            with self.app.test_request_context():
                from flask import url_for
                v_url, f_url = url_for(vuln, **args), url_for(fixed, **args)
            self.assertIn("VULNERABLE: TRAINING ONLY", self.text(v_url), v_url)
            self.assertIn("FIXED: SECURE VERSION", self.text(f_url), f_url)


class InjectionLabTests(LabTestCase):
    def test_sql_injection_search_vulnerable_returns_every_row(self):
        normal = self.text("/lab/injection/search/vulnerable?q=Aditi")
        self.assertIn("Aditi Rao", normal)
        self.assertNotIn("Karan Mehta", normal)
        attack = self.text("/lab/injection/search/vulnerable", query_string={"q": "' OR '1'='1"})
        for name in ("Aditi Rao", "Karan Mehta", "Isha Menon"):
            self.assertIn(name, attack)

    def test_sql_injection_search_vulnerable_can_read_other_tables(self):
        payload = "zzz' UNION SELECT id, username, password_md5 FROM lab_users --"
        page = self.text("/lab/injection/search/vulnerable", query_string={"q": payload})
        self.assertIn("<td>lab_admin</td>", page)
        self.assertIn(hashlib.md5(b"labadmin-9X").hexdigest(), page)

    def test_sql_error_text_is_leaked_by_vulnerable_search(self):
        page = self.text("/lab/injection/search/vulnerable", query_string={"q": "'"})
        self.assertIn("SQL error", page)

    def test_search_fixed_treats_payloads_as_plain_text(self):
        for payload in ("' OR '1'='1", "zzz' UNION SELECT id, username, password_md5 FROM lab_users --", "'"):
            page = self.text("/lab/injection/search/fixed", query_string={"q": payload})
            self.assertNotIn("Aditi Rao", page, payload)
            self.assertNotIn("<td>lab_admin</td>", page, payload)
            self.assertNotIn(hashlib.md5(b"labadmin-9X").hexdigest(), page, payload)
            self.assertNotIn("SQL error", page, payload)
        self.assertIn("Aditi Rao", self.text("/lab/injection/search/fixed?q=Aditi"))

    def test_sql_injection_login_vulnerable_bypasses_password(self):
        response = self.client.post("/lab/injection/login/vulnerable",
                                    data={"username": "lab_admin'--", "password": "not-the-password"})
        self.assertIn("Signed in as lab_admin (admin)", response.get_data(as_text=True))

    def test_login_vulnerable_still_rejects_without_injection(self):
        response = self.client.post("/lab/injection/login/vulnerable",
                                    data={"username": "lab_admin", "password": "wrong"})
        self.assertIn("Login failed.", response.get_data(as_text=True))

    def test_sql_injection_login_fixed_cannot_be_bypassed(self):
        response = self.client.post("/lab/injection/login/fixed",
                                    data={"username": "lab_admin'--", "password": "x"})
        self.assertIn("Incorrect username or password.", response.get_data(as_text=True))
        ok = self.client.post("/lab/injection/login/fixed",
                              data={"username": "lab_admin", "password": "labadmin-9X"})
        self.assertIn("Signed in as lab_admin", ok.get_data(as_text=True))

    def test_reflected_xss_vulnerable_echoes_raw_html(self):
        payload = "<script>alert(1)</script>"
        self.assertIn(payload, self.text("/lab/xss/vulnerable", query_string={"name": payload}))

    def test_reflected_xss_fixed_escapes_html(self):
        payload = "<script>alert(1)</script>"
        page = self.text("/lab/xss/fixed", query_string={"name": payload})
        self.assertNotIn(payload, page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)


class AccessControlLabTests(LabTestCase):
    def test_idor_vulnerable_exposes_other_users_record(self):
        self.act_as("lab_student1")
        self.assertIn("belongs to lab_student1", self.text("/lab/access/records/1/vulnerable"))
        self.assertIn("belongs to lab_student2", self.text("/lab/access/records/2/vulnerable"))
        self.assertIn("belongs to lab_admin", self.text("/lab/access/records/3/vulnerable"))

    def test_idor_fixed_blocks_other_users_records(self):
        self.act_as("lab_student1")
        self.assertEqual(self.client.get("/lab/access/records/1/fixed").status_code, 200)
        for other in (2, 3, 999):
            self.assertEqual(self.client.get(f"/lab/access/records/{other}/fixed").status_code, 404, other)

    def test_idor_fixed_requires_login(self):
        self.assertEqual(self.client.get("/lab/access/records/1/fixed").status_code, 401)

    def test_missing_role_check_vulnerable_lets_student_into_admin_panel(self):
        self.act_as("lab_student1")
        page = self.text("/lab/access/admin-panel/vulnerable")
        self.assertIn("<td>lab_admin</td>", page)

    def test_admin_panel_fixed_forbids_student_but_allows_admin(self):
        self.act_as("lab_student1")
        self.assertEqual(self.client.get("/lab/access/admin-panel/fixed").status_code, 403)
        self.act_as("lab_admin")
        self.assertEqual(self.client.get("/lab/access/admin-panel/fixed").status_code, 200)


class AuthenticationLabTests(LabTestCase):
    def login(self, route, user, pw):
        return self.client.post(f"/lab/auth/login/{route}", data={"username": user, "password": pw})

    def test_vulnerable_login_reveals_which_usernames_exist(self):
        real = self.login("vulnerable", "lab_student1", "wrong").get_data(as_text=True)
        fake = self.login("vulnerable", "nobody_here", "wrong").get_data(as_text=True)
        self.assertIn("Wrong password for that account.", real)
        self.assertIn("No account with that username.", fake)

    def test_vulnerable_login_has_no_attempt_limit(self):
        for _ in range(15):
            self.assertEqual(self.login("vulnerable", "lab_student1", "bad").status_code, 200)
        self.assertIn("Welcome lab_student1.", self.login("vulnerable", "lab_student1", "sunshine1").get_data(as_text=True))

    def test_fixed_login_uses_one_generic_message(self):
        real = self.login("fixed", "lab_student1", "wrong").get_data(as_text=True)
        fake = self.login("fixed", "nobody_here", "wrong").get_data(as_text=True)
        self.assertIn("Incorrect username or password.", real)
        self.assertIn("Incorrect username or password.", fake)

    def test_fixed_login_throttles_even_correct_password(self):
        for _ in range(5):
            self.login("fixed", "lab_student1", "bad")
        blocked = self.login("fixed", "lab_student1", "sunshine1")
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Too many attempts", blocked.get_data(as_text=True))


class CryptoAndMisconfigLabTests(LabTestCase):
    def test_md5_storage_shows_identical_hashes_for_identical_passwords(self):
        page = self.text("/lab/crypto/vulnerable")
        self.assertEqual(page.count(hashlib.md5(b"sunshine1").hexdigest()), 2)

    def test_fixed_storage_is_salted_and_not_md5(self):
        page = self.text("/lab/crypto/fixed")
        self.assertNotIn(hashlib.md5(b"sunshine1").hexdigest(), page)
        conn = sqlite3.connect(self.db_path)
        hashes = [r[0] for r in conn.execute("SELECT password_hash FROM lab_users WHERE username LIKE 'lab_student%'")]
        conn.close()
        self.assertEqual(len(set(hashes)), 2)   # same password, different salts
        self.assertTrue(all(h.startswith(("scrypt:", "pbkdf2:")) for h in hashes))

    def test_misconfig_vulnerable_lacks_headers_and_advertises_internals(self):
        h = self.client.get("/lab/misconfig/vulnerable").headers
        self.assertNotIn("Content-Security-Policy", h)
        self.assertNotIn("X-Frame-Options", h)
        self.assertIn("X-Powered-By", h)
        self.assertEqual(h["Access-Control-Allow-Origin"], "*")

    def test_config_dump_exposes_secret_key(self):
        self.assertIn(self.app.config["SECRET_KEY"], self.text("/lab/misconfig/config-dump"))

    def test_misconfig_fixed_has_headers_and_no_banner(self):
        h = self.client.get("/lab/misconfig/fixed").headers
        for name in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
            self.assertIn(name, h)
        self.assertNotIn("X-Powered-By", h)
        self.assertNotIn("Access-Control-Allow-Origin", h)


class ExceptionHandlingLabTests(LabTestCase):
    def test_vulnerable_calculator_leaks_stack_trace(self):
        response = self.client.get("/lab/errors/divide/vulnerable?divisor=0")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 500)
        self.assertIn("Traceback", body)
        self.assertIn("lab_app.py", body)
        self.assertIn("ZeroDivisionError", body)

    def test_fixed_calculator_returns_generic_message(self):
        for value in ("0", "abc", "1.5"):
            response = self.client.get("/lab/errors/divide/fixed", query_string={"divisor": value})
            body = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 400, value)
            self.assertNotIn("Traceback", body)
            self.assertNotIn("lab_app.py", body)
        self.assertIn("= 25.0", self.text("/lab/errors/divide/fixed?divisor=4"))

    def test_fail_open_vulnerable_grants_access_on_bad_input(self):
        self.assertIn("Access denied.", self.text("/lab/errors/fail-open/vulnerable?clearance=1"))
        self.assertIn("ACCESS GRANTED", self.text("/lab/errors/fail-open/vulnerable?clearance=7"))
        self.assertIn("ACCESS GRANTED", self.text("/lab/errors/fail-open/vulnerable?clearance=abc"))

    def test_fail_open_fixed_denies_on_bad_input(self):
        self.assertIn("Access denied.", self.text("/lab/errors/fail-open/fixed?clearance=1"))
        self.assertIn("ACCESS GRANTED", self.text("/lab/errors/fail-open/fixed?clearance=7"))
        self.assertIn("Access denied.", self.text("/lab/errors/fail-open/fixed?clearance=abc"))
        self.assertIn("Access denied.", self.text("/lab/errors/fail-open/fixed"))


if __name__ == "__main__":
    unittest.main()
