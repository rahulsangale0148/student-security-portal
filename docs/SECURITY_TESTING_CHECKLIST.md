# Security testing checklist: Student Security Portal

Framework: **OWASP Top 10:2025**. Tool: **Burp Suite Community Edition** (manual testing).
Target: `http://127.0.0.1:5000` only. Record every result as Pass, Fail or Not tested, and keep evidence for each Fail.

## 0. Preparation

- [ ] Both servers are bound to 127.0.0.1 (check the startup message).
- [ ] `python -m unittest discover -s tests -v` ends with `OK` before you start.
- [ ] Created accounts: **student A**, **student B** (register two, or use `seed-demo`), and one **admin**.
- [ ] Burp proxy works (see `BURP_SUITE_GUIDE.md`). HTTP history shows requests.
- [ ] Wrote down the date, commit/zip name and Python/Flask versions in your report.

## A01 Broken Access Control

- [ ] While signed out, request `/student/dashboard`, `/student/profile`, `/admin/`, `/admin/students`, `/admin/audit`. Expect a redirect to sign in.
- [ ] Signed in as student A, request every `/admin/...` URL. Expect 403.
- [ ] As student A, replay an admin POST (for example `/admin/students/1/delete`) from Repeater with a valid token. Expect 403 and nothing deleted.
- [ ] As student A, add `?id=2`, `?student_id=2`, `?user_id=2` to dashboard and profile. Your own data must still be shown.
- [ ] POST to `/student/profile` with extra fields (`attendance_pct`, `student_code`, `role`, `user_id`). Confirm they are ignored.
- [ ] Change the HTTP method (GET to POST and back) on protected URLs.
- [ ] As admin, request `/student/dashboard`. Expect 403.
- [ ] Try `/admin/students/999999` and `/admin/students/abc`. Expect 404, no details.
- [ ] Try `/admin/students/1/marks/<id>/delete` using a mark id that belongs to another student. It must not delete.

## A02 Security Misconfiguration

- [ ] Inspect response headers on several pages: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.
- [ ] Inspect `Set-Cookie`: `HttpOnly` and `SameSite=Lax` present. Note that `Secure` is off locally on purpose.
- [ ] Signed-in pages return `Cache-Control: no-store`.
- [ ] Request `/console`, `/static/../config.py`, `/.env`, `/instance/portal.sqlite3`, `/schema.sql`. None may return content.
- [ ] Confirm the Werkzeug debugger is off (cause an error; no interactive traceback).
- [ ] Check `Server` header for version details (Werkzeug sets one; note it as informational).
- [ ] Confirm the app refuses to start without `SECRET_KEY`.

## A03 Software Supply Chain Failures

- [ ] Review `requirements.txt` (two packages).
- [ ] On your machine run `pip install pip-audit` then `pip-audit` and record results.
- [ ] Confirm no page loads scripts, styles or fonts from other websites (Burp history shows only 127.0.0.1).

## A04 Cryptographic Failures

- [ ] Open the SQLite file (DB Browser for SQLite) and confirm `password_hash` values start with `scrypt:` and are unique per user.
- [ ] Search all Burp responses for password values or hashes. None should appear.
- [ ] Note the session cookie is signed (try editing it and confirm you are signed out).
- [ ] Record that traffic is plain HTTP locally and what you would require for deployment (HTTPS, HSTS).

## A05 Injection

- [ ] Admin search `/admin/students?q=` with: `'`, `' OR '1'='1`, `%`, `_`, `\`, a UNION payload. Expect no errors and no extra rows.
- [ ] Login username field with `' OR '1'='1' --`. Expect the generic error.
- [ ] Registration and profile fields with `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`. Expect validation errors, never executed script.
- [ ] Admin notice title/body with HTML. Expect it displayed as text on both admin and student pages.
- [ ] View page source of each page where input is echoed; confirm characters are encoded (`&lt;`).
- [ ] Confirm the CSP blocks inline script (browser console shows a violation if you inject one).

## A06 Insecure Design

- [ ] Confirm admin accounts cannot be created via `/register` (add `role=admin` to the request).
- [ ] Confirm students cannot edit attendance, marks, course, student ID.
- [ ] Review the password rules (length 10 to 128, letter and digit, not common, not containing the username).
- [ ] Try very long inputs (over 16 KB body gives 413) and unusual Unicode.
- [ ] Think about abuse cases: lockout of a victim's username by repeated failures (known trade-off).

## A07 Authentication Failures

- [ ] Compare responses for valid username with wrong password versus invalid username. Same message and same page structure.
- [ ] Compare response times for both cases (Burp shows timings). Differences should be small.
- [ ] Send 6 wrong passwords for one username. Expect 429 on the 6th and still 429 with the right password.
- [ ] Confirm a new session cookie is issued at login (compare cookie before and after).
- [ ] Copy the session cookie, sign out, then replay a request with the old cookie. **Record the result honestly**: this app uses client-side signed sessions, see `LIMITATIONS.md`.
- [ ] Change password: wrong current password is rejected; after success you are signed out.
- [ ] Disable a student as admin; that student's existing session stops working on the next request.

## A08 Software or Data Integrity Failures

- [ ] POST without `csrf_token` (every form: register, login, profile, password, logout, all admin actions). Expect 400.
- [ ] Use student A's token in student B's session. Expect 400.
- [ ] Modify the session cookie by one character. Expect to be signed out.
- [ ] Confirm destructive actions need POST (GET to `/logout` returns 405).

## A09 Security Logging and Alerting Failures

- [ ] After each test above, open Admin > Audit log and check an entry exists: failed login, rate limit, CSRF rejection, access denied, admin edit.
- [ ] Confirm no passwords or tokens appear in the log or in `instance/app.log`.
- [ ] Put a newline and HTML in a username during login; confirm the log entry is one line and is displayed as text.
- [ ] Note what is **not** logged or alerted (no email alerts, no log shipping).

## A10 Mishandling of Exceptional Conditions

- [ ] Request a missing page, wrong method, huge body, malformed form data. Responses must be generic.
- [ ] Send non-numeric values where numbers are expected (`year_of_study=abc`, `attendance_pct=NaN`, `1e999`).
- [ ] Remove parameters entirely from POST requests (empty body).
- [ ] Confirm errors never show file paths, SQL, stack traces or library versions.
- [ ] Stop the server mid-request or delete the DB file and observe: does the app fail safely (denied), not open?

## Finishing

- [ ] Every Fail has a finding in the report with evidence.
- [ ] Fixes made, then every Fail retested and marked Fixed / Still open.
- [ ] Re-run the unit tests after fixes.
- [ ] Complete `LIMITATIONS.md` section "Still needs manual verification".
