# Limitations and checks that still need manual verification

This document is deliberately blunt. A security project is only credible if it says what it does not cover.

## 1. How this project was verified

Done during development (in a Linux sandbox, Python 3.12, Flask 3.1):

- The portal's automated tests (`tests/test_app.py`) and the lab's tests (`security-lab/tests/test_lab.py`) were executed and passed.
- Three protections (CSRF checking, the admin role check, parameterized search SQL) were deliberately broken one at a time to confirm the tests fail when protection is removed.
- The Flask CLI commands, server start-up, static file serving and the lab's disabled-by-default guard were run.

**Not done:**

- Not run on **Windows 11** or in a real **browser**. The page layout, sidebar, mobile menu and dark theme have not been visually checked by the author of the code. Look at it on your own screen and phone-width window.
- No **accessibility audit** (screen reader, axe, Lighthouse). Semantic HTML, labels, skip link, focus outlines and table captions are included, but conformance is unverified.
- No **Burp Suite** testing was done. Every Burp step in the docs is a plan for you to carry out, not a result.
- No dependency vulnerability scan (`pip-audit`) was run.
- No load, performance or concurrency testing.

## 2. Known design limitations (candidates for your report)

| Limitation | Why it matters | Possible improvement |
|---|---|---|
| **Sessions are client-side signed cookies.** Logging out clears the browser's cookie, but a copy of the old cookie stays valid until it expires (30 minutes idle). | A stolen cookie cannot be revoked early. | Store sessions on the server (database table with a random session id) and delete them on logout and password change. |
| **CSRF and rate limiting are custom code**, not Flask-WTF / Flask-Limiter. | Less battle-tested than established libraries. | Switch to the libraries (see README, design decision 1) and re-run tests. |
| **Per-username lockout can be abused**: anyone can lock a known username for 15 minutes by failing logins. | Denial of service against one account. | Add CAPTCHA, progressive delays, or notify the owner. |
| **IP rate limiting trusts `remote_addr`.** Behind a reverse proxy every user may appear as one IP. | Limits may block everyone, or never apply. | Configure `ProxyFix` correctly for your proxy. |
| **Registration reveals whether a username or email is taken.** | Account enumeration through the sign-up form. | Send a confirmation email instead of an on-screen message. |
| **No email verification, password reset, MFA or account recovery.** | Real systems need these. | Add email flows and TOTP. |
| **Plain HTTP locally.** `Secure` cookie flag and HSTS are only on in production config. | Traffic is readable on a hostile network. | Serve through HTTPS (reverse proxy) for any real deployment. |
| **Flask's development server** is used. | Not hardened or built for real traffic. | Use Waitress or Gunicorn behind a reverse proxy. |
| **SQLite file** has no encryption at rest and a single writer. | Disk theft exposes data; busy sites would block. | Use a server database and disk encryption. |
| **Audit log is in the same database** as the data it protects, and admins can read it but nothing stops a database owner editing it. | Weak tamper resistance. | Ship logs to a separate append-only store. |
| **No alerting.** Events are recorded but nobody is notified. | OWASP A09 asks for alerting, not only logging. | Add email/webhook alerts on repeated failures. |
| **Admin accounts have no MFA** and the admin login page is public. | High-value target. | Add MFA and IP allow-listing. |
| **scrypt availability.** Some Python builds lack `hashlib.scrypt`. | Registration would fail with an error. | Set `PASSWORD_HASH_METHOD=pbkdf2:sha256` in `.env`. |
| **Password rules** are length and composition only; no breached-password check. | Weak but "valid" passwords are possible. | Check against a breach list. |
| **Version pins are ranges** (`Flask>=3.1,<4`). | Builds are not perfectly reproducible. | Pin exact versions with a lock file. |

## 3. Still needs manual verification

Tick these yourself and record results in your report.

- [ ] Layout and navigation at desktop, tablet and phone widths in Edge/Chrome and Firefox.
- [ ] Keyboard-only use of every form and the sidebar; visible focus everywhere.
- [ ] Screen reader pass on login, registration and the dashboard.
- [ ] Colour contrast check of the theme (tool such as the browser's accessibility panel).
- [ ] CSP in a real browser: open the console on every page and confirm no violations for legitimate content.
- [ ] Session cookie behaviour in the browser (flags, expiry after 30 idle minutes, behaviour after logout and cookie replay).
- [ ] All Burp checks in `SECURITY_TESTING_CHECKLIST.md`.
- [ ] `pip-audit` results for installed packages.
- [ ] Timing differences between known and unknown usernames at login (the code equalizes hashing work, but measure it).
- [ ] Behaviour with concurrent logins from two browsers.
- [ ] Windows-specific: file permissions on `.env` and `instance/`, and that `.env` is not committed to any repository.
- [ ] Behaviour when the database file is missing, locked or read-only (does it fail safely?).

## 4. Categories only partly covered by the lab

The security lab demonstrates A01, A02, A04, A05, A07 and A10. It deliberately does **not** include exercises for A03 (supply chain), A06 (insecure design), A08 (integrity failures) or A09 (logging). Test those on the main app using the checklist.
