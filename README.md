# Student Security Portal

A small student records website (Python, Flask, SQLite) built for one purpose: to be **security-tested by you, on your own computer**. The main app is written with secure defaults. A separate, optional, deliberately vulnerable **security lab** lets you practise attacks safely and compare them with the fixes.

All student data is fictional. Nothing here should ever be put on the public internet.

---

## 1. What you get

| Part | What it does |
|---|---|
| Home page | Branding and a list of built-in protections |
| Student registration, login, logout | Hashed passwords, generic errors, rate limiting |
| Student dashboard | Student ID, attendance, marks, notices |
| Student profile | Edit name, phone and address only |
| Change password | Requires the current password |
| Admin login and dashboard | Separate login page, only for admin accounts |
| Admin student management | Search, edit, add/remove marks, disable or delete accounts |
| Admin notices and audit log | Publish notices; review security events |
| Security assessment page | Scope, rules and an OWASP Top 10:2025 test map |
| `security-lab/` | Optional vulnerable practice app on port 5001 (off by default) |
| `docs/` | Checklist, report template, OWASP mapping, limitations, Burp guide |

## 2. Project structure (what every file does)

```
student-security-portal/
├── app.py              Starts the app. Builds it, adds headers/error pages, defines the
│                       command-line tools (init-db, create-admin, seed-demo).
├── config.py           All settings. Secrets come from environment variables, never from code.
├── database.py         SQLite connection helper and the audit-log writer.
├── schema.sql          The table definitions (users, students, marks, notices, ...).
├── security.py         The security toolbox: CSRF tokens, login rate limiting, role checks,
│                       input validation, security headers.
├── auth.py             Register, student login, admin login, logout, change password.
├── student.py          Student dashboard and profile pages.
├── admin.py            Admin pages (every route is protected by one admin-only check).
├── public.py           Home page and security assessment page.
├── requirements.txt    The two Python packages needed.
├── .env.example        Template for your private .env settings file.
├── conftest.py         Lets the optional pytest tool find the app (can be ignored).
├── templates/          Jinja2 HTML pages. Output is auto-escaped (XSS protection).
│   ├── base.html       Page frame, sidebar navigation, flash messages
│   ├── _macros.html    Reusable form fields (labels, errors, accessible markup)
│   ├── auth/ student/ admin/ public/   Pages for each area
├── static/
│   ├── css/style.css   The dark navy theme (responsive, keyboard-focus styles)
│   └── js/app.js       Menu button, "Show password", delete confirmations (no inline JS)
├── instance/           Your private runtime files: the SQLite database and app.log.
│                       Created automatically; ignored by git.
├── tests/test_app.py   Automated tests for the portal (own temporary database).
├── docs/               Security documents (see section 9).
└── security-lab/       Separate vulnerable training app. Read its README first.
```

## 3. Setup on Windows 11 (PowerShell)

You need **Python 3.10 or newer** from python.org (tick "Add python.exe to PATH" in the installer). Check with `python --version`.

Open PowerShell in the folder where you want the project, then run these one at a time.

```powershell
# 1. Go into the project folder
cd student-security-portal

# 2. Create a virtual environment (a private box for this project's packages)
python -m venv .venv

# 3. Activate it. Your prompt will start with (.venv)
.\.venv\Scripts\Activate.ps1
```

If step 3 says "running scripts is disabled", run this once, then repeat step 3:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

```powershell
# 4. Install the dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 5. Create your private settings file and fill SECRET_KEY with a random value
Copy-Item .env.example .env
$key = python -c "import secrets; print(secrets.token_hex(32))"
(Get-Content .env) -replace '^SECRET_KEY=.*', "SECRET_KEY=$key" | Set-Content .env

# 6. Create the database tables
flask --app app init-db

# 7. Create your admin account. You will be asked for a username, email and a
#    password (typing is hidden). Use a strong password you do not use anywhere else.
flask --app app create-admin

# 8. (Optional) Add five fictional demo students that all share a password you choose.
#    Useful for testing access control between two different students.
flask --app app seed-demo

# 9. Run the website
python app.py
```

Open **http://127.0.0.1:5000** in your browser. Stop the server with `Ctrl + C`.

### Run the automated tests

In a second PowerShell window (activate the virtual environment first), or after stopping the server:

```powershell
python -m unittest discover -s tests -v
```

You want to see `OK` at the end. Tests use a temporary database file and never touch `instance/portal.sqlite3`.

### Troubleshooting

| Message | Fix |
|---|---|
| `SECRET_KEY is missing or shorter than 32 characters` | Redo step 5. Open `.env` in Notepad and check the line starts with `SECRET_KEY=` followed by 64 characters. |
| `'flask' is not recognized` | The virtual environment is not active. Run step 3 again. |
| `No such table` | Run step 6 (`init-db`). |
| Port 5000 already in use | Close the other program, or run `flask --app app run --port 5050`. |

## 4. How to use it

- **Students:** click *Create a student account*, sign in, view the dashboard, edit your profile.
- **Admin:** go to `/admin/login`. Admin accounts can only be created with the `create-admin` command, never through the website (this prevents "register as admin" attacks).
- **Admin tasks:** search students, open a record, correct attendance, add marks (students see them immediately), disable or delete an account, publish notices, read the audit log.

## 5. Security features and where to find them

| Requirement | Implementation | File |
|---|---|---|
| Password hashing | Werkzeug `generate_password_hash` (scrypt, random salt) | `auth.py` |
| Parameterized SQL | Every query uses `?` placeholders | all route files, `database.py` |
| CSRF protection | Per-session random token on every POST; compared in constant time | `security.py` |
| Session cookie settings | HttpOnly, SameSite=Lax, 30-minute idle expiry, Secure in production | `config.py` |
| Server-side authentication/authorization | Role re-read from the database on every request; decorators and a blueprint-wide admin check | `security.py`, `app.py`, `admin.py` |
| Login rate limiting | 5 failures per username and 20 per IP per 15 minutes, stored in SQLite | `security.py` |
| XSS defence | Jinja2 auto-escaping, input validation, no inline script, strict CSP | templates, `security.py` |
| Debug off in production | `ProductionConfig.DEBUG = False`, ignores `ENABLE_DEBUG` | `config.py` |
| Secrets from environment | `SECRET_KEY` from `.env`; app refuses to start without a strong one | `config.py`, `app.py` |
| Security headers | CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, HSTS (production), no-store for signed-in pages | `security.py` |
| Generic login errors | One message for unknown user, wrong password and disabled account; dummy hash check evens out timing | `auth.py` |
| Mass-assignment defence | Profile form reads an allow-list of three fields only | `student.py` |
| Audit logging | Logins, failures, denied access, admin changes | `database.py` |
| Safe errors | Generic error pages; details go to `instance/app.log` | `app.py` |

### Design decisions you should know about

1. **CSRF and rate limiting are small custom modules, not Flask-WTF / Flask-Limiter.** The environment this project was built and tested in had no internet access, so those packages could not be installed or tested. The CSRF code follows the standard synchronizer-token pattern and uses the same names as Flask-WTF (`csrf_token()` in templates, `csrf_token` form field, `X-CSRFToken` header). To switch later: `pip install Flask-WTF`, then in `app.py` replace `app.before_request(check_csrf)` with `CSRFProtect(app)`. Re-run the tests afterwards; that swap has **not** been tested here.
2. **The session is a signed client-side cookie** (Flask's default). It cannot be forged without the secret key, but a copied cookie stays valid until it expires even after logout. This is a known limitation, listed in `docs/LIMITATIONS.md`, and a good thing to try in Burp.
3. **Unit tests use `unittest`** (included with Python) so no extra package is needed. `pytest` also works if you install it.

## 6. Testing the app with Burp Suite Community Edition

Start with `docs/BURP_SUITE_GUIDE.md` (proxy setup), then follow `docs/SECURITY_TESTING_CHECKLIST.md`. Record every finding with `docs/VULNERABILITY_REPORT_TEMPLATE.md`. Do not write "vulnerable" in a report unless you have evidence (a saved request and response).

## 7. The security lab

`security-lab/` is a separate app with its own database and port. It stays **disabled** until you set `LAB_ENABLED=1`. See `security-lab/README.md`.

## 8. Rules for using this project

- Test only this project, on your own computer, with fictional data.
- Keep both apps on `127.0.0.1`. Never change the host to `0.0.0.0`, never forward ports, never deploy the lab.
- Never reuse a real password here.

## 9. Documents

| File | Purpose |
|---|---|
| `docs/SECURITY_TESTING_CHECKLIST.md` | Step-by-step test list with tick boxes |
| `docs/VULNERABILITY_REPORT_TEMPLATE.md` | Report layout: finding, evidence, impact, severity, remediation, retest |
| `docs/OWASP_TOP10_2025_MAPPING.md` | Each OWASP 2025 category mapped to code, lab exercise and test |
| `docs/LIMITATIONS.md` | Known limits and checks that need manual verification |
| `docs/BURP_SUITE_GUIDE.md` | Connecting your browser to Burp for localhost testing |

## 10. Is this production-ready?

No. It is a learning project. See `docs/LIMITATIONS.md` for what a real deployment would still need (HTTPS, a production web server, MFA, password reset, monitoring, backups, dependency scanning).
