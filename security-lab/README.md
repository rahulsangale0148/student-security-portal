# Security Training Lab

**Deliberately vulnerable. For authorized local practice only.**

This is a separate app from the Student Security Portal. It has its own database (`lab.sqlite3`, rebuilt on every start), its own port (5001) and fictional data. Nothing in it touches the portal or its database.

## Safety rails

- **Disabled by default.** It refuses to start unless `LAB_ENABLED=1`.
- Binds only to `127.0.0.1` and rejects requests from non-loopback addresses or unexpected Host headers.
- Flask debug mode is never enabled.
- The secret key is random on each start; nothing is hard-coded.
- Never port-forward, tunnel, deploy or share this app. Never reuse its code in a real project.
- All lab pages carry a red banner, and every route is labelled **VULNERABLE: TRAINING ONLY** or **FIXED: SECURE VERSION**.
- Lab forms deliberately have no CSRF tokens, to keep exercises simple.

## Scope

In scope: `http://127.0.0.1:5001` on your own computer. Out of scope: everything else.

## Setup (PowerShell, virtual environment from the main README active)

```powershell
cd security-lab
$env:LAB_ENABLED = "1"
python lab_app.py
```

Open http://127.0.0.1:5001. The "Act as" buttons switch between fictional users without a password (needed for the access-control exercises). Fictional lab accounts for the login exercises: `lab_student1` / `sunshine1`, `lab_student2` / `sunshine1`, `lab_admin` / `labadmin-9X`. They protect nothing real.

Stop with `Ctrl + C`. Turn the lab off afterwards: `Remove-Item Env:LAB_ENABLED`.

Run the lab's own tests: `python -m unittest discover -s tests -v`

## Exercises

Each row has a vulnerable and a fixed page. "Observed" means a test in `tests/test_lab.py` demonstrated it, so you should see the same.

| OWASP 2025 | Exercise | What to do in Burp | Observed in vulnerable version | Fix (in the fixed route) |
|---|---|---|---|---|
| A01 | IDOR notes `/lab/access/records/<id>/vulnerable` | Act as `lab_student1`, change the id in Repeater | Other users' private notes are returned | Query also filters `owner_id` = signed-in user; others get 404 |
| A01 | Admin panel | Act as a student, open the page | A student can list all accounts | Server-side role check returns 403 |
| A02 | Headers and config dump | Compare response headers of both pages; open `/lab/misconfig/config-dump` | No CSP/frame/nosniff headers, `X-Powered-By` banner, wildcard CORS; config page shows the secret key | Security headers added, no banner, no dump page |
| A04 | Password storage | Open both pages | Unsalted MD5; two users with the same password have identical values | Salted scrypt; values differ |
| A05 | SQL search | Send a quote `'`, then a boolean condition, then a UNION that selects from `lab_users` | SQL error text is shown; all rows returned; other tables readable | Parameterized query, input treated as text |
| A05 | SQL login | Try a username ending with a SQL comment, e.g. `lab_admin'--` | Signed in as admin without the password | Parameterized query plus hash check |
| A05 | Reflected XSS | Send `<script>alert(1)</script>` in `name` | Script tag appears unescaped in the response | Jinja auto-escaping encodes it |
| A07 | Login | Compare messages for real and fake usernames; send many wrong passwords | Different messages reveal valid usernames; no limit on attempts | One generic message; 5-attempt limit returns 429 |
| A10 | Calculator | Divisor `0`, then `abc` | HTTP 500 with a full stack trace and file path | Validation, generic 400, details only in the server log |
| A10 | Fail-open check | Clearance `1`, `7`, then `abc` | Non-numeric value grants access | Fails closed: denied |

## How to work through one exercise

1. **Scope:** note the URL and that it is the local lab.
2. **Observe:** use the vulnerable page normally with Burp running; read the request and response.
3. **Test:** change one value in Repeater; save the request and response as evidence.
4. **Record:** write a finding with `../docs/VULNERABILITY_REPORT_TEMPLATE.md`.
5. **Remediate:** read the matching `fixed` route in `lab_app.py` (comments marked `FIX:` explain each change).
6. **Retest:** repeat the exact same request against the fixed page and record the result.

## Not covered

A03, A06, A08 and A09 have no lab exercise. Test those on the main app.
