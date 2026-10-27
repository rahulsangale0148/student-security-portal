# OWASP Top 10:2025 mapping

Category names follow https://owasp.org/Top10/2025/. "Control" means a protection that exists in the code. It is **not** proof the protection works. "Assessment status" stays *Not yet assessed* until you test and record evidence in your report.

| ID | Category | Controls in the portal | Lab exercise (security-lab) | Main manual tests | Assessment status |
|---|---|---|---|---|---|
| A01 | Broken Access Control | `role_required`/`require_role` in `security.py`; blueprint-wide admin check in `admin.py`; student data looked up from the session in `student.py`; allow-listed profile fields; mark deletion scoped by student id | IDOR on private notes; missing role check on admin panel | Checklist A01 | Not yet assessed |
| A02 | Security Misconfiguration | Debug off, secure-by-default config (`config.py`); security headers and CSP (`security.py`); cookie flags; app refuses to start without a strong secret; request size limit | Verbose headers and config dump | Checklist A02 | Not yet assessed |
| A03 | Software Supply Chain Failures | Only two dependencies; no CDN scripts, fonts or images; no external requests | None (covered by manual review) | Checklist A03, `pip-audit` | Not yet assessed |
| A04 | Cryptographic Failures | scrypt with salt for passwords; signed session cookie; Secure cookie + HSTS in production config; no secrets in source | Unsalted MD5 storage | Checklist A04 | Not yet assessed |
| A05 | Injection (includes XSS) | Parameterized SQL; escaped LIKE wildcards; Jinja auto-escaping; strict input validation; CSP without inline script | SQL injection (search and login); reflected XSS | Checklist A05 | Not yet assessed |
| A06 | Insecure Design | Admins only via CLI; mass-assignment allow-list; DB CHECK constraints; password policy; throttling designed in | None | Checklist A06 | Not yet assessed |
| A07 | Authentication Failures | Generic login errors; dummy hash for timing; rate limiting; new session at login; password change requires current password and ends the session | Account enumeration and no throttling | Checklist A07 | Not yet assessed |
| A08 | Software or Data Integrity Failures | CSRF tokens on all POSTs; signed session cookie; POST-only logout | None | Checklist A08 | Not yet assessed |
| A09 | Security Logging and Alerting Failures | `audit_log` table, admin viewer, log-injection stripping; `instance/app.log` for server errors. **No alerting.** | None | Checklist A09 | Not yet assessed |
| A10 | Mishandling of Exceptional Conditions | Central error handlers, generic pages, details only in log; input validation fails closed; DB transactions for multi-row writes | Stack trace leak; fail-open check | Checklist A10 | Not yet assessed |

## Automated test coverage (what the unit tests already check)

| Area | Test classes in `tests/test_app.py` |
|---|---|
| Registration, validation | `RegistrationTests` |
| Login, logout, generic errors | `LoginTests`, `RateLimitTests` |
| Password hashing | `PasswordHashingTests` |
| CSRF | `CsrfTests` |
| Student/admin authorization | `AccessControlTests`, `AdminFeatureTests` |
| Injection and XSS handling | `InjectionAndXssTests` |
| Configuration and headers | `SecurityConfigurationTests` |
| CLI account creation | `CommandLineTests` |

Passing tests show the checked behaviour works for the inputs tested. They do not replace manual testing.
