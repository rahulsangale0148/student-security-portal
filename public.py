"""
public.py - pages anyone can open: home and the security assessment information page.
"""
from flask import Blueprint, render_template

bp = Blueprint("public", __name__)

# Shown on the assessment page. Each row says where a control lives in the code and
# what a tester should try. Nothing here claims a weakness exists - it lists what to test.
OWASP_2025 = [
    ("A01", "Broken Access Control",
     "Role checks in security.py and admin.py; student data is looked up from the session.",
     "Log in as a student and request /admin/... URLs. Try another student's data."),
    ("A02", "Security Misconfiguration",
     "Debug off, security headers and CSP, secure cookie flags (config.py, security.py).",
     "Inspect response headers and cookie flags in Burp. Trigger errors and read the page."),
    ("A03", "Software Supply Chain Failures",
     "Two small dependencies listed in requirements.txt; no external scripts or CDNs.",
     "Review requirements.txt; run pip-audit on your machine."),
    ("A04", "Cryptographic Failures",
     "Passwords hashed with scrypt and a per-password salt; session cookie is signed.",
     "Confirm no plaintext or reversible password is stored or returned in any response."),
    ("A05", "Injection",
     "Parameterized SQL everywhere; Jinja2 auto-escaping; CSP blocks inline script.",
     "Send quotes and script tags through every form field and the search box."),
    ("A06", "Insecure Design",
     "Allow-lists for editable fields; admin accounts only via command line.",
     "Try sending extra fields (attendance_pct, role) in the profile form."),
    ("A07", "Authentication Failures",
     "Generic login error, rate limiting, new session on login, password rules.",
     "Compare responses for valid and invalid usernames; repeat failed logins."),
    ("A08", "Software or Data Integrity Failures",
     "Signed session cookie; CSRF tokens on all POST requests.",
     "Edit the session cookie value; replay a POST without its token."),
    ("A09", "Security Logging and Alerting Failures",
     "Audit log of logins, denials and admin changes (admin > Audit log).",
     "Run your tests, then check that each attack left a log entry."),
    ("A10", "Mishandling of Exceptional Conditions",
     "Generic error pages; details go to the server log only.",
     "Send malformed input, huge bodies and bad IDs; look for stack traces."),
]


@bp.route("/")
def home():
    return render_template("public/home.html")


@bp.route("/security-assessment")
def assessment():
    return render_template("public/assessment.html", owasp=OWASP_2025)
