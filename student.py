"""
student.py - pages for signed-in students.

Access control design: the student record is always looked up with g.user["id"]
(taken from the server-side session). No URL or form field ever says WHICH student
to show, so one student cannot ask for another student's data (no IDOR).
"""
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from database import audit, get_db
from security import (clean_line, role_required, validate_address, validate_full_name,
                      validate_phone)

bp = Blueprint("student", __name__, url_prefix="/student")


def _my_record():
    return get_db().execute("SELECT * FROM students WHERE user_id = ?", (g.user["id"],)).fetchone()


@bp.route("/dashboard")
@role_required("student")
def dashboard():
    db = get_db()
    student = _my_record()
    marks = db.execute(
        "SELECT subject, score, max_score FROM marks WHERE student_id = ? ORDER BY subject",
        (student["id"],),
    ).fetchall()
    total = sum(m["score"] for m in marks)
    maximum = sum(m["max_score"] for m in marks)
    overall = round(total / maximum * 100, 1) if maximum else None
    notices = db.execute(
        "SELECT title, body, created_at FROM notices ORDER BY id DESC LIMIT 5"
    ).fetchall()
    return render_template("student/dashboard.html", student=student, marks=marks,
                           overall=overall, notices=notices)


@bp.route("/profile", methods=["GET", "POST"])
@role_required("student")
def profile():
    student = _my_record()
    if request.method == "GET":
        return render_template("student/profile.html", student=student, form=student, errors={})

    # ALLOW-LIST of editable fields. Anything else in the request (attendance_pct,
    # student_code, role, user_id ...) is simply never read - this blocks mass assignment.
    form = {
        "full_name": clean_line(request.form.get("full_name"), 80),
        "phone": clean_line(request.form.get("phone"), 15),
        "address": clean_line(request.form.get("address"), 200),
    }
    errors = {}
    if err := validate_full_name(form["full_name"]):
        errors["full_name"] = err
    if err := validate_phone(form["phone"]):
        errors["phone"] = err
    if err := validate_address(form["address"]):
        errors["address"] = err
    if errors:
        return render_template("student/profile.html", student=student, form=form,
                               errors=errors), 400

    db = get_db()
    db.execute(
        "UPDATE students SET full_name = ?, phone = ?, address = ? WHERE id = ?",
        (form["full_name"], form["phone"], form["address"], student["id"]),
    )
    db.commit()
    audit("profile_updated", g.user["id"])
    flash("Profile saved.", "success")
    return redirect(url_for("student.profile"))
