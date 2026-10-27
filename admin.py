"""
admin.py - admin-only pages.

One `before_request` on the blueprint checks the admin role for EVERY route in this
file, so a new route cannot be added without protection by accident.
"""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from database import audit, get_db
from security import (COURSES, clean_block, clean_line, parse_number, require_role,
                      validate_address, validate_full_name, validate_phone)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
def admin_only():
    return require_role("admin")  # None means "allowed, carry on"


def _get_student_or_404(student_id):
    row = get_db().execute(
        "SELECT s.*, u.username, u.email, u.is_active FROM students s "
        "JOIN users u ON u.id = s.user_id WHERE s.id = ?", (student_id,)
    ).fetchone()
    if row is None:
        abort(404)
    return row


@bp.route("/")
def dashboard():
    db = get_db()
    stats = db.execute(
        "SELECT COUNT(*) AS students, COALESCE(ROUND(AVG(attendance_pct), 1), 0) AS avg_attendance "
        "FROM students"
    ).fetchone()
    inactive = db.execute(
        "SELECT COUNT(*) AS n FROM users WHERE role = 'student' AND is_active = 0"
    ).fetchone()["n"]
    notice_count = db.execute("SELECT COUNT(*) AS n FROM notices").fetchone()["n"]
    recent = db.execute(
        "SELECT event, detail, ip, created_at FROM audit_log ORDER BY id DESC LIMIT 8"
    ).fetchall()
    return render_template("admin/dashboard.html", stats=stats, inactive=inactive,
                           notice_count=notice_count, recent=recent)


@bp.route("/students")
def students():
    q = clean_line(request.args.get("q"), 60)
    sql = ("SELECT s.id, s.student_code, s.full_name, s.course, s.year_of_study, s.attendance_pct, "
           "u.username, u.email, u.is_active FROM students s JOIN users u ON u.id = s.user_id ")
    params = ()
    if q:
        # Parameterized LIKE. The user's text is a bound value, never part of the SQL.
        # We also escape % and _ so they match literally instead of acting as wildcards.
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql += ("WHERE s.full_name LIKE ? ESCAPE '\\' OR s.student_code LIKE ? ESCAPE '\\' "
                "OR u.username LIKE ? ESCAPE '\\' ")
        params = (like, like, like)
    sql += "ORDER BY s.id LIMIT 200"
    rows = get_db().execute(sql, params).fetchall()
    return render_template("admin/students.html", students=rows, q=q)


@bp.route("/students/<int:student_id>")
def student_detail(student_id):
    student = _get_student_or_404(student_id)
    marks = get_db().execute(
        "SELECT id, subject, score, max_score FROM marks WHERE student_id = ? ORDER BY subject",
        (student_id,)).fetchall()
    return render_template("admin/student_detail.html", student=student, marks=marks,
                           courses=COURSES, form=student, errors={})


@bp.route("/students/<int:student_id>/edit", methods=["POST"])
def student_edit(student_id):
    student = _get_student_or_404(student_id)
    form = {
        "full_name": clean_line(request.form.get("full_name"), 80),
        "phone": clean_line(request.form.get("phone"), 15),
        "address": clean_line(request.form.get("address"), 200),
        "course": clean_line(request.form.get("course"), 20),
        "year_of_study": clean_line(request.form.get("year_of_study"), 3),
        "attendance_pct": clean_line(request.form.get("attendance_pct"), 8),
    }
    errors = {}
    if err := validate_full_name(form["full_name"]):
        errors["full_name"] = err
    if err := validate_phone(form["phone"]):
        errors["phone"] = err
    if err := validate_address(form["address"]):
        errors["address"] = err
    if form["course"] not in COURSES:
        errors["course"] = "Choose a course from the list."
    year, err = parse_number(form["year_of_study"], 1, 3, "Year")
    if err or year != int(year):
        errors["year_of_study"] = err or "Year must be a whole number."
    attendance, err = parse_number(form["attendance_pct"], 0, 100, "Attendance")
    if err:
        errors["attendance_pct"] = err

    if errors:
        marks = get_db().execute(
            "SELECT id, subject, score, max_score FROM marks WHERE student_id = ? ORDER BY subject",
            (student_id,)).fetchall()
        return render_template("admin/student_detail.html", student=student, marks=marks,
                               courses=COURSES, form=form, errors=errors), 400

    db = get_db()
    db.execute(
        "UPDATE students SET full_name = ?, phone = ?, address = ?, course = ?, "
        "year_of_study = ?, attendance_pct = ? WHERE id = ?",
        (form["full_name"], form["phone"], form["address"], form["course"],
         int(year), attendance, student_id),
    )
    db.commit()
    audit("admin_student_edit", g.user["id"], f"student_id={student_id}")
    flash("Student record updated.", "success")
    return redirect(url_for("admin.student_detail", student_id=student_id))


@bp.route("/students/<int:student_id>/marks", methods=["POST"])
def mark_add(student_id):
    _get_student_or_404(student_id)
    subject = clean_line(request.form.get("subject"), 60)
    score, err1 = parse_number(request.form.get("score"), 0, 1000, "Score")
    max_score, err2 = parse_number(request.form.get("max_score") or "100", 1, 1000, "Maximum")
    error = None
    if not subject or any(c in subject for c in "<>"):
        error = "Enter a subject name (no < or > characters)."
    else:
        error = err1 or err2
    if not error and score > max_score:
        error = "Score cannot be higher than the maximum."
    if error:
        flash(error, "error")
        return redirect(url_for("admin.student_detail", student_id=student_id))

    db = get_db()
    db.execute("INSERT INTO marks (student_id, subject, score, max_score) VALUES (?, ?, ?, ?)",
               (student_id, subject, score, max_score))
    db.commit()
    audit("admin_mark_add", g.user["id"], f"student_id={student_id} subject={subject}")
    flash("Marks added.", "success")
    return redirect(url_for("admin.student_detail", student_id=student_id))


@bp.route("/students/<int:student_id>/marks/<int:mark_id>/delete", methods=["POST"])
def mark_delete(student_id, mark_id):
    db = get_db()
    # Both ids are in the WHERE clause: a mark can only be deleted via its own student.
    db.execute("DELETE FROM marks WHERE id = ? AND student_id = ?", (mark_id, student_id))
    db.commit()
    audit("admin_mark_delete", g.user["id"], f"student_id={student_id} mark_id={mark_id}")
    flash("Marks removed.", "success")
    return redirect(url_for("admin.student_detail", student_id=student_id))


@bp.route("/students/<int:student_id>/toggle-active", methods=["POST"])
def student_toggle_active(student_id):
    student = _get_student_or_404(student_id)
    new_state = 0 if student["is_active"] else 1
    db = get_db()
    db.execute("UPDATE users SET is_active = ? WHERE id = ? AND role = 'student'",
               (new_state, student["user_id"]))
    db.commit()
    audit("admin_toggle_active", g.user["id"], f"student_id={student_id} active={new_state}")
    flash("Account enabled." if new_state else "Account disabled. The student cannot sign in.",
          "success")
    return redirect(url_for("admin.student_detail", student_id=student_id))


@bp.route("/students/<int:student_id>/delete", methods=["POST"])
def student_delete(student_id):
    student = _get_student_or_404(student_id)
    db = get_db()
    # Deleting the user cascades to the student row and marks (ON DELETE CASCADE).
    db.execute("DELETE FROM users WHERE id = ? AND role = 'student'", (student["user_id"],))
    db.commit()
    audit("admin_student_delete", g.user["id"], f"student_id={student_id}")
    flash("Student record deleted.", "success")
    return redirect(url_for("admin.students"))


@bp.route("/notices", methods=["GET", "POST"])
def notices():
    db = get_db()
    errors = {}
    form = {"title": "", "body": ""}
    if request.method == "POST":
        form = {"title": clean_line(request.form.get("title"), 80),
                "body": clean_block(request.form.get("body"), 1000)}
        if len(form["title"]) < 3:
            errors["title"] = "Title must be at least 3 characters."
        if len(form["body"]) < 3:
            errors["body"] = "Message must be at least 3 characters."
        if not errors:
            db.execute("INSERT INTO notices (title, body, created_by) VALUES (?, ?, ?)",
                       (form["title"], form["body"], g.user["id"]))
            db.commit()
            audit("admin_notice_add", g.user["id"], form["title"])
            flash("Notice published.", "success")
            return redirect(url_for("admin.notices"))
    rows = db.execute("SELECT id, title, body, created_at FROM notices ORDER BY id DESC").fetchall()
    return render_template("admin/notices.html", notices=rows, form=form, errors=errors), \
        (400 if errors else 200)


@bp.route("/notices/<int:notice_id>/delete", methods=["POST"])
def notice_delete(notice_id):
    db = get_db()
    db.execute("DELETE FROM notices WHERE id = ?", (notice_id,))
    db.commit()
    audit("admin_notice_delete", g.user["id"], f"notice_id={notice_id}")
    flash("Notice deleted.", "success")
    return redirect(url_for("admin.notices"))


@bp.route("/audit")
def audit_log():
    rows = get_db().execute(
        "SELECT a.id, a.event, a.detail, a.ip, a.created_at, u.username FROM audit_log a "
        "LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT 200").fetchall()
    return render_template("admin/audit.html", entries=rows)
