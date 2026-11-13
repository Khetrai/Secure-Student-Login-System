import os
from datetime import datetime, timedelta
import pyotp
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from db import get_db
from security import check_password, encrypt, decrypt
from auth import role_required
from audit import log_action, verify_chain
from backup import backup_database, list_backups

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("USE_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
)
csrf = CSRFProtect(app)

MAX_ATTEMPTS = 5
LOCK_MINUTES = 15
MAX_OTP_TRIES = 5


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user:
            # account locked?
            if user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > datetime.now():
                conn.close()
                log_action(user["id"], "LOGIN_BLOCKED", "account is locked")
                flash("Account locked. Try again later.")
                return render_template("login.html")

            # correct password -> go to OTP step
            if check_password(password, user["password_hash"]):
                conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (user["id"],),
                )
                conn.commit()
                conn.close()
                session.clear()
                session["pending_user_id"] = user["id"]
                log_action(user["id"], "PASSWORD_OK", "waiting for OTP")
                return redirect(url_for("otp"))

            # wrong password
            attempts = user["failed_attempts"] + 1
            locked = None
            if attempts >= MAX_ATTEMPTS:
                locked = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat()
                attempts = 0
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked, user["id"]),
            )
            conn.commit()
            conn.close()
            log_action(user["id"], "LOGIN_FAILED", "wrong password")
            if locked:
                log_action(user["id"], "ACCOUNT_LOCKED", f"locked for {LOCK_MINUTES} minutes")
            flash("Invalid username or password")
            return render_template("login.html")

        conn.close()
        log_action(None, "LOGIN_FAILED", "unknown username")
        flash("Invalid username or password")

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        session["otp_tries"] = session.get("otp_tries", 0) + 1
        if session["otp_tries"] > MAX_OTP_TRIES:
            uid = session.get("pending_user_id")
            session.clear()
            log_action(uid, "OTP_TOO_MANY", "too many wrong codes")
            flash("Too many wrong codes. Login again.")
            return redirect(url_for("login"))

        code = request.form["code"].strip()
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (session["pending_user_id"],)
        ).fetchone()
        conn.close()

        if user and pyotp.TOTP(user["otp_secret"]).verify(code, valid_window=1):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            log_action(user["id"], "LOGIN_SUCCESS", "password + OTP")
            return redirect(url_for("dashboard"))

        log_action(session.get("pending_user_id"), "OTP_FAILED", "wrong code")
        flash("Invalid code")

    return render_template("otp.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(session["user_id"], "LOGOUT", "")
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
@role_required("admin")
def admin_panel():
    return render_template("admin.html", backups=list_backups())


@app.route("/admin/backup", methods=["POST"])
@role_required("admin")
def admin_backup():
    path = backup_database()
    log_action(session["user_id"], "BACKUP_CREATED", os.path.basename(path))
    flash("Backup created")
    return redirect(url_for("admin_panel"))


@app.route("/audit")
@role_required("admin")
def audit_page():
    log_action(session["user_id"], "AUDIT_VIEWED", "")
    ok, bad_id = verify_chain()
    conn = get_db()
    rows = conn.execute(
        "SELECT a.id, a.created_at, u.username, a.action, a.details, a.ip "
        "FROM audit_log a LEFT JOIN users u ON u.id = a.user_id "
        "ORDER BY a.id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return render_template("audit.html", rows=rows, ok=ok, bad_id=bad_id)



@app.route("/teacher", methods=["GET", "POST"])
@role_required("teacher")
def teacher_panel():
    conn = get_db()

    if request.method == "POST":
        course = request.form.get("course", "").strip()

        if not course or len(course) > 50:
            flash("Please enter a valid course name.")
        else:
            students = conn.execute(
                "SELECT id FROM students"
            ).fetchall()

            valid_ids = {str(s["id"]) for s in students}
            entries = []
            error = None

            for student_id in valid_ids:
                marks = request.form.get(
                    "marks_" + student_id, ""
                ).strip()

                # Blank marks are skipped
                if marks == "":
                    continue

                if not marks.isdecimal() or not (0 <= int(marks) <= 100):
                    error = "Marks must be between 0 and 100."
                    break

                entries.append((student_id, marks))

            if error:
                flash(error)

            elif not entries:
                flash("Please enter marks for at least one student.")

            else:
                now = datetime.now().isoformat(timespec="seconds")

                conn.executemany(
                    "INSERT INTO marks "
                    "(student_id, course, marks_enc, updated_by, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [
                        (
                            int(student_id),
                            course,
                            encrypt(marks),
                            session["user_id"],
                            now
                        )
                        for student_id, marks in entries
                    ]
                )

                conn.commit()

                log_action(
                    session["user_id"],
                    "BULK_MARKS_ADDED",
                    f"course={course}, students={len(entries)}"
                )

                flash(f"Marks saved for {len(entries)} students!")

    students = [
        {
            "id": r["id"],
            "roll_no": r["roll_no"],
            "name": decrypt(r["full_name_enc"])
        }
        for r in conn.execute(
            "SELECT id, roll_no, full_name_enc FROM students ORDER BY roll_no"
        )
    ]

    records = [
        {
            "roll_no": r["roll_no"],
            "name": decrypt(r["full_name_enc"]),
            "course": r["course"],
            "marks": decrypt(r["marks_enc"]),
            "updated_at": r["updated_at"],
        }
        for r in conn.execute(
            "SELECT m.course, m.marks_enc, m.updated_at, "
            "s.roll_no, s.full_name_enc "
            "FROM marks m JOIN students s ON s.id = m.student_id "
            "ORDER BY m.id DESC"
        )
    ]

    conn.close()

    return render_template(
        "teacher.html",
        students=students,
        records=records
    )

@app.route("/my-marks")
@role_required("student")
def my_marks():
    conn = get_db()
    student = conn.execute(
        "SELECT id, roll_no, full_name_enc FROM students WHERE user_id = ?",
        (session["user_id"],),
    ).fetchone()

    if not student:
        conn.close()
        return render_template("page.html", title="My Marks",
                               message="No student profile found. Ask the admin.")

    rows = conn.execute(
        "SELECT course, marks_enc, updated_at FROM marks WHERE student_id = ? ORDER BY id DESC",
        (student["id"],),
    ).fetchall()
    conn.close()

    marks = [
        {"course": r["course"], "marks": decrypt(r["marks_enc"]), "updated_at": r["updated_at"]}
        for r in rows
    ]
    log_action(session["user_id"], "MARKS_VIEWED", "")
    return render_template("my_marks.html", name=decrypt(student["full_name_enc"]),
                           roll_no=student["roll_no"], marks=marks)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(404)
def not_found(e):
    return render_template("page.html", title="404 Not Found",
                           message="This page does not exist."), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("page.html", title="Error",
                           message="Something went wrong. Please try again."), 500
def forbidden(e):
    log_action(session.get("user_id"), "ACCESS_DENIED", request.path)
    return render_template("page.html", title="403 Forbidden",
                           message="You are not allowed to open this page."), 403


if __name__ == "__main__":
    app.run(debug=os.environ.get("APP_DEBUG") == "1")