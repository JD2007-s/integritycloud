from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
import hashlib
import os
from datetime import datetime, timezone
from functools import wraps

import sqlite3

from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Optional email (works only if env vars are set)
try:
    from flask_mail import Mail, Message
    MAIL_AVAILABLE = True
except Exception:
    MAIL_AVAILABLE = False


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

serializer = URLSafeTimedSerializer(app.secret_key)

mail = Mail(app)
if MAIL_AVAILABLE:
    app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER")
    app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587"))
    app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER")
    mail.init_app(app)


# -------------------- HELPERS --------------------
def utc_now():
    return datetime.now(timezone.utc)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _get_database_url():
    # Supports both keys: DATABASE_URL (standard) and DATABASE_URL (your earlier one)
    return os.environ.get("DATABASE_URL") or os.environ.get("DATABASE_URL")


def get_db():
    db_url = _get_database_url()
    if not db_url:
        raise RuntimeError("Database URL not set. Set DATABASE_URL (recommended) or DATABASE_URL in Render.")
    return psycopg2.connect(db_url, sslmode="require", cursor_factory=RealDictCursor)


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS file_hashes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        filename TEXT NOT NULL,
        filesize INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        CONSTRAINT fk_filehash_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tamper_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        filename TEXT NOT NULL,
        expected_sha256 TEXT NOT NULL,
        actual_sha256 TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        CONSTRAINT fk_tamper_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_file_hashes_user_id ON file_hashes(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tamper_logs_user_id ON tamper_logs(user_id)")

    conn.commit()
    cur.close()
    conn.close()


try:
    init_db()
except Exception as e:
    print("DB init warning:", e)


# -------------------- USER MODEL --------------------
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role="user"):
        self.id = str(id)
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role or "user"

    @property
    def is_admin(self):
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, password_hash, role FROM users WHERE id=%s", (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    return User(row["id"], row["username"], row["email"], row["password_hash"], row["role"])


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return abort(403)
        return fn(*args, **kwargs)
    return wrapper


# -------------------- AUTH --------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        user_input = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, email, password_hash, role
            FROM users
            WHERE lower(username)=%s OR lower(email)=%s
            LIMIT 1
        """, (user_input, user_input))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row["id"], row["username"], row["email"], row["password_hash"], row["role"]))
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username/email or password")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not username or not email or not password:
            return render_template("signup.html", error="All fields are required")

        if len(password) < 6:
            return render_template("signup.html", error="Password must be at least 6 characters")

        pw_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users(username,email,password_hash) VALUES (%s,%s,%s) RETURNING id, role",
                (username, email, pw_hash)
            )
            created = cur.fetchone()
            conn.commit()
        except Exception:
            conn.rollback()
            cur.close()
            conn.close()
            return render_template("signup.html", error="Username or Email already exists")

        cur.close()
        conn.close()

        login_user(User(created["id"], username, email, pw_hash, created["role"]))
        return redirect(url_for("dashboard"))

    return render_template("signup.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# -------------------- FORGOT / RESET --------------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, email FROM users WHERE lower(email)=%s LIMIT 1", (email,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        reset_link = None
        if row:
            token = serializer.dumps({"user_id": row["id"]})
            base = (os.environ.get("APP_BASE_URL") or request.host_url).rstrip("/")
            reset_link = f"{base}{url_for('reset_password', token=token)}"

            # Send mail if SMTP configured, else show link on page (demo mode)
            if MAIL_AVAILABLE and app.config.get("MAIL_SERVER") and app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD"):
                try:
                    msg = Message("Password Reset - IntegrityCloud", recipients=[row["email"]])
                    msg.body = f"Reset your password (valid 30 minutes): {reset_link}"
                    mail.send(msg)
                    reset_link = None  # hide it if sent
                except Exception as e:
                    print("Mail send failed:", e)

        return render_template(
            "forgot.html",
            message="If the email exists, a reset link has been generated/sent.",
            reset_link=reset_link
        )

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        data = serializer.loads(token, max_age=1800)
        user_id = data["user_id"]
    except SignatureExpired:
        return "Reset link expired. Please request again.", 400
    except BadSignature:
        return "Invalid reset link.", 400

    if request.method == "POST":
        new_password = request.form.get("password") or ""
        if len(new_password) < 6:
            return render_template("reset.html", error="Password must be at least 6 characters")

        pw_hash = generate_password_hash(new_password)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (pw_hash, user_id))
        conn.commit()
        cur.close()
        conn.close()

        return redirect(url_for("login"))

    return render_template("reset.html")


# -------------------- DASHBOARD --------------------
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM file_hashes WHERE user_id=%s", (int(current_user.id),))
    hashes_count = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM tamper_logs WHERE user_id=%s", (int(current_user.id),))
    tamper_count = cur.fetchone()["c"]

    cur.execute("""
        SELECT filename, filesize, sha256, created_at
        FROM file_hashes
        WHERE user_id=%s
        ORDER BY id DESC
        LIMIT 20
    """, (int(current_user.id),))
    hashes = cur.fetchall()

    cur.execute("""
        SELECT filename, expected_sha256, actual_sha256, created_at
        FROM tamper_logs
        WHERE user_id=%s
        ORDER BY id DESC
        LIMIT 20
    """, (int(current_user.id),))
    tampers = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "dashboard.html",
        user=current_user,
        hashes_count=hashes_count,
        tamper_count=tamper_count,
        hashes=hashes,
        tampers=tampers
    )


# -------------------- ADMIN PANEL --------------------
@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM users")
    total_users = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM file_hashes")
    total_hashes = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM tamper_logs")
    total_tampers = cur.fetchone()["c"]

    cur.execute("""
    SELECT id, username, email, role, created_at
    FROM users
    ORDER BY id DESC
    LIMIT 30
""")
    users = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_hashes=total_hashes,
        total_tampers=total_tampers,
        users=users
    )
@app.route("/admin/promote/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def promote_user(user_id):
    if int(current_user.id) == user_id:
        return abort(400, "You cannot modify your own role.")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role='admin' WHERE id=%s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("admin_panel"))

@app.route("/admin/demote/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def demote_user(user_id):
    if int(current_user.id) == user_id:
        return abort(400, "You cannot demote yourself.")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role='user' WHERE id=%s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("admin_panel"))

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    if int(current_user.id) == user_id:
        return abort(400, "You cannot delete yourself.")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("admin_panel"))
# -------------------- PAGES --------------------
@app.route("/home")
@login_required
def home():
    return render_template("index.html")


@app.route("/compare")
@login_required
def compare_page():
    return render_template("compare.html")


# -------------------- API --------------------
@app.route("/api/register", methods=["POST"])
@login_required
def api_register():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    data = f.read()
    if not data:
        return jsonify({"error": "Uploaded file is empty"}), 400

    file_hash = sha256_bytes(data)
    filesize = len(data)
    filename = f.filename or "unknown"
    now = utc_now()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO file_hashes (user_id, username, filename, filesize, sha256, created_at)
      VALUES (%s, %s, %s, %s, %s, %s)
    """, (int(current_user.id), current_user.username, filename, filesize, file_hash, now))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "message": "Hash stored successfully",
        "filename": filename,
        "filesize": filesize,
        "hash": file_hash,
        "created_at": now.isoformat()
    })


@app.route("/api/verify", methods=["POST"])
@login_required
def api_verify():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    data = f.read()
    if not data:
        return jsonify({"error": "Uploaded file is empty"}), 400

    actual_hash = sha256_bytes(data)
    filesize = len(data)
    filename = f.filename or "unknown"

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
      SELECT sha256, created_at
      FROM file_hashes
      WHERE user_id=%s AND filename=%s
      ORDER BY id DESC
      LIMIT 1
    """, (int(current_user.id), filename))
    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return jsonify({
            "status": "NOT_REGISTERED",
            "message": "No stored hash found for this filename. Please Register/Store hash first.",
            "filename": filename,
            "filesize": filesize,
            "actual_hash": actual_hash
        })

    expected_hash = row["sha256"]
    stored_time = row["created_at"]

    if expected_hash == actual_hash:
        cur.close()
        conn.close()
        return jsonify({
            "status": "SAFE",
            "message": "File integrity verified. No changes detected.",
            "filename": filename,
            "filesize": filesize,
            "stored_at": stored_time.isoformat() if stored_time else None,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash
        })

    now = utc_now()
    cur.execute("""
      INSERT INTO tamper_logs (user_id, username, filename, expected_sha256, actual_sha256, created_at)
      VALUES (%s, %s, %s, %s, %s, %s)
    """, (int(current_user.id), current_user.username, filename, expected_hash, actual_hash, now))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "status": "TAMPERED",
        "message": "ALERT: File has been modified (hash mismatch).",
        "filename": filename,
        "filesize": filesize,
        "stored_at": stored_time.isoformat() if stored_time else None,
        "expected_hash": expected_hash,
        "actual_hash": actual_hash,
        "logged_at": now.isoformat()
    })


@app.route("/api/compare", methods=["POST"])
@login_required
def api_compare():
    if "file1" not in request.files or "file2" not in request.files:
        return jsonify({"error": "Both files are required"}), 400

    f1 = request.files["file1"]
    f2 = request.files["file2"]

    d1 = f1.read()
    d2 = f2.read()

    if not d1 or not d2:
        return jsonify({"error": "One of the uploaded files is empty"}), 400

    h1 = sha256_bytes(d1)
    h2 = sha256_bytes(d2)

    return jsonify({
        "file1": {"name": f1.filename or "file1", "size": len(d1), "hash": h1},
        "file2": {"name": f2.filename or "file2", "size": len(d2), "hash": h2},
        "result": "MATCH" if h1 == h2 else "MISMATCH"
    })


print("Register API hit")
if __name__ == "__main__":
    app.run(debug=True)