from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, abort, flash
)
import hashlib
import os
import sys
from datetime import datetime, timezone
from functools import wraps
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required, logout_user, current_user
)

from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Optional email (only if env vars configured)
try:
    from flask_mail import Mail, Message
    MAIL_AVAILABLE = True
except Exception:
    MAIL_AVAILABLE = False


# -------------------- APP SETUP --------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")  # MUST set SECRET_KEY in Render

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

serializer = URLSafeTimedSerializer(app.secret_key)

mail = Mail()
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

def get_database_url():
    # Render provides DATABASE_URL for Postgres
    return os.environ.get("DATABASE_URL")

@contextmanager
def db_cursor():
    db_url = get_database_url()
    if not db_url:
        raise RuntimeError("DATABASE_URL not set in Render Environment Variables.")
    
    # FIX: Removed hardcoded sslmode="require". 
    # Render's internal URLs don't support it, and external URLs already include it.
    conn = psycopg.connect(db_url, row_factory=dict_row)
    try:
        cur = conn.cursor()
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

@app.get("/health")
def health():
    return "👍", 200


# -------------------- DATABASE INIT --------------------
def init_db():
    with db_cursor() as (conn, cur):
        # Users (soft delete via deleted_at)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            deleted_at TIMESTAMP NULL
        )
        """)

        # File hashes
        cur.execute("""
        CREATE TABLE IF NOT EXISTS file_hashes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            filename TEXT NOT NULL,
            filesize INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            CONSTRAINT fk_filehash_user FOREIGN KEY (user_id)
                REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        # Tamper logs
        cur.execute("""
        CREATE TABLE IF NOT EXISTS tamper_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            filename TEXT NOT NULL,
            expected_sha256 TEXT NOT NULL,
            actual_sha256 TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            CONSTRAINT fk_tamper_user FOREIGN KEY (user_id)
                REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_file_hashes_user_id ON file_hashes(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tamper_logs_user_id ON tamper_logs(user_id)")

        # Create default admin if no users
        cur.execute("SELECT COUNT(*) AS c FROM users")
        if cur.fetchone()["c"] == 0:
            admin_user = os.environ.get("ADMIN_USERNAME", "admin")
            admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "admin123")
            cur.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, 'admin')
            """, (admin_user, admin_email, generate_password_hash(admin_pass)))
            print("✅ Default admin created.")


# FIX: Do not silently ignore initialization errors. 
# If DB fails to create, the app must stop so you can see the error in Render Logs!
try:
    init_db()
    print("✅ Database tables verified/created successfully.")
except Exception as e:
    print(f"❌ CRITICAL DB INIT ERROR: {e}")
    # Force crash so Gunicorn shows the error in logs instead of 500 error later
    sys.exit(1)


# -------------------- USER MODEL --------------------
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role="user"):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role or "user"

    @property
    def is_admin(self):
        return self.role == "admin"

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    with db_cursor() as (conn, cur):
        cur.execute("""
            SELECT id, username, email, password_hash, role
            FROM users
            WHERE id=%s AND deleted_at IS NULL
        """, (int(user_id),))
        row = cur.fetchone()
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
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        user_input = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""

        with db_cursor() as (conn, cur):
            cur.execute("""
                SELECT id, username, email, password_hash, role
                FROM users
                WHERE deleted_at IS NULL
                  AND (lower(username)=%s OR lower(email)=%s)
                LIMIT 1
            """, (user_input, user_input))
            row = cur.fetchone()

        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row["id"], row["username"], row["email"], row["password_hash"], row["role"]))
            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        flash("❌ Invalid username/email or password", "error")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "")

        if not username or not email or not password:
            flash("❌ All fields are required", "error")
            return render_template("signup.html")

        if len(password) < 6:
            flash("❌ Password must be at least 6 characters", "error")
            return render_template("signup.html")

        pw_hash = generate_password_hash(password)

        try:
            with db_cursor() as (conn, cur):
                cur.execute("""
                    INSERT INTO users(username,email,password_hash,role)
                    VALUES (%s,%s,%s,'user')
                    RETURNING id, role
                """, (username, email, pw_hash))
                created = cur.fetchone()

            login_user(User(created["id"], username, email, pw_hash, created["role"]))
            flash("✅ Account created!", "success")
            return redirect(url_for("dashboard"))
        except Exception:
            flash("❌ Username or Email already exists", "error")

    return render_template("signup.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("✅ Logged out", "success")
    return redirect(url_for("login"))


# -------------------- FORGOT / RESET --------------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        with db_cursor() as (conn, cur):
            cur.execute("""
                SELECT id, email
                FROM users
                WHERE deleted_at IS NULL AND lower(email)=%s
                LIMIT 1
            """, (email,))
            row = cur.fetchone()

        reset_link = None
        if row:
            token = serializer.dumps({"user_id": row["id"]})
            base = (os.environ.get("APP_BASE_URL") or request.host_url).rstrip("/")
            reset_link = f"{base}{url_for('reset_password', token=token)}"

            # Send email if configured, else show link in UI (demo)
            if (
                MAIL_AVAILABLE
                and app.config.get("MAIL_SERVER")
                and app.config.get("MAIL_USERNAME")
                and app.config.get("MAIL_PASSWORD")
                and app.config.get("MAIL_DEFAULT_SENDER")
            ):
                try:
                    msg = Message("Password Reset - IntegrityCloud", recipients=[row["email"]])
                    msg.body = f"Reset your password (valid 30 minutes): {reset_link}"
                    mail.send(msg)
                    reset_link = None
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
        data = serializer.loads(token, max_age=1800)  # 30 min
        user_id = int(data["user_id"])
    except SignatureExpired:
        return "Reset link expired. Please request again.", 400
    except (BadSignature, KeyError, ValueError):
        return "Invalid reset link.", 400

    if request.method == "POST":
        new_password = request.form.get("password") or ""
        if len(new_password) < 6:
            return render_template("reset.html", error="Password must be at least 6 characters")

        pw_hash = generate_password_hash(new_password)
        with db_cursor() as (conn, cur):
            cur.execute("""
                UPDATE users SET password_hash=%s
                WHERE id=%s AND deleted_at IS NULL
            """, (pw_hash, user_id))

        flash("✅ Password updated. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("reset.html")


# -------------------- PAGES --------------------
@app.route("/home")
@login_required
def home():
    return render_template("index.html")


@app.route("/compare")
@login_required
def compare_page():
    return render_template("compare.html")


# -------------------- DASHBOARD --------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = int(current_user.id)

    with db_cursor() as (conn, cur):
        cur.execute("SELECT COUNT(*) AS c FROM file_hashes WHERE user_id=%s", (user_id,))
        hashes_count = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) AS c FROM tamper_logs WHERE user_id=%s", (user_id,))
        tamper_count = cur.fetchone()["c"]

        cur.execute("""
            SELECT filename, filesize, sha256, created_at
            FROM file_hashes
            WHERE user_id=%s
            ORDER BY id DESC LIMIT 20
        """, (user_id,))
        hashes = cur.fetchall()

        cur.execute("""
            SELECT filename, expected_sha256, actual_sha256, created_at
            FROM tamper_logs
            WHERE user_id=%s
            ORDER BY id DESC LIMIT 20
        """, (user_id,))
        tampers = cur.fetchall()

    return render_template(
        "dashboard.html",
        hashes_count=hashes_count,
        tamper_count=tamper_count,
        hashes=hashes,
        tampers=tampers
    )

# -------------------- ADMIN --------------------
@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    with db_cursor() as (conn, cur):
        cur.execute("SELECT COUNT(*) AS c FROM users WHERE deleted_at IS NULL")
        total_users = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) AS c FROM file_hashes")
        total_hashes = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) AS c FROM tamper_logs")
        total_tampers = cur.fetchone()["c"]

        cur.execute("""
            SELECT id, username, email, role, created_at
            FROM users
            WHERE deleted_at IS NULL
            ORDER BY id DESC
            LIMIT 200
        """)
        users = cur.fetchall()

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
        flash("❌ You cannot modify your own role.", "error")
        return redirect(url_for("admin_panel"))

    with db_cursor() as (conn, cur):
        cur.execute("""
            UPDATE users SET role='admin'
            WHERE id=%s AND deleted_at IS NULL
        """, (user_id,))
    flash("✅ User promoted to admin.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/demote/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def demote_user(user_id):
    if int(current_user.id) == user_id:
        flash("❌ You cannot demote yourself.", "error")
        return redirect(url_for("admin_panel"))

    with db_cursor() as (conn, cur):
        cur.execute("""
            UPDATE users SET role='user'
            WHERE id=%s AND deleted_at IS NULL
        """, (user_id,))
    flash("✅ User set to normal user.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def soft_delete_user(user_id):
    if int(current_user.id) == user_id:
        flash("❌ You cannot delete yourself.", "error")
        return redirect(url_for("admin_panel"))

    with db_cursor() as (conn, cur):
        cur.execute("""
            UPDATE users SET deleted_at=%s
            WHERE id=%s AND deleted_at IS NULL
        """, (utc_now(), user_id))
    flash("✅ User soft-deleted.", "success")
    return redirect(url_for("admin_panel"))


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

    with db_cursor() as (conn, cur):
        cur.execute("""
            INSERT INTO file_hashes (user_id, username, filename, filesize, sha256, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (int(current_user.id), current_user.username, filename, filesize, file_hash, now))

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

    with db_cursor() as (conn, cur):
        cur.execute("""
            SELECT sha256, created_at
            FROM file_hashes
            WHERE user_id=%s AND filename=%s
            ORDER BY id DESC LIMIT 1
        """, (int(current_user.id), filename))
        row = cur.fetchone()

        if not row:
            return jsonify({
                "status": "NOT_REGISTERED",
                "message": "No stored hash found for this filename. Store hash first.",
                "filename": filename,
                "filesize": filesize,
                "actual_hash": actual_hash
            })

        expected_hash = row["sha256"]
        stored_time = row["created_at"]

        if expected_hash == actual_hash:
            return jsonify({
                "status": "SAFE",
                "message": "File integrity verified. No changes detected.",
                "filename": filename,
                "filesize": filesize,
                "stored_at": stored_time.isoformat() if stored_time else None,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash
            })

        # Tampered -> log
        now = utc_now()
        cur.execute("""
            INSERT INTO tamper_logs (user_id, username, filename, expected_sha256, actual_sha256, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (int(current_user.id), current_user.username, filename, expected_hash, actual_hash, now))

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


if __name__ == "__main__":
    app.run(debug=True)