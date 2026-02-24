from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, abort, flash
)
import hashlib
import os
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

# Optional email
try:
    from flask_mail import Mail, Message
    MAIL_AVAILABLE = True
except Exception:
    MAIL_AVAILABLE = False


# -------------------- APP SETUP --------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

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
    return os.environ.get("DATABASE_URL")

@contextmanager
def db_cursor():
    db_url = get_database_url()
    if not db_url:
        raise RuntimeError("DATABASE_URL not set in Render Environment Variables.")
    conn = psycopg.connect(db_url, sslmode="require", row_factory=dict_row)
    try:
        cur = conn.cursor()
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# -------------------- DATABASE INITIALIZATION & MIGRATION --------------------
def init_db():
    with db_cursor() as (conn, cur):
        # 1. USERS table
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

        # 2. FILE HASHES table
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

        # 3. TAMPER LOGS table
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

        # --- AUTO-MIGRATION LOGIC ---
        # This checks if the user_id column exists. If not, it adds it.
        # This fixes the "column user_id does not exist" error automatically.
        for table in ['file_hashes', 'tamper_logs']:
            cur.execute(f"""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='{table}' AND column_name='user_id'
            """)
            if not cur.fetchone():
                print(f"⚠️ Migrating {table}: Adding user_id column...")
                cur.execute(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER;")
                # Re-add foreign key if it was missing
                cur.execute(f"""
                    ALTER TABLE {table} 
                    ADD CONSTRAINT fk_{table}_user_migrated 
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_file_hashes_user_id ON file_hashes(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tamper_logs_user_id ON tamper_logs(user_id)")

        # Create Admin
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

try:
    init_db()
except Exception as e:
    print("DB init error:", e)


# -------------------- USER MODEL --------------------
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role="user"):
        self.id = id # Keep as original type (int)
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


# -------------------- ROUTES --------------------
@app.route("/", methods=["GET", "POST"])
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

    return render_template("signup.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("✅ Logged out", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    with db_cursor() as (conn, cur):
        user_id = int(current_user.id)
        
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
            return jsonify({"status": "NOT_REGISTERED", "filename": filename})

        expected_hash = row["sha256"]
        if expected_hash == actual_hash:
            return jsonify({"status": "SAFE", "filename": filename})

        # Tampered
        now = utc_now()
        cur.execute("""
            INSERT INTO tamper_logs (user_id, username, filename, expected_sha256, actual_sha256, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (int(current_user.id), current_user.username, filename, expected_hash, actual_hash, now))

        return jsonify({"status": "TAMPERED", "filename": filename})

# (Keep your other routes like /admin, /home, /compare, etc. exactly as they were)

if __name__ == "__main__":
    app.run(debug=True)