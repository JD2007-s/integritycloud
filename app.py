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
import requests
import psycopg
from psycopg.rows import dict_row

from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required, logout_user, current_user
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Optional email (only if env vars configured)
try:
    from flask_mail import Mail, Message
    MAIL_AVAILABLE = False
except ImportError:
    MAIL_AVAILABLE = False

# -------------------- AI SUMMARY FEATURE --------------------
def get_ai_summary(file_text):
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    
    # Securely fetches the key from Render or your local .env file
    nvidia_key = os.environ.get("NVIDIA_AI_KEY")
    
    if not nvidia_key:
        return "AI key not configured."

    headers = {
        "Authorization": f"Bearer {nvidia_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "meta/llama-3.2-3b-instruct",
        "messages": [
            {"role": "system", "content": "You are a helpful cloud security assistant. Summarize the following text in exactly 2 short sentences."},
            {"role": "user", "content": file_text[:2000]} # Read up to 2000 characters to keep it fast
        ],
        "max_tokens": 100
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data['choices'][0]['message']['content']
        else:
            return "AI Summary Error."
    except Exception as e:
        return "AI Summary not available."

# -------------------- APP SETUP --------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")  # MUST set SECRET_KEY in Render

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# --- SUPABASE CONFIGURATION ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

serializer = URLSafeTimedSerializer(app.secret_key)

# --- Email Configuration (Gmail SMTP) ---
mail = Mail()
if MAIL_AVAILABLE:
    app.config["MAIL_SERVER"] = "smtp.gmail.com"
    app.config["MAIL_PORT"] = 587
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "solankiparul2026@gmail.com")
    app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "jqlcsqbtjunpvvjz")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER", "solankiparul2026@gmail.com")
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

def format_bytes(size):
    if not size:
        return "0 Bytes"
    if size < 1024:
        return f"{size} Bytes"
    elif size < 1048576:
        return f"{size / 1024:.2f} KB"
    else:
        return f"{size / 1048576:.2f} MB"

@app.get("/health")
def health():
    return "👍", 200


# -------------------- DATABASE INIT --------------------
def init_db():
    with db_cursor() as (conn, cur):
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

        cur.execute("SELECT COUNT(*) AS c FROM users")
        if cur.fetchone()["c"] == 0:
            admin_user = os.environ.get("ADMIN_USERNAME", "admin")
            admin_email = os.environ.get("ADMIN_EMAIL", "admin_fic@gmail.com")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "adminfic2026")
            cur.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, 'admin')
            """, (admin_user, admin_email, generate_password_hash(admin_pass)))
            print("✅ Default admin created.")

try:
    init_db()
    print("✅ Database tables verified/created successfully.")
except Exception as e:
    print(f"❌ CRITICAL DB INIT ERROR: {e}")
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
            cur.execute("SELECT id, email FROM users WHERE deleted_at IS NULL AND lower(email)=%s LIMIT 1", (email,))
            row = cur.fetchone()

        if row:
            token = serializer.dumps({"user_id": row["id"]})
            # Make sure this points to your live Render URL so the link works!
            base = (os.environ.get("APP_BASE_URL") or request.host_url).rstrip("/")
            reset_link = f"{base}{url_for('reset_password', token=token)}"

            # --- NEW GOOGLE SCRIPT EMAIL API ---
            # Paste your copied Web App URL inside these quotes:
            script_url = "PASTE_YOUR_COPIED_LINK_HERE"
            
            payload = {
                "to": row["email"],
                "subject": "Password Reset - IntegrityCloud",
                "body": f"Hello,\n\nYou requested a password reset for IntegrityCloud.\nClick the link below to set a new password.\n\n{reset_link}"
            }
            
            try:
                # This sends a secure web request to Google, bypassing Render's firewall!
                requests.post(script_url, data=payload, timeout=15)
                flash("✅ A password reset link has been emailed to you!", "success")
            except Exception as e:
                print(f"API send failed: {e}")
                flash("⚠️ Email API failed to connect.", "error")
            # -----------------------------------

        else:
            flash("❌ We couldn't find an account with that email address.", "error")

        return render_template("forgot.html")

    return render_template("forgot.html")
# -------------------- PAGES --------------------
@app.route("/home")
@login_required
def home():
    return render_template("index.html")

@app.route("/compare")
@login_required
def compare_page():
    return render_template("compare.html")


# -------------------- CORE LOGIC (JSON API ROUTES) --------------------
@app.route("/register_file", methods=["POST"])
@login_required
def register_file():
    uploaded_file = request.files.get("file")
    
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"status": "error", "message": "No file selected."}), 400

    try:
        filename = secure_filename(uploaded_file.filename)
        
        # 1. Read file into memory to calculate hash
        file_bytes = uploaded_file.read()
        file_hash = sha256_bytes(file_bytes)
        filesize = len(file_bytes)
        
        # 2. AUTOMATIC SUPABASE UPLOAD
        endpoint = f"{SUPABASE_URL}/storage/v1/object/integrity-files/{filename}"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": uploaded_file.content_type,
            "x-upsert": "true" # Overwrites if file exists
        }
        
        cloud_response = requests.post(endpoint, headers=headers, data=file_bytes)
        
        if cloud_response.status_code not in [200, 201]:
            print(f"Cloud Storage Error: {cloud_response.text}")
            return jsonify({"status": "error", "message": "Cloud storage failed. Try again."}), 500

        # 3. Save to Database
        with db_cursor() as (conn, cur):
            cur.execute("""
                INSERT INTO file_hashes (user_id, username, filename, filesize, sha256, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (current_user.id, current_user.username, filename, filesize, file_hash, utc_now()))
            
        # 4. NEW AI FEATURE: Generate summary if it's a text file
        ai_summary = "Not a text file."
        if filename.endswith('.txt'):
            file_text = file_bytes.decode('utf-8', errors='ignore')
            ai_summary = get_ai_summary(file_text)

        return jsonify({
            "status": "success", 
            "message": "File secured in Supabase and Database!",
            "filename": filename,
            "filesize": filesize,
            "hash": file_hash,
            "ai_summary": ai_summary
        }), 200
        
    except Exception as e:
        print(f"System Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/verify_file", methods=["POST"])
@login_required
def verify_file():
    uploaded_file = request.files.get("file")
    
    if uploaded_file and uploaded_file.filename:
        filename = secure_filename(uploaded_file.filename)
        file_bytes = uploaded_file.read() 
        actual_hash = sha256_bytes(file_bytes) 
        
        try:
            with db_cursor() as (conn, cur):
                cur.execute("""
                    SELECT sha256 FROM file_hashes 
                    WHERE user_id=%s AND filename=%s 
                    ORDER BY id DESC LIMIT 1
                """, (current_user.id, filename))
                row = cur.fetchone()
                
                if not row:
                    return jsonify({
                        "status": "error", 
                        "message": f"No record found for '{filename}'. Please register it first."
                    }), 404
                    
                expected_hash = row["sha256"]
                
                if actual_hash == expected_hash:
                    return jsonify({
                        "status": "success", 
                        "message": "File verified! It is perfectly intact."
                    }), 200
                else:
                    cur.execute("""
                        INSERT INTO tamper_logs (user_id, username, filename, expected_sha256, actual_sha256, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (current_user.id, current_user.username, filename, expected_hash, actual_hash, utc_now()))
                    
                    return jsonify({
                        "status": "error", 
                        "message": "TAMPER DETECTED! This file has been modified."
                    }), 400
                    
        except Exception as e:
            return jsonify({"status": "error", "message": "Database error occurred during verification."}), 500

    return jsonify({"status": "error", "message": "No file was selected."}), 400


# -------------------- DASHBOARD --------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = int(current_user.id)
    STORAGE_LIMIT_MB = 512
    storage_limit_bytes = STORAGE_LIMIT_MB * 1024 * 1024

    with db_cursor() as (conn, cur):
        cur.execute("SELECT COUNT(*) AS c FROM file_hashes WHERE user_id=%s", (user_id,))
        hashes_count = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) AS c FROM tamper_logs WHERE user_id=%s", (user_id,))
        tamper_count = cur.fetchone()["c"]

        cur.execute("SELECT COALESCE(SUM(filesize), 0) AS total_storage FROM file_hashes WHERE user_id=%s", (user_id,))
        storage_bytes = cur.fetchone()["total_storage"]

        cur.execute("""
            SELECT id, filename, filesize, sha256, created_at
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

    raw_percentage = (storage_bytes / storage_limit_bytes) * 100 if storage_limit_bytes > 0 else 0
    storage_percentage = 1 if 0 < raw_percentage < 1 else min(raw_percentage, 100)

    return render_template(
        "dashboard.html",
        hashes_count=hashes_count,
        tamper_count=tamper_count,
        hashes=hashes,
        tampers=tampers,
        user=current_user,
        storage_formatted=format_bytes(storage_bytes),
        storage_limit_mb=STORAGE_LIMIT_MB,
        storage_percentage=round(storage_percentage, 1)
    )

# -------------------- DELETE FEATURE --------------------
@app.route("/delete_file/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    with db_cursor() as (conn, cur):
        cur.execute("SELECT filename FROM file_hashes WHERE id=%s AND user_id=%s", (file_id, current_user.id))
        row = cur.fetchone()
        
        if row:
            filename = row['filename']
            
            endpoint = f"{SUPABASE_URL}/storage/v1/object/integrity-files/{filename}"
            headers = {
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}"
            }
            try:
                cloud_res = requests.delete(endpoint, headers=headers)
                if cloud_res.status_code not in [200, 204]:
                    print(f"Supabase Delete Warning: {cloud_res.text}")
            except Exception as e:
                print(f"Cloud Delete Error: {e}")

            cur.execute("DELETE FROM file_hashes WHERE id=%s", (file_id,))
            flash(f"✅ {filename} has been removed from cloud storage.", "success")
        else:
            flash("❌ File not found or unauthorized.", "error")
            
    return redirect(url_for('dashboard'))

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
        
        cur.execute("SELECT COALESCE(SUM(filesize), 0) AS c FROM file_hashes")
        global_storage_bytes = cur.fetchone()["c"]

        cur.execute("""
            SELECT 
                u.id, u.username, u.email, u.role, u.created_at,
                COALESCE(SUM(f.filesize), 0) AS total_storage,
                COUNT(f.id) AS file_count
            FROM users u
            LEFT JOIN file_hashes f ON u.id = f.user_id
            WHERE u.deleted_at IS NULL
            GROUP BY u.id, u.username, u.email, u.role, u.created_at
            ORDER BY u.id DESC
            LIMIT 200
        """)
        users_raw = cur.fetchall()
        
        formatted_users = []
        for u in users_raw:
            user_dict = dict(u)
            user_dict["formatted_storage"] = format_bytes(user_dict["total_storage"])
            
            storage_mb = user_dict["total_storage"] / (1024 * 1024)
            bill = 5.00 + (storage_mb * 0.15) + (user_dict["file_count"] * 0.05)
            user_dict["bill"] = f"${bill:.2f}"
            
            formatted_users.append(user_dict)

    GLOBAL_LIMIT_MB = 512
    raw_pct = (global_storage_bytes / (GLOBAL_LIMIT_MB * 1024 * 1024)) * 100
    global_storage_percentage = 1 if 0 < raw_pct < 1 else min(raw_pct, 100)

    return render_template(
        "admin.html",
        total_users=total_users,
        total_hashes=total_hashes,
        total_tampers=total_tampers,
        users=formatted_users,
        global_storage_formatted=format_bytes(global_storage_bytes),
        global_storage_percentage=round(global_storage_percentage, 1),
        global_limit_mb=GLOBAL_LIMIT_MB
    )
# -------------------- LEGAL PAGES --------------------
@app.route("/privacy")
def privacy():
    return """
    <body style="background-color: #09090b; color: #e4e4e7; font-family: sans-serif; display: flex; justify-content: center; padding-top: 100px;">
        <div style="max-width: 600px; padding: 30px; background: #18181b; border: 1px solid #27272a; border-radius: 15px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
            <h2 style="color: #10b981; margin-top: 0;">Privacy Policy</h2>
            <p style="line-height: 1.6; color: #a1a1aa;">This application is an academic project developed for university demonstration purposes. We respect your privacy. No real-world user data is tracked, sold, or distributed to third parties.</p>
            <br>
            <a href="/" style="color: #3b82f6; text-decoration: none; font-weight: bold;">&larr; Back to IntegrityCloud</a>
        </div>
    </body>
    """

@app.route("/terms")
def terms():
    return """
    <body style="background-color: #09090b; color: #e4e4e7; font-family: sans-serif; display: flex; justify-content: center; padding-top: 100px;">
        <div style="max-width: 600px; padding: 30px; background: #18181b; border: 1px solid #27272a; border-radius: 15px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
            <h2 style="color: #3b82f6; margin-top: 0;">Terms of Service</h2>
            <p style="line-height: 1.6; color: #a1a1aa;">By using IntegrityCloud, you acknowledge that this is a student-developed security project. While we use advanced cryptography to secure files, please do not upload highly sensitive, real-world personal data to this demonstration environment.</p>
            <br>
            <a href="/" style="color: #3b82f6; text-decoration: none; font-weight: bold;">&larr; Back to IntegrityCloud</a>
        </div>
    </body>
    """

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)