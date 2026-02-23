from flask import Flask, render_template, request, redirect, session, jsonify
import hashlib
import os
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import RealDictCursor


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")


# Dummy login credentials (same as your code)
USERNAME = "admin"
PASSWORD = "admin123"


# -------------------- DB (PostgreSQL on Render) --------------------
def get_db():
    """
    Connect to Render PostgreSQL using DATABASE_URL env var.
    sslmode=require is commonly needed for external Postgres URLs.
    """
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")

    return psycopg2.connect(db_url, sslmode="require", cursor_factory=RealDictCursor)


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # file_hashes table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS file_hashes (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        filename TEXT NOT NULL,
        filesize INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL
    )
    """)

    # tamper_logs table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tamper_logs (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        filename TEXT NOT NULL,
        expected_sha256 TEXT NOT NULL,
        actual_sha256 TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL
    )
    """)

    conn.commit()
    cur.close()
    conn.close()


# Initialize DB tables at startup
# (Render will run this when service boots)
try:
    init_db()
except Exception as e:
    # Don't crash local dev if DATABASE_URL isn't set.
    # On Render, DATABASE_URL will be set.
    print("DB init warning:", str(e))


# -------------------- HASH --------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return datetime.now(timezone.utc)


# -------------------- AUTH --------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == USERNAME and request.form.get("password") == PASSWORD:
            session["user"] = USERNAME
            return redirect("/home")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# -------------------- PAGES --------------------
@app.route("/home")
def home():
    if "user" not in session:
        return redirect("/")
    return render_template("index.html")


@app.route("/compare")
def compare_page():
    if "user" not in session:
        return redirect("/")
    return render_template("compare.html")


# -------------------- API: REGISTER (STORE HASH) --------------------
@app.route("/api/register", methods=["POST"])
def api_register():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

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
      INSERT INTO file_hashes (username, filename, filesize, sha256, created_at)
      VALUES (%s, %s, %s, %s, %s)
    """, (session["user"], filename, filesize, file_hash, now))

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


# -------------------- API: VERIFY INTEGRITY --------------------
@app.route("/api/verify", methods=["POST"])
def api_verify():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

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

    # Find latest stored hash for this filename (per user)
    cur.execute("""
      SELECT sha256, created_at
      FROM file_hashes
      WHERE username = %s AND filename = %s
      ORDER BY id DESC
      LIMIT 1
    """, (session["user"], filename))

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

    # Tampered → log it
    now = utc_now()
    cur.execute("""
      INSERT INTO tamper_logs (username, filename, expected_sha256, actual_sha256, created_at)
      VALUES (%s, %s, %s, %s, %s)
    """, (session["user"], filename, expected_hash, actual_hash, now))

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


# -------------------- API: COMPARE TWO FILES --------------------
@app.route("/api/compare", methods=["POST"])
def api_compare():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

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

    same = (h1 == h2)

    return jsonify({
        "file1": {"name": f1.filename or "file1", "size": len(d1), "hash": h1},
        "file2": {"name": f2.filename or "file2", "size": len(d2), "hash": h2},
        "result": "MATCH" if same else "MISMATCH"
    })


if __name__ == "__main__":
    # Local dev only; Render uses gunicorn
    app.run(debug=True)