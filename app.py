rom flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os
import bcrypt
from datetime import datetime

from utils.database import init_db, get_connection
from utils.encryption import encrypt_file, decrypt_file
from utils.otp_handler import generate_otp_secret, generate_otp, verify_otp
from utils.malware_checker import is_safe_file

app = Flask(__name__)
app.secret_key = "supersecretkey"

# =========================
# Folders and Paths
# =========================

UPLOAD_FOLDER = "uploads/encrypted_files"
LOG_FOLDER = "logs"
LOG_FILE = os.path.join(LOG_FOLDER, "security.log")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)


# =========================
# Helper Function: Logging
# =========================

def write_log(action, username):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save in text log file
    with open(LOG_FILE, "a") as file:
        file.write(f"[{timestamp}] {username}: {action}\n")

    # Save in database logs table
    conn = get_connection()
    conn.execute(
        "INSERT INTO logs (action, username, timestamp) VALUES (?, ?, ?)",
        (action, username, timestamp)
    )
    conn.commit()
    conn.close()


# =========================
# Initial Setup
# =========================

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads/encrypted_files"
LOG_FOLDER = "logs"

# Initialize database here
init_db()


# =========================
# Home Page
# =========================

@app.route("/")
def home():
    return render_template("home.html")


# =========================
# Register User
# =========================

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # Hash password using bcrypt
    password_hash = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()

    # Generate OTP secret for user
    otp_secret = generate_otp_secret()

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, otp_secret)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, otp_secret)
        )
        conn.commit()

        flash("Registration successful. Please login.")
        write_log("User registered successfully", username)

    except:
        flash("User already exists.")

    conn.close()
    return redirect(url_for("home"))


# =========================
# Login Step 1: Password Verification
# =========================

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = get_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if user and bcrypt.checkpw(
        password.encode(),
        user["password_hash"].encode()
    ):
        session["temp_user"] = username
        session["otp_secret"] = user["otp_secret"]

        # Generate OTP (shown in terminal for demo)
        otp = generate_otp(user["otp_secret"])
        print(f"\nOTP for {username}: {otp}\n")

        write_log("Password verified, OTP generated", username)

        return redirect(url_for("otp_page"))

    flash("Invalid credentials")
    write_log("Failed login attempt", username)

    return redirect(url_for("home"))


# =========================
# Login Step 2: OTP Verification
# =========================

@app.route("/otp", methods=["GET", "POST"])
def otp_page():
    if "temp_user" not in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        user_otp = request.form["otp"]
        secret = session.get("otp_secret")

        if verify_otp(secret, user_otp):
            session["user"] = session["temp_user"]

            session.pop("temp_user", None)
            session.pop("otp_secret", None)

            write_log("Logged in successfully", session["user"])

            return redirect(url_for("dashboard"))

        flash("Invalid OTP")
        write_log(
            "Invalid OTP entered",
            session.get("temp_user", "Unknown")
        )

    return render_template("otp.html")


# =========================
# Dashboard
# =========================

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "dashboard.html",
        user=session["user"]
    )


# =========================
# Upload File
# =========================

@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("home"))

    if "file" not in request.files:
        flash("No file selected")
        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file selected")
        return redirect(url_for("dashboard"))

    # Malware detection
    if not is_safe_file(file.filename):
        flash("Blocked file type detected")

        write_log(
            f"Blocked malicious upload: {file.filename}",
            session["user"]
        )

        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Save file
    file.save(filepath)

    # Encrypt file after upload
    encrypt_file(filepath)

    # Save metadata to database
    conn = get_connection()

    conn.execute(
        """
        INSERT INTO files
        (filename, owner, upload_time, encrypted_path)
        VALUES (?, ?, ?, ?)
        """,
        (
            filename,
            session["user"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            filepath
        )
    )

    conn.commit()
    conn.close()

    write_log(
        f"Uploaded encrypted file: {filename}",
        session["user"]
    )

    flash("File uploaded and encrypted successfully")

    return redirect(url_for("dashboard"))


# =========================
# View User Files
# =========================

@app.route("/files")
def files():
    if "user" not in session:
        return redirect(url_for("home"))

    conn = get_connection()

    files = conn.execute(
        """
        SELECT * FROM files
        WHERE owner = ?
        """,
        (session["user"],)
    ).fetchall()

    conn.close()

    return render_template(
        "files.html",
        files=files
    )


# =========================
# View / Decrypt File
# =========================

@app.route("/view/<filename>")
def view_file(filename):
    if "user" not in session:
        return redirect(url_for("home"))

    conn = get_connection()

    file_data = conn.execute(
        """
        SELECT * FROM files
        WHERE filename = ? AND owner = ?
        """,
        (filename, session["user"])
    ).fetchone()

    conn.close()

    if not file_data:
        flash("Access denied")

        write_log(
            f"Unauthorized access attempt to {filename}",
            session["user"]
        )

        return redirect(url_for("files"))

    try:
        content = decrypt_file(
            file_data["encrypted_path"]
        ).decode(errors="ignore")

    except:
        content = "Unable to preview this file format."

    write_log(
        f"Viewed file: {filename}",
        session["user"]
    )

    return render_template(
        "view.html",
        content=content
    )


# =========================
# Admin Panel
# =========================

@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect(url_for("home"))

    conn = get_connection()

    user = conn.execute(
        """
        SELECT * FROM users
        WHERE username = ?
        """,
        (session["user"],)
    ).fetchone()

    conn.close()

    if not user or user["role"] != "admin":
        flash("Admin access only")
        return redirect(url_for("dashboard"))

    return render_template("admin.html")


# =========================
# View Security Logs
# =========================

@app.route("/logs")
def logs():
    if "user" not in session:
        return redirect(url_for("home"))

    if not os.path.exists(LOG_FILE):
        logs_data = "No logs available yet."

    else:
        with open(LOG_FILE, "r") as file:
            logs_data = file.read()

    return render_template(
        "logs.html",
        logs=logs_data
    )


# =========================
# Logout
# =========================

@app.route("/logout")
def logout():
    username = session.get("user", "Unknown User")

    write_log("Logged out", username)

    session.clear()

    flash("Logged out successfully")

    return redirect(url_for("home"))


# =========================
# Run Application
# =========================

if __name__ == "__main__":
    app.run(debug=True)
