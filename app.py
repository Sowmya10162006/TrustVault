
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
import os
import hashlib
import uuid

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.join(basedir, "instance")
os.makedirs(instance_dir, exist_ok=True)

database_path = os.path.join(instance_dir, "trustvault.db")
UPLOAD_FOLDER = os.path.join(instance_dir, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx"}
MAX_FILE_SIZE = 10 * 1024 * 1024

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + database_path
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "local-dev-key-change-before-deployment"
)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(
        db.String(150), unique=True, nullable=False, index=True
    )
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    uploaded_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )
    owner = db.relationship("User", backref="documents")
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill in all fields.")
            return redirect(url_for("register"))

        if len(password) < 12:
            flash("Password must contain at least 12 characters.")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.")
            return redirect(url_for("register"))

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            role="user"
        )
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")
@app.route("/dashboard")
@login_required
def dashboard():
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <title>TrustVault | Dashboard</title>

        <style>
            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f1f5f9;
                color: #1e293b;
            }}

            .navbar {{
                background: #173b68;
                color: white;
                padding: 18px 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}

            .logo {{
                font-size: 24px;
                font-weight: bold;
            }}

            .user {{
                font-size: 14px;
            }}

            .container {{
                max-width: 900px;
                margin: 50px auto;
                padding: 0 20px;
            }}

            .welcome {{
                background: white;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.08);
                margin-bottom: 25px;
            }}

            .welcome h1 {{
                margin-top: 0;
                color: #173b68;
            }}

            .welcome p {{
                color: #64748b;
            }}

            .cards {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
            }}

            .card {{
                background: white;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            }}

            .card h2 {{
                color: #173b68;
                margin-top: 0;
            }}

            .card p {{
                color: #64748b;
                line-height: 1.5;
            }}

            .button {{
                display: inline-block;
                padding: 11px 20px;
                background: #173b68;
                color: white;
                text-decoration: none;
                border-radius: 6px;
                margin-top: 10px;
            }}

            .button:hover {{
                background: #24558e;
            }}

            .logout {{
                margin-top: 30px;
                text-align: center;
            }}

            .logout button {{
                padding: 10px 25px;
                background: #dc2626;
                color: white;
                border: none;
                border-radius: 6px;
                cursor: pointer;
            }}

            @media (max-width: 600px) {{
                .cards {{
                    grid-template-columns: 1fr;
                }}

                .navbar {{
                    padding: 15px 20px;
                }}
            }}
        </style>
    </head>

    <body>

        <div class="navbar">
            <div class="logo">TrustVault</div>
            <div class="user">{current_user.email}</div>
        </div>

        <div class="container">

            <div class="welcome">
                <h1>Welcome, {current_user.name}!</h1>
                <p>
                    Your secure document storage dashboard.
                    Manage and verify your documents safely.
                </p>
            </div>

            <div class="cards">

                <div class="card">
                    <h2>Upload Document</h2>
                    <p>
                        Securely upload your documents to TrustVault.
                        Files are protected and stored safely.
                    </p>

                    <a href="/upload" class="button">
                        Upload Document
                    </a>
                </div>

                <div class="card">
                    <h2>My Documents</h2>
                    <p>
                        View your uploaded documents and check
                        their integrity whenever you need.
                    </p>

                    <a href="/documents" class="button">
                        View Documents
                    </a>
                </div>

            </div>

            <div class="logout">
                <form action="/logout" method="POST">
                    <button type="submit">Logout</button>
                </form>
            </div>

        </div>

    </body>
    </html>
    """


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have logged out.")
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_document():
    if request.method == "POST":
        file = request.files.get("document")

        if not file or not file.filename:
            flash("Please choose a document.")
            return redirect(url_for("upload_document"))

        safe_name = secure_filename(file.filename)

        if not safe_name or "." not in safe_name:
            flash("Invalid filename.")
            return redirect(url_for("upload_document"))

        extension = safe_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            flash("Only PDF, TXT, PNG, JPG, JPEG, and DOCX files are allowed.")
            return redirect(url_for("upload_document"))

        content = file.read(MAX_FILE_SIZE + 1)

        if len(content) > MAX_FILE_SIZE:
            flash("Maximum file size is 10 MB.")
            return redirect(url_for("upload_document"))

        if not content:
            flash("Empty files cannot be uploaded.")
            return redirect(url_for("upload_document"))

        stored_name = f"{uuid.uuid4().hex}.{extension}"
        file_path = os.path.join(UPLOAD_FOLDER, stored_name)

        with open(file_path, "wb") as saved_file:
            saved_file.write(content)

        document = Document(
            original_filename=safe_name,
            stored_filename=stored_name,
            sha256_hash=hashlib.sha256(content).hexdigest(),
            owner_id=current_user.id
        )

        try:
            db.session.add(document)
            db.session.commit()
        except Exception:
            db.session.rollback()
            os.remove(file_path)
            raise

        flash("Document uploaded successfully!")
        return redirect(url_for("my_documents"))

    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TrustVault | Upload Document</title>

        <style>
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f1f5f9;
                color: #1e293b;
            }

            .navbar {
                background: #173b68;
                color: white;
                padding: 20px 40px;
                font-size: 24px;
                font-weight: bold;
            }

            .container {
                max-width: 650px;
                margin: 60px auto;
                padding: 20px;
            }

            .upload-box {
                background: white;
                padding: 35px;
                border-radius: 12px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.08);
                text-align: center;
            }

            h1 {
                color: #173b68;
            }

            .description {
                color: #64748b;
                line-height: 1.6;
            }

            .file-area {
                margin: 30px 0;
                padding: 25px;
                border: 2px dashed #94a3b8;
                border-radius: 10px;
                background: #f8fafc;
            }

            input[type="file"] {
                max-width: 100%;
                margin-top: 12px;
            }

            button {
                background: #173b68;
                color: white;
                border: none;
                padding: 13px 28px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 16px;
            }

            button:hover {
                background: #24558e;
            }

            .links {
                margin-top: 25px;
            }

            .links a {
                color: #173b68;
                margin: 0 10px;
                text-decoration: none;
                font-weight: bold;
            }

            .links a:hover {
                text-decoration: underline;
            }

            @media (max-width: 600px) {
                .navbar {
                    padding: 18px 20px;
                }

                .upload-box {
                    padding: 25px 18px;
                }
            }
        </style>
    </head>

    <body>
        <div class="navbar">TrustVault</div>

        <div class="container">
            <div class="upload-box">
                <h1>Upload Document</h1>

                <p class="description">
                    Securely upload your document to TrustVault.
                    Your file's SHA-256 hash will be stored for integrity verification.
                </p>

                <p class="description">
                    Allowed formats: PDF, TXT, PNG, JPG, JPEG, DOCX.
                    Maximum file size: 10 MB.
                </p>

                <form method="POST" enctype="multipart/form-data">
                    <div class="file-area">
                        <p><strong>Choose a document to upload</strong></p>
                        <input type="file" name="document"
                               accept=".pdf,.txt,.png,.jpg,.jpeg,.docx" required>
                    </div>

                    <button type="submit">Upload Securely</button>
                </form>

                <div class="links">
                    <a href="/documents">My Documents</a>
                    <a href="/dashboard">Dashboard</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """


@app.route("/documents")
@login_required
def my_documents():
    documents = Document.query.filter_by(
        owner_id=current_user.id
    ).order_by(Document.uploaded_at.desc()).all()

    rows = ""

    for doc in documents:
        rows += f"""
        <div class="document-card">
            <div class="document-info">
                <h3>{doc.original_filename}</h3>
                <p><strong>SHA-256 Hash</strong></p>
                <code>{doc.sha256_hash}</code>
            </div>

            <div class="actions">
                <a class="button"
                   href="{url_for('download_document', document_id=doc.id)}">
                   Download
                </a>

                <a class="button verify"
                   href="{url_for('verify_document', document_id=doc.id)}">
                   Verify Integrity
                </a>
            </div>
        </div>
        """

    if not rows:
        rows = '<div class="empty">No documents uploaded yet.</div>'

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TrustVault | My Documents</title>

        <style>
            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f1f5f9;
                color: #1e293b;
            }}

            .navbar {{
                background: #173b68;
                color: white;
                padding: 20px 40px;
                font-size: 24px;
                font-weight: bold;
            }}

            .container {{
                max-width: 900px;
                margin: 40px auto;
                padding: 20px;
            }}

            .heading {{
                color: #173b68;
                margin-bottom: 25px;
            }}

            .document-card {{
                background: white;
                padding: 25px;
                margin-bottom: 20px;
                border-radius: 12px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.07);
            }}

            .document-info h3 {{
                color: #173b68;
                overflow-wrap: anywhere;
            }}

            .document-info code {{
                display: block;
                background: #f1f5f9;
                padding: 12px;
                border-radius: 6px;
                overflow-wrap: anywhere;
                font-size: 12px;
            }}

            .actions {{
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
                margin-top: 20px;
            }}

            .button {{
                display: inline-block;
                background: #173b68;
                color: white;
                padding: 11px 18px;
                border-radius: 6px;
                text-decoration: none;
                font-size: 14px;
            }}

            .verify {{
                background: #15803d;
            }}

            .button:hover {{
                opacity: 0.85;
            }}

            .empty {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                text-align: center;
                color: #64748b;
            }}

            .back {{
                display: inline-block;
                margin-top: 15px;
                color: #173b68;
                font-weight: bold;
                text-decoration: none;
            }}

            @media (max-width: 600px) {{
                .navbar {{
                    padding: 18px 20px;
                }}

                .document-card {{
                    padding: 18px;
                }}
            }}
        </style>
    </head>

    <body>
        <div class="navbar">TrustVault</div>

        <div class="container">
            <h1 class="heading">My Documents</h1>
            <p>Manage your uploaded files and verify their integrity.</p>

            {rows}

            <a class="back" href="/upload">+ Upload Another Document</a>
            <br>
            <a class="back" href="/dashboard">← Back to Dashboard</a>
        </div>
    </body>
    </html>
    """


@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None or document.owner_id != current_user.id:
        return "Document not found.", 404

    return send_from_directory(
        UPLOAD_FOLDER,
        document.stored_filename,
        as_attachment=True,
        download_name=document.original_filename
    )
    
@app.route("/documents/<int:document_id>/verify", methods=["GET"])
@login_required
def verify_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None or document.owner_id != current_user.id:
        return "Document not found.", 404

    file_path = os.path.join(UPLOAD_FOLDER, document.stored_filename)

    if not os.path.isfile(file_path):
        result = "Integrity check failed: stored file is missing."
        status = "FAILED"
    else:
        with open(file_path, "rb") as stored_file:
            current_hash = hashlib.sha256(stored_file.read()).hexdigest()

        if current_hash == document.sha256_hash:
            result = "Integrity verified: document has not changed."
            status = "VERIFIED"
        else:
            result = "Integrity check failed: document content has changed."
            status = "FAILED"

    color = "#15803d" if status == "VERIFIED" else "#dc2626"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TrustVault | Integrity Check</title>

        <style>
            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f1f5f9;
                color: #1e293b;
            }}

            .navbar {{
                background: #173b68;
                color: white;
                padding: 20px 40px;
                font-size: 24px;
                font-weight: bold;
            }}

            .container {{
                max-width: 700px;
                margin: 60px auto;
                padding: 20px;
            }}

            .result-card {{
                background: white;
                padding: 35px;
                border-radius: 12px;
                text-align: center;
                box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            }}

            .status {{
                color: {color};
                font-size: 22px;
                font-weight: bold;
            }}

            .message {{
                line-height: 1.6;
                color: #475569;
            }}

            .hash {{
                text-align: left;
                background: #f1f5f9;
                padding: 15px;
                border-radius: 8px;
                overflow-wrap: anywhere;
                font-size: 12px;
            }}

            .button {{
                display: inline-block;
                margin: 15px 8px 0;
                padding: 12px 20px;
                background: #173b68;
                color: white;
                text-decoration: none;
                border-radius: 6px;
            }}

            .button:hover {{
                background: #24558e;
            }}
        </style>
    </head>

    <body>
        <div class="navbar">TrustVault</div>

        <div class="container">
            <div class="result-card">
                <h1>Document Integrity Check</h1>

                <p class="status">{status}</p>
                <p class="message">{result}</p>

                <p><strong>Document:</strong></p>
                <p>{document.original_filename}</p>

                <p><strong>Stored SHA-256 Hash:</strong></p>
                <div class="hash">{document.sha256_hash}</div>

                <a class="button" href="/documents">My Documents</a>
                <a class="button" href="/dashboard">Dashboard</a>
            </div>
        </div>
    </body>
    </html>
    """
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
