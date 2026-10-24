# TrustVault – Secure Document Storage

TrustVault is a secure document storage web application built using Python and Flask. It allows users to register, log in, upload documents, download their files, and verify document integrity using SHA-256 hashing.

## Features

- User registration and login
- Secure document upload
- File type and size validation
- Unique filenames for stored documents
- SHA-256 hash generation
- Document download
- Document integrity verification
- User-specific document access

## Technologies Used

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- SQLite
- HTML and CSS
- Git and GitHub

## Allowed File Types

PDF, TXT, PNG, JPG, JPEG, and DOCX.

Maximum file size: 10 MB.

## Run Locally

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install the required dependencies.
4. Run the Flask application using `python app.py`.
5. Open `http://127.0.0.1:5000` in your browser.

## Security Notes

- Passwords are stored as password hashes.
- Uploaded files use unique storage filenames.
- Document ownership is checked before downloading or verifying files.
- SHA-256 hashes are used to detect changes to stored documents.

## Author

Sowmya

## Project Repository

https://github.com/Sowmya10162006/TrustVault