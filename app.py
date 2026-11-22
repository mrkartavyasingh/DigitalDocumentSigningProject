"""Flask web interface for digital document signing and verification."""
import os
import tempfile
from pathlib import Path
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from key_manager import PUBLIC_KEY_PATH, load_public_key
from bundle_utils import create_signed_bundle, verify_signed_bundle, MAX_DOCUMENT_BYTES, MAX_BUNDLE_BYTES

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BUNDLE_BYTES + 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)

def save_upload(file_storage, suffix="", max_bytes=MAX_DOCUMENT_BYTES):
    name = secure_filename(file_storage.filename or "")
    if not name:
        raise ValueError("Choose a file with a valid filename.")
    fd, path = tempfile.mkstemp(prefix="upload_", suffix=suffix, dir=UPLOAD_DIR)
    os.close(fd)
    file_storage.save(path)
    if Path(path).stat().st_size > max_bytes:
        os.unlink(path)
        raise ValueError(f"File exceeds the {max_bytes // (1024 * 1024)} MB limit.")
    return path, name

@app.errorhandler(413)
def too_large(_error):
    return render_template("index.html", page="home", error="Upload is too large. Maximum document size is 25 MB."), 413

@app.route("/")
def index():
    return render_template("index.html", page="home")

@app.route("/sign", methods=["GET", "POST"])
def sign():
    if request.method == "GET":
        return render_template("index.html", page="sign")
    uploaded = request.files.get("document")
    passphrase = request.form.get("passphrase", "")
    if not uploaded or not uploaded.filename:
        return render_template("index.html", page="sign", error="Select a document.")
    if not passphrase:
        return render_template("index.html", page="sign", error="Enter the private-key passphrase.")
    path = None
    bundle_path = None
    try:
        path, original_name = save_upload(uploaded)
        bundle_path, metrics = create_signed_bundle(path, original_name, passphrase)
        download_name = secure_filename(Path(original_name).stem) + "_signed_bundle.zip"
        response = send_file(bundle_path, as_attachment=True, download_name=download_name, mimetype="application/zip")
        # Flask closes the response after sending; temporary files are cleaned with call_on_close.
        response.call_on_close(lambda: _cleanup(path, bundle_path))
        return response
    except (ValueError, FileNotFoundError, OSError) as exc:
        _cleanup(path, bundle_path)
        return render_template("index.html", page="sign", error=str(exc)), 400

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "GET":
        return render_template("index.html", page="verify")
    uploaded = request.files.get("bundle")
    if not uploaded or not uploaded.filename:
        return render_template("index.html", page="verify", error="Select a signed ZIP bundle.")
    path = None
    try:
        path, _ = save_upload(uploaded, suffix=".zip", max_bytes=MAX_BUNDLE_BYTES)
        trusted = load_public_key()
        valid, message, details = verify_signed_bundle(path, trusted)
        return render_template("index.html", page="verify", result={
            "valid": valid, "message": message, "details": details
        })
    except (ValueError, FileNotFoundError, OSError) as exc:
        return render_template("index.html", page="verify", error=str(exc)), 400
    finally:
        _cleanup(path)

@app.route("/public-key")
def public_key():
    if not PUBLIC_KEY_PATH.exists():
        flash("Public key not found. Run python key_manager.py init first.", "error")
        return redirect(url_for("index"))
    return send_file(PUBLIC_KEY_PATH, as_attachment=True, download_name="public_key.pem", mimetype="application/x-pem-file")

def _cleanup(*paths):
    for path in paths:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
