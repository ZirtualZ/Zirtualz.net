import io
import os
import time
import gzip
from flask import Flask, request, render_template, send_file, abort
from werkzeug.exceptions import RequestEntityTooLarge

from config import BASE_DIR, DATA_DIR, FILES_DIR, UPLOAD_TEMP_DIR, MAX_UPLOAD_SIZE
from ip_tracker import IPTracker
from upload_manager import UploadManager

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

tracker = IPTracker(DATA_DIR)
uploads = UploadManager(DATA_DIR, FILES_DIR, UPLOAD_TEMP_DIR, None)

PAGES = [
    {"name": "Home",  "url": "/"},
    {"name": "Files", "url": "/files"},
]

# Register admin routes (gitignored)
try:
    from admin import register_admin_routes
    register_admin_routes(app, tracker, uploads)
except ImportError:
    pass


@app.context_processor
def inject_pages():
    return {"pages": PAGES}


def get_request_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else request.remote_addr or "unknown"


def is_admin_ip(ip):
    return ip in ("127.0.0.1", "::1") or ip.startswith("192.168.40.")


@app.before_request
def enforce_ip():
    ip = get_request_ip()
    if is_admin_ip(ip):
        return
    tracker.evaluate_ip(ip, request.path, request.headers.get("User-Agent", ""), request.method)
    block_status = tracker.check_block(ip)
    if block_status == "black":
        return render_template("banned.html", status="permanent"), 403
    if block_status == "red":
        state      = tracker.get_state(ip)
        expires_at = None
        if state.get("red_until"):
            expires_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(state["red_until"]))
        return render_template("banned.html", status="temporary", expires_at=expires_at), 403


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/files", methods=["GET", "POST"])
def files_list():
    upload_message = upload_error = temp_link = None

    if request.method == "POST":
        _, message = uploads.save_upload(
            request.files.get("file"),
            request.form.get("description", "").strip(),
            request.form.get("submission_type", "permanent"),
            get_request_ip(),
        )
        if isinstance(message, dict):
            upload_message = message["message"]
            temp_link      = message["temp_link"]
        elif message.startswith("✓"):
            upload_message = message
        else:
            upload_error = message

    return render_template(
        "files.html",
        files=uploads.get_file_list(),
        upload_message=upload_message,
        upload_error=upload_error,
        temp_link=temp_link,
        pending_count=len(uploads.load_pending()),
    )


@app.route("/temp/<upload_id>")
def temp_file(upload_id):
    file_info, status = uploads.get_temp_file(upload_id)
    if status == "expired":
        return "This link has expired and the file has been deleted.", 410
    if status in ("not_found", "missing"):
        return "File not found.", 404

    if file_info["is_image"]:
        return send_file(
            file_info["path"],
            mimetype="image/jpeg",
            as_attachment=False,
            download_name=file_info["filename"],
        )

    with gzip.open(file_info["path"], "rb") as f:
        data = f.read()
    return send_file(io.BytesIO(data), as_attachment=True, download_name=file_info["filename"])


@app.route("/file/<filename>")
def serve_file(filename):
    if ".." in filename or "/" in filename or "\\" in filename:
        abort(400)
    filepath      = os.path.abspath(os.path.join(FILES_DIR, filename))
    files_dir_abs = os.path.abspath(FILES_DIR)
    if not filepath.startswith(files_dir_abs):
        abort(403)
    if not os.path.isfile(filepath):
        abort(404)
    return send_file(filepath)


@app.errorhandler(RequestEntityTooLarge)
def handle_large_upload(error):
    return render_template(
        "files.html",
        files=uploads.get_file_list(),
        upload_error="File exceeds the 10MB upload limit.",
        pending_count=len(uploads.load_pending()),
    ), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)