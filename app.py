import io
import os
import gzip
import time
import random

from flask import Flask, request, render_template, send_file, abort, redirect, url_for, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from config import BASE_DIR, DATA_DIR, UPLOAD_TEMP_DIR, MAX_UPLOAD_SIZE
from upload_manager import UploadManager

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

uploads = UploadManager(DATA_DIR, UPLOAD_TEMP_DIR, None)

PAGES = [
    {"name": "Home",  "url": "/"},
    {"name": "Vault", "url": "/vault"},
    {"name": "IRC", "url": "/irc"},
]

# Globally recognized image formats
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp")
MISC_EXTENSIONS = (".gif", ".txt", ".mp4", ".avi")

# Register admin routes (gitignored)
try:
    from admin import register_admin_routes
    register_admin_routes(app, uploads)
except ImportError:
    pass


# ====================== HELPERS & UTILITIES ======================

def _list_media_files(directory, extensions):
    """Efficiently scan, filter, and sort directory contents using iterator blocks."""
    try:
        with os.scandir(directory) as entries:
            return sorted([
                e.name for e in entries
                if e.is_file() and e.name.lower().endswith(extensions)
            ])
    except FileNotFoundError:
        return []


# ====================== RATE LIMITING ======================

def get_request_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else request.remote_addr or "unknown"

def is_admin_ip(ip):
    return ip in ("127.0.0.1", "::1") or ip.startswith("192.168.40.")

def rate_limit_key():
    ip = get_request_ip()
    return None if is_admin_ip(ip) else ip  # None = exempt from rate limiting

limiter = Limiter(
    key_func=rate_limit_key,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",  # swap to "redis://localhost:6379" for persistence
)

@app.errorhandler(429)
def rate_limited(e):
    return render_template("banned.html", status="rate_limited"), 429


# ====================== CONTEXT & HELPERS ======================

@app.context_processor
def inject_pages():
    return {"pages": PAGES}


# ====================== ROUTES ======================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/thing")
def thing():
    return render_template("thiu.html")

@app.route("/contact", methods=["GET", "POST"])
@limiter.limit("5 per hour") # Keeps bots from flooding your inbox
def contact():
    if request.method == "POST":
        honeypot = request.form.get("website", "").strip()
        bot_status = "(bot)" if honeypot else "(not a bot)"

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()
        
        # Format the text payload for server logs or your local file storage
        log_entry = f"Time: {time.ctime()}\nFrom: {name} ({email})\nIP: {get_request_ip()}\nBot check: {bot_status}\nMsg: {message}\n{'-'*40}\n"
        
        # Save messages to a secure directory location
        out_path = os.path.join(DATA_DIR, "messages.txt")
        with open(out_path, "a", encoding="utf-8") as f:
            f.write(log_entry)

        if honeypot:
            return "Message rejected. <a href='/'>Go Home</a>"
            
        return "Message sent successfully! <a href='/'>Go Home</a>"
        
    return render_template("contact.html")

@app.route("/data/images", strict_slashes=False)
def list_images():
    img_dir = os.path.join(DATA_DIR, "images")
    images = _list_media_files(img_dir, IMAGE_EXTENSIONS)
    return render_template("image_list.html", images=images)

@app.route("/data/misc", strict_slashes=False)
def list_gifs():
    gif_dir = os.path.join(DATA_DIR, "gifs")
    gifs = _list_media_files(gif_dir, MISC_EXTENSIONS)
    return render_template("gifs.html", gifs=gifs)

@app.route("/data", strict_slashes=False)
def data_index():
    img_dir = os.path.join(DATA_DIR, "images")
    gif_dir = os.path.join(DATA_DIR, "gifs")
    music_dir = os.path.join(DATA_DIR, "music")

    images = _list_media_files(img_dir, IMAGE_EXTENSIONS)
    gifs = _list_media_files(gif_dir, MISC_EXTENSIONS)
    songs = _list_media_files(music_dir, (".mp3",))

    return render_template("data.html", images=images, gifs=gifs, songs=songs)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route("/temp/<upload_id>")
@limiter.limit("30 per hour")
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

    # Streaming the stream object directly prevents high memory peaks under concurrent workloads
    gzip_file = gzip.open(file_info["path"], "rb")
    return send_file(
        gzip_file, 
        as_attachment=True, 
        download_name=file_info["filename"],
        mimetype="application/octet-stream"
    )


@app.route("/minecraft")
def minecraft():
    return render_template("minecraft.html")

@app.route("/irc")
def irc():
    return render_template("irc.html")

@app.route("/vault")
def vault():
    return render_template("vault.html")



@app.route("/vault/<version>")
def vault_version(version):
    # Validate against template structural breakouts or OS injection variants
    safe_version = secure_filename(version)
    if not safe_version or safe_version != version:
        abort(404)
    try:
        return render_template(f"archive/{safe_version}.html")
    except Exception:
        abort(404)


@app.route("/data/images/random")
@limiter.limit("30 per minute")
def random_image():
    img_dir = os.path.join(DATA_DIR, "images")
    images = _list_media_files(img_dir, IMAGE_EXTENSIONS)
    if not images:
        abort(404)
    pick = random.choice(images)
    return jsonify({"url": f"/data/images/{pick}", "file": pick})


@app.route("/data/images/<filename>")
def serve_image(filename):
    img_dir = os.path.join(DATA_DIR, "images")
    return send_from_directory(img_dir, filename)


@app.route("/data/gifs/<filename>")
def serve_gif(filename):
    gif_dir = os.path.join(DATA_DIR, "gifs")
    return send_from_directory(gif_dir, filename)


@app.route("/music/random")
@limiter.limit("30 per minute")
def random_music():
    music_dir = os.path.join(DATA_DIR, "music")
    songs = _list_media_files(music_dir, (".mp3",))
    if not songs:
        abort(404)
    chosen = random.choice(songs)
    return jsonify({"file": chosen, "url": url_for("serve_music", filename=chosen)})


@app.route("/music/<filename>")
def serve_music(filename):
    music_dir = os.path.join(DATA_DIR, "music")
    return send_from_directory(music_dir, filename)


# ====================== ERROR HANDLERS ======================

@app.errorhandler(RequestEntityTooLarge)
def handle_large_upload(error):
    return "File exceeds the 10MB upload limit.", 413


if __name__ == "__main__":
    print("Your Flask web server is online!")
    app.run(host="0.0.0.0", port=8081, debug=True)
