"""File upload and management."""
import gzip
import io
import json
import os
import re
import shutil
import time
import unicodedata
import uuid
from werkzeug.utils import secure_filename

# Temp upload expiry: TTL scales down with file size.
# Formula: TTL = BASE_TTL / (1 + size_mb * SIZE_PENALTY)
TEMP_BASE_TTL       = 7 * 24 * 60 * 60  # 7 days for small files
SIZE_PENALTY        = 0.5               # each MB roughly halves remaining TTL
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024 # 100 MB hard cap
IDLE_TTL            = 2 * 24 * 60 * 60  # reap if not accessed in 48h

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff"}
IMAGE_QUALITY    = 30    # JPEG/WEBP quality (0-95)
IMAGE_MAX_DIM    = 1280  # resize if either dimension exceeds this
GZIP_LEVEL       = 9

BLOCKED_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".jsp", ".jspx",
    ".py", ".rb", ".pl", ".cgi", ".sh", ".bash",
    ".exe", ".dll", ".so", ".bat", ".cmd", ".msi",
    ".htaccess", ".htpasswd",
}

MAX_FILENAME_LENGTH = 200


def sanitize_filename(raw_name: str) -> tuple[str, str | None]:
    """Clean and validate a user-supplied filename. Returns (name, None) or ("", error)."""
    if not raw_name:
        return "", "No filename provided."

    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw_name)
    cleaned = unicodedata.normalize("NFC", cleaned)
    cleaned = cleaned.lstrip("./\\ \t")
    cleaned = secure_filename(cleaned)

    if not cleaned:
        return "", "The filename contains no valid characters."

    if len(cleaned) > MAX_FILENAME_LENGTH:
        base, ext = os.path.splitext(cleaned)
        cleaned = base[:MAX_FILENAME_LENGTH - len(ext)] + ext

    ext = os.path.splitext(cleaned)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        return "", f"Files with the '{ext}' extension are not allowed."

    return cleaned, None


def _size_based_ttl(size_bytes: int) -> float:
    size_mb = size_bytes / (1024 * 1024)
    return TEMP_BASE_TTL / (1 + size_mb * SIZE_PENALTY)


def _is_expired(data: dict) -> bool:
    now = time.time()
    submitted_at  = data.get("submitted_at", 0)
    last_accessed = data.get("last_accessed", submitted_at)
    size_bytes    = data.get("raw_size", data.get("size", 0))
    return (
        now - submitted_at  > _size_based_ttl(size_bytes) or
        now - last_accessed > IDLE_TTL
    )


def _compress_image(src_path: str) -> bytes:
    try:
        from PIL import Image, ImageOps
    except ImportError:
        with open(src_path, "rb") as f:
            return f.read()

    with Image.open(src_path) as img:
        img = ImageOps.exif_transpose(img)
        img = img.convert("RGB")
        if max(img.size) > IMAGE_MAX_DIM:
            img.thumbnail((IMAGE_MAX_DIM, IMAGE_MAX_DIM), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=IMAGE_QUALITY, optimize=True)
        return buf.getvalue()


def _compress_generic(src_path: str) -> bytes:
    buf = io.BytesIO()
    with open(src_path, "rb") as src, gzip.GzipFile(fileobj=buf, mode="wb",
                                                     compresslevel=GZIP_LEVEL) as gz:
        shutil.copyfileobj(src, gz)
    return buf.getvalue()


class UploadManager:
    def __init__(self, data_dir, upload_temp_dir, admin_secret):
        self.data_dir        = data_dir
        self.upload_temp_dir = upload_temp_dir
        self.admin_secret    = admin_secret
        self.pending_file    = os.path.join(data_dir, "pending_uploads.json")
        self.temporary_file  = os.path.join(data_dir, "temporary_uploads.json")
        self.ensure_dirs()

    def ensure_dirs(self):
        for d in (self.data_dir, self.upload_temp_dir):
            os.makedirs(d, exist_ok=True)

    # --- persistence ---

    def _load_json(self, path: str) -> dict:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_json(self, path: str, data: dict):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_pending(self):   return self._load_json(self.pending_file)
    def save_pending(self, d): self._save_json(self.pending_file, d)
    def load_temporary(self):   return self._load_json(self.temporary_file)
    def save_temporary(self, d): self._save_json(self.temporary_file, d)

    # --- uploads ---

    def make_unique_filename(self, filename):
        safe = secure_filename(filename) or "upload"
        base, ext = os.path.splitext(safe)
        target, i = safe, 1
        while os.path.exists(os.path.join(self.data_dir, target)):
            target = f"{base}-{i}{ext}"
            i += 1
        return target

    def save_upload(self, file, description, submission_type, user_ip):
        if not file or not file.filename:
            return None, "Please choose a file to upload."
        filename, err = sanitize_filename(file.filename)
        if err:
            return None, err
        self.ensure_dirs()
        upload_id = uuid.uuid4().hex
        if submission_type == "temporary":
            return self._save_temporary(file, filename, description, user_ip, upload_id)
        return self._save_permanent(file, filename, description, user_ip, upload_id)

    def _save_temporary(self, file, filename, description, user_ip, upload_id):
        file.seek(0, 2)
        raw_size = file.tell()
        file.seek(0)

        if raw_size > MAX_FILE_SIZE_BYTES:
            return None, f"Temporary uploads are capped at {MAX_FILE_SIZE_BYTES // (1024*1024)} MB."

        scratch_path = os.path.join(self.upload_temp_dir, f"_scratch_{upload_id}_{filename}")
        file.save(scratch_path)

        ext      = os.path.splitext(filename)[1].lower()
        is_image = ext in IMAGE_EXTENSIONS

        if is_image:
            compressed = _compress_image(scratch_path)
            stored_ext = ".jpg"
        else:
            compressed = _compress_generic(scratch_path)
            stored_ext = ext + ".gz"

        os.remove(scratch_path)

        stored_name = f"{upload_id}{stored_ext}"
        with open(os.path.join(self.upload_temp_dir, stored_name), "wb") as f:
            f.write(compressed)

        now        = time.time()
        expiry_sec = _size_based_ttl(raw_size)

        temp = self.load_temporary()
        temp[upload_id] = {
            "original_filename": filename,
            "stored_filename":   stored_name,
            "is_image":          is_image,
            "raw_size":          raw_size,
            "stored_size":       len(compressed),
            "submitted_at":      now,
            "last_accessed":     now,
            "expires_at":        now + expiry_sec,
            "idle_ttl":          IDLE_TTL,
            "submitted_ip":      user_ip,
            "description":       description,
        }
        self.save_temporary(temp)

        ratio    = (1 - len(compressed) / raw_size) * 100 if raw_size else 0
        expiry_d = expiry_sec / 86400
        return upload_id, {
            "message": (
                f"Temporary file stored (compressed {ratio:.0f}%). "
                f"Expires in ≤{expiry_d:.1f} days or after {IDLE_TTL // 3600}h of inactivity."
            ),
            "temp_link": f"/temp/{upload_id}",
            "upload_id": upload_id,
        }

    def _save_permanent(self, file, filename, description, user_ip, upload_id):
        pending_name = f"{upload_id}_{filename}"
        temp_path    = os.path.join(self.upload_temp_dir, pending_name)
        file.save(temp_path)

        pending = self.load_pending()
        pending[upload_id] = {
            "original_filename": filename,
            "pending_filename":  pending_name,
            "size":              os.path.getsize(temp_path),
            "submitted_at":      time.time(),
            "submitted_ip":      user_ip,
            "description":       description,
            "mime_type":         file.mimetype,
        }
        self.save_pending(pending)
        return upload_id, "Upload request received and saved for approval."

    # --- retrieval ---

    def get_temp_file(self, upload_id: str):
        """Returns (file_info, "ok") or (None, reason). Bumps last_accessed on hit."""
        temp = self.load_temporary()
        if upload_id not in temp:
            return None, "not_found"

        data = temp[upload_id]
        if _is_expired(data):
            self._reap_temp_entry(temp, upload_id, data)
            self.save_temporary(temp)
            return None, "expired"

        stored_path = os.path.join(self.upload_temp_dir, data["stored_filename"])
        if not os.path.isfile(stored_path):
            temp.pop(upload_id, None)
            self.save_temporary(temp)
            return None, "missing"

        data["last_accessed"] = time.time()
        self.save_temporary(temp)

        return {
            "path":            stored_path,
            "filename":        data["original_filename"],
            "is_image":        data.get("is_image", False),
            "stored_filename": data["stored_filename"],
        }, "ok"

    def get_file_list(self):
        self.ensure_dirs()
        return [
            {"name": f, "url": f"/file/{f}"}
            for f in sorted(os.listdir(self.data_dir))
            if os.path.isfile(os.path.join(self.data_dir, f))
        ]

    # --- admin actions ---

    def approve_upload(self, upload_id):
        pending = self.load_pending()
        if upload_id not in pending:
            return False, "Upload not found."
        data      = pending.pop(upload_id)
        temp_path = os.path.join(self.upload_temp_dir, data["pending_filename"])
        if not os.path.isfile(temp_path):
            return False, "Pending file is missing."
        os.replace(temp_path, os.path.join(self.data_dir, self.make_unique_filename(data["original_filename"])))
        self.save_pending(pending)
        return True, f"Approved: {data['original_filename']}"

    def reject_upload(self, upload_id, is_temporary=False):
        if is_temporary:
            store = self.load_temporary()
            key   = "stored_filename"
        else:
            store = self.load_pending()
            key   = "pending_filename"

        if upload_id not in store:
            return False, "Upload not found."

        data = store.pop(upload_id)
        path = os.path.join(self.upload_temp_dir, data[key])
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass

        (self.save_temporary if is_temporary else self.save_pending)(store)
        return True, f"Rejected: {data['original_filename']}"

    def delete_file(self, filename):
        safe = secure_filename(filename)
        path = os.path.abspath(os.path.join(self.data_dir, safe))
        if not path.startswith(os.path.abspath(self.data_dir)):
            return False, "Invalid file name."
        if not os.path.isfile(path):
            return False, "File not found."
        os.remove(path)
        return True, f"Deleted: {safe}"

    def clear_pending(self):
        for data in self.load_pending().values():
            path = os.path.join(self.upload_temp_dir, data["pending_filename"])
            try:
                if os.path.isfile(path): os.remove(path)
            except OSError:
                pass
        self.save_pending({})

    def clear_temporary(self):
        for data in self.load_temporary().values():
            path = os.path.join(self.upload_temp_dir, data["stored_filename"])
            try:
                if os.path.isfile(path): os.remove(path)
            except OSError:
                pass
        self.save_temporary({})

    def cleanup_temporary(self) -> dict:
        """Reap expired/idle uploads. Safe to call frequently."""
        temp    = self.load_temporary()
        expired = [uid for uid, data in temp.items() if _is_expired(data)]
        for uid in expired:
            self._reap_temp_entry(temp, uid, temp[uid])
        if expired:
            self.save_temporary(temp)
        return {"reaped": len(expired), "remaining": len(temp)}

    def _reap_temp_entry(self, temp: dict, upload_id: str, data: dict):
        path = os.path.join(self.upload_temp_dir, data.get("stored_filename", ""))
        try:
            if path and os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass
        temp.pop(upload_id, None)