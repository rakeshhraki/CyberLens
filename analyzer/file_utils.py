import os
import secrets
from pathlib import Path
from typing import Tuple, Optional

from flask import current_app
from werkzeug.utils import secure_filename


def sanitize_filename(filename: str) -> str:
    if not filename:
        return "unnamed_file"

    filename = filename.replace("\x00", "")
    sanitized = secure_filename(filename)

    return sanitized or "unnamed_file"


def generate_random_filename(original_filename: str) -> str:
    _, ext = os.path.splitext(original_filename)
    ext = ext.lower()

    random_base = secrets.token_hex(16)

    return f"{random_base}{ext}"


def validate_extension(filename: str) -> bool:
    if not filename:
        return False

    _, ext = os.path.splitext(filename)
    ext = ext.lower().lstrip(".")

    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def validate_mime_type(mime_type: str) -> bool:
    if not mime_type:
        return False

    return mime_type in current_app.config["ALLOWED_MIME_TYPES"]


def detect_double_extension(filename: str) -> bool:
    if not filename:
        return False

    parts = filename.split(".")

    return len(parts) > 2


def validate_file_size(file_size: int) -> bool:
    max_size = current_app.config["MAX_CONTENT_LENGTH"]

    return 0 <= file_size <= max_size


def _is_safe_path(file_path: str, base_folder: str) -> bool:
    try:
        base = Path(base_folder).resolve()
        target = Path(file_path).resolve()

        return os.path.commonpath(
            [str(base), str(target)]
        ) == str(base)

    except (ValueError, OSError):
        return False


def get_safe_file_path(filename: str) -> str:
    upload_folder = current_app.config["UPLOAD_FOLDER"]

    os.makedirs(upload_folder, exist_ok=True)

    safe_name = sanitize_filename(filename)

    full_path = os.path.join(
        upload_folder,
        safe_name
    )

    if not _is_safe_path(
        full_path,
        upload_folder
    ):
        raise ValueError(
            "Path traversal attempt detected"
        )

    return os.path.abspath(full_path)


def save_uploaded_file(
    file,
    random_filename: str
) -> Tuple[str, int]:

    upload_folder = current_app.config["UPLOAD_FOLDER"]

    os.makedirs(upload_folder, exist_ok=True)

    file_path = get_safe_file_path(
        random_filename
    )

    file.save(file_path)

    file_size = os.path.getsize(file_path)

    if not validate_file_size(file_size):
        cleanup_file(file_path)

        raise ValueError(
            "Uploaded file exceeds maximum size"
        )

    return file_path, file_size


def cleanup_file(file_path: str) -> bool:
    try:
        if not file_path:
            return False

        upload_folder = current_app.config["UPLOAD_FOLDER"]

        if not _is_safe_path(
            file_path,
            upload_folder
        ):
            return False

        if os.path.isfile(file_path):
            os.remove(file_path)
            return True

        return False

    except (OSError, ValueError):
        return False


def validate_upload(
    file,
    filename: str
) -> Tuple[bool, Optional[str]]:

    if not file or not filename:
        return False, "No file provided"

    if "\x00" in filename:
        return False, "Invalid filename"

    file.seek(0, os.SEEK_END)

    file_size = file.tell()

    file.seek(0)

    if not validate_file_size(file_size):
        max_mb = (
            current_app.config["MAX_CONTENT_LENGTH"]
            / (1024 * 1024)
        )

        return False, (
            f"File size exceeds maximum of {max_mb}MB"
        )

    if not validate_extension(filename):
        allowed = ", ".join(
            current_app.config["ALLOWED_EXTENSIONS"]
        )

        return False, (
            f"File type not allowed. "
            f"Allowed types: {allowed}"
        )

    mime_type = file.content_type

    if mime_type and not validate_mime_type(mime_type):
        return False, (
            f"MIME type '{mime_type}' not allowed"
        )

    return True, None