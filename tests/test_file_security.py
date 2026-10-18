from io import BytesIO
import os

import pytest
from werkzeug.datastructures import FileStorage

from app import app
from analyzer.file_utils import (
    validate_upload,
    sanitize_filename,
    generate_random_filename,
    get_safe_file_path,
    save_uploaded_file,
    cleanup_file,
)


@pytest.fixture
def app_context():
    with app.app_context():
        yield


def make_upload(
    content=b"test",
    filename="sample.txt",
    content_type="text/plain"
):
    return FileStorage(
        stream=BytesIO(content),
        filename=filename,
        content_type=content_type
    )


def test_empty_filename(app_context):
    file = make_upload()

    is_valid, error = validate_upload(
        file,
        ""
    )

    assert is_valid is False
    assert error


def test_path_traversal_filename(app_context):
    file = make_upload(
        filename="../../malicious.exe",
        content_type="application/octet-stream"
    )

    is_valid, error = validate_upload(
        file,
        "../../malicious.exe"
    )

    assert is_valid is False
    assert error


def test_double_extension(app_context):
    file = make_upload(
        filename="document.pdf.exe",
        content_type="application/octet-stream"
    )

    is_valid, error = validate_upload(
        file,
        "document.pdf.exe"
    )

    assert is_valid is False
    assert error


def test_null_byte_filename(app_context):
    file = make_upload(
        filename="safe.txt\x00.exe",
        content_type="text/plain"
    )

    is_valid, error = validate_upload(
        file,
        "safe.txt\x00.exe"
    )

    assert is_valid is False
    assert error


def test_safe_filename(app_context):
    file = make_upload(
        content=b"CyberLens test",
        filename="sample.txt",
        content_type="text/plain"
    )

    is_valid, error = validate_upload(
        file,
        "sample.txt"
    )

    assert is_valid is True
    assert error is None


def test_filename_sanitization(app_context):
    result = sanitize_filename(
        "../../test file.txt"
    )

    assert ".." not in result
    assert "/" not in result
    assert "\\" not in result


def test_random_filename_is_not_original(
    app_context
):
    original = "malicious_sample.exe"

    random_name = generate_random_filename(
        original
    )

    assert random_name != original
    assert random_name.endswith(".exe")
    assert len(random_name) > len(".exe")


def test_safe_path_stays_inside_upload_folder(
    app_context
):
    safe_path = get_safe_file_path(
        "test.txt"
    )

    upload_folder = os.path.abspath(
        app.config["UPLOAD_FOLDER"]
    )

    assert os.path.commonpath(
        [safe_path, upload_folder]
    ) == upload_folder


def test_uploaded_file_is_saved_with_random_name(
    app_context
):
    random_name = generate_random_filename(
        "security_test.txt"
    )

    upload = make_upload(
        content=b"CyberLens security test",
        filename="security_test.txt",
        content_type="text/plain"
    )

    file_path, file_size = save_uploaded_file(
        upload,
        random_name
    )

    try:
        assert os.path.isfile(file_path)

        assert file_size == len(
            b"CyberLens security test"
        )

        assert os.path.basename(
            file_path
        ) == random_name

    finally:
        cleanup_file(file_path)


def test_cleanup_removes_uploaded_file(
    app_context
):
    random_name = generate_random_filename(
        "cleanup_test.txt"
    )

    upload = make_upload(
        content=b"temporary",
        filename="cleanup_test.txt",
        content_type="text/plain"
    )

    file_path, _ = save_uploaded_file(
        upload,
        random_name
    )

    assert os.path.isfile(file_path)

    result = cleanup_file(file_path)

    assert result is True
    assert not os.path.exists(file_path)