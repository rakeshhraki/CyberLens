import os
import mimetypes
from typing import Dict, Tuple, Optional


def get_file_extension(filename: str) -> str:
    """
    Get file extension from filename.
    Returns extension without dot.
    Example: 'report.pdf' -> 'pdf'
    """
    _, ext = os.path.splitext(filename)
    return ext.lower().lstrip('.')


def detect_mime_type(file_path: str) -> Optional[str]:
    """
    Detect MIME type using python-magic if available.
    Falls back to Python mimetypes.
    """
    try:
        import magic

        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)

    except ImportError:
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type

    except Exception:
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type


def get_file_size(file_path: str) -> int:
    """
    Get file size in bytes.
    """
    return os.path.getsize(file_path)


def is_executable(extension: str) -> bool:
    """
    Check whether the file extension indicates an executable.
    """

    executable_extensions = {
        'exe',
        'dll',
        'bat',
        'cmd',
        'com',
        'msi',
        'scr',
        'vbs',
        'js',
        'jar',
        'app',
        'elf',
        'bin',
        'sh'
    }

    return extension.lower() in executable_extensions


def is_pe_file(file_path: str) -> bool:
    """
    Check whether the file begins with the MZ PE signature.
    """

    try:
        with open(file_path, 'rb') as f:
            header = f.read(2)

        return header == b'MZ'

    except Exception:
        return False


def detect_double_extension(filename: str) -> bool:
    """
    Detect suspicious double extensions.

    Examples:
        invoice.pdf.exe -> True
        photo.jpg       -> False
    """

    if not filename:
        return False

    parts = filename.split('.')

    return len(parts) > 2


def compare_extension_mime(
    extension: str,
    mime_type: Optional[str]
) -> Tuple[bool, Optional[str]]:
    """
    Compare file extension with detected MIME type.

    Returns:
        (matches, evidence)
    """

    if not mime_type:
        return True, None

    extension_mime_map = {
        'pdf': 'application/pdf',

        'doc': 'application/msword',

        'docx':
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',

        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',

        'png': 'image/png',

        'txt': 'text/plain',

        'exe': 'application/x-msdownload',
        'dll': 'application/x-msdownload',

        'bat': 'text/plain',
        'cmd': 'text/plain',

        'com': 'application/x-msdownload',

        'msi': 'application/x-msi',

        'scr': 'application/x-msdownload',

        'vbs': 'text/vbscript',

        'js': 'text/javascript',

        'jar': 'application/java-archive',

        'sh': 'application/x-sh',

        'elf': 'application/x-executable'
    }

    expected_mime = extension_mime_map.get(
        extension.lower()
    )

    if not expected_mime:
        return True, None

    if mime_type == expected_mime:
        return True, None

    compatible_mimes = {
        'text/plain': {
            'bat',
            'cmd',
            'sh'
        },

        'application/octet-stream': {
            'exe',
            'dll',
            'bin',
            'elf'
        }
    }

    for base_mime, compatible_extensions in compatible_mimes.items():

        if (
            mime_type.startswith(base_mime)
            and extension.lower() in compatible_extensions
        ):
            return True, None

    evidence = (
        f"Extension '{extension}' suggests "
        f"'{expected_mime}' but detected "
        f"'{mime_type}'"
    )

    return False, evidence


def classify_file_category(
    extension: str,
    mime_type: Optional[str]
) -> str:
    """
    Classify file into a general category.

    Categories:
        document
        image
        executable
        script
        archive
        other
    """

    extension = extension.lower()

    document_extensions = {
        'pdf',
        'doc',
        'docx',
        'txt',
        'rtf',
        'odt'
    }

    image_extensions = {
        'jpg',
        'jpeg',
        'png',
        'gif',
        'bmp',
        'tiff',
        'webp'
    }

    executable_extensions = {
        'exe',
        'dll',
        'com',
        'msi',
        'scr',
        'elf',
        'bin',
        'app'
    }

    script_extensions = {
        'bat',
        'cmd',
        'vbs',
        'js',
        'sh',
        'ps1',
        'py'
    }

    archive_extensions = {
        'zip',
        'rar',
        '7z',
        'tar',
        'gz',
        'bz2'
    }

    if extension in document_extensions:
        return 'document'

    if extension in image_extensions:
        return 'image'

    if extension in executable_extensions:
        return 'executable'

    if extension in script_extensions:
        return 'script'

    if extension in archive_extensions:
        return 'archive'

    return 'other'


def format_file_size(size_bytes: int) -> str:
    """
    Convert bytes into human-readable format.
    """

    size = float(size_bytes)

    for unit in ['B', 'KB', 'MB', 'GB']:

        if size < 1024.0:
            return f"{size:.2f} {unit}"

        size /= 1024.0

    return f"{size:.2f} TB"


def identify_file(
    file_path: str,
    original_filename: str
) -> Dict:
    """
    Perform comprehensive static file identification.
    """

    extension = get_file_extension(
        original_filename
    )

    file_size = get_file_size(
        file_path
    )

    mime_type = detect_mime_type(
        file_path
    )

    # IMPORTANT:
    # This function is defined above and is now
    # definitely available here.
    is_exec = is_executable(
        extension
    )

    is_pe = is_pe_file(
        file_path
    )

    has_double_ext = detect_double_extension(
        original_filename
    )

    ext_mime_match, mime_mismatch_evidence = (
        compare_extension_mime(
            extension,
            mime_type
        )
    )

    category = classify_file_category(
        extension,
        mime_type
    )

    identification = {

        'filename':
            original_filename,

        'extension':
            extension,

        'mime_type':
            mime_type,

        'file_size':
            file_size,

        'file_size_human':
            format_file_size(file_size),

        'is_executable':
            is_exec,

        'is_pe_file':
            is_pe,

        'has_double_extension':
            has_double_ext,

        'extension_mime_match':
            ext_mime_match,

        'mime_mismatch_evidence':
            mime_mismatch_evidence,

        'file_category':
            category
    }

    return identification