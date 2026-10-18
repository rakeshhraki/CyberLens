import os
from datetime import datetime
from typing import Dict, Optional, Any
from flask import current_app


def make_json_safe(value: Any) -> Any:
    """
    Convert metadata values into JSON-serializable Python types.

    Pillow EXIF values can contain special objects such as IFDRational,
    which cannot be directly serialized into JSON. This function safely
    converts those values without changing normal strings, numbers,
    booleans, lists, tuples, or dictionaries.
    """

    if value is None:
        return None

    # Normal JSON-compatible primitive types
    if isinstance(value, (str, int, float, bool)):
        return value

    # Convert bytes safely to text
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    # Recursively process dictionaries
    if isinstance(value, dict):
        return {
            str(key): make_json_safe(val)
            for key, val in value.items()
        }

    # Recursively process lists and tuples
    if isinstance(value, (list, tuple)):
        return [make_json_safe(item) for item in value]

    # Handle Pillow IFDRational and similar numeric objects
    try:
        return float(value)
    except (TypeError, ValueError):
        pass

    # Final fallback for unusual metadata objects
    return str(value)


def get_filesystem_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract safe file system metadata.
    This uses os.path functions which are safe and don't execute files.
    """
    try:
        # Get file stats
        stat = os.stat(file_path)

        # Convert timestamps to datetime objects
        # Handle OS differences gracefully
        creation_time = None
        try:
            creation_time = datetime.fromtimestamp(stat.st_ctime)
        except (OSError, ValueError):
            pass

        modification_time = None
        try:
            modification_time = datetime.fromtimestamp(stat.st_mtime)
        except (OSError, ValueError):
            pass

        access_time = None
        try:
            access_time = datetime.fromtimestamp(stat.st_atime)
        except (OSError, ValueError):
            pass

        metadata = {
            'file_size': stat.st_size,
            'creation_time': (
                creation_time.isoformat()
                if creation_time
                else None
            ),
            'modification_time': (
                modification_time.isoformat()
                if modification_time
                else None
            ),
            'access_time': (
                access_time.isoformat()
                if access_time
                else None
            ),
            'mode': stat.st_mode,
            'inode': stat.st_ino,
            'device': stat.st_dev
        }

        return metadata

    except Exception as e:
        # Return basic metadata if extraction fails
        return {
            'file_size': (
                os.path.getsize(file_path)
                if os.path.exists(file_path)
                else 0
            ),
            'creation_time': None,
            'modification_time': None,
            'access_time': None,
            'error': str(e)
        }


def get_image_metadata(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract safe image metadata using Pillow.
    Pillow reads image headers without executing the file.
    """
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS

        with Image.open(file_path) as img:
            metadata = {
                'format': img.format,
                'mode': img.mode,
                'size': img.size,
                'width': img.width,
                'height': img.height
            }

            # Try to extract EXIF data if available
            try:
                exif_data = {}
                exif = img._getexif()

                if exif:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)

                        # Convert EXIF values into JSON-safe values
                        exif_data[str(tag)] = make_json_safe(value)

                    metadata['exif'] = exif_data

            except (AttributeError, KeyError, TypeError):
                # No EXIF data or not available
                pass

            # Final safety conversion for all image metadata
            return make_json_safe(metadata)

    except ImportError:
        # Pillow not available
        return None

    except Exception:
        # Not a valid image or can't be read
        return None


def get_pdf_metadata(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract safe PDF metadata.

    Note: This is a placeholder. Full PDF metadata extraction would
    require additional libraries like PyPDF2. For now, we return
    basic info.
    """
    try:
        # Check if file appears to be a PDF by reading first few bytes
        with open(file_path, 'rb') as f:
            header = f.read(4)

            if header != b'%PDF':
                return None

        # Basic PDF info without full parsing
        metadata = {
            'format': 'PDF',
            'note': (
                'Full PDF metadata extraction requires '
                'additional libraries'
            )
        }

        return metadata

    except Exception:
        return None


def get_document_metadata(
    file_path: str,
    file_extension: str
) -> Optional[Dict[str, Any]]:
    """
    Extract metadata for document files.

    Placeholder for future implementation with libraries
    like python-docx.
    """
    # This is a placeholder for document-specific metadata
    # Would require libraries like python-docx for DOCX files
    return None


def extract_metadata(
    file_path: str,
    file_extension: str
) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from a file.

    Combines filesystem metadata with format-specific metadata.
    """
    # Get filesystem metadata (always available)
    fs_metadata = get_filesystem_metadata(file_path)

    # Initialize format-specific metadata
    format_metadata = None

    # Extract format-specific metadata based on extension
    extension = file_extension.lower()

    if extension in [
        'jpg',
        'jpeg',
        'png',
        'gif',
        'bmp',
        'tiff',
        'webp'
    ]:
        format_metadata = get_image_metadata(file_path)

    elif extension == 'pdf':
        format_metadata = get_pdf_metadata(file_path)

    elif extension in ['doc', 'docx']:
        format_metadata = get_document_metadata(
            file_path,
            extension
        )

    # Combine metadata
    combined_metadata = {
        'filesystem': fs_metadata,
        'format_specific': format_metadata
    }

    # Make absolutely sure the complete metadata object
    # can be serialized to JSON before it reaches the database.
    return make_json_safe(combined_metadata)


def format_metadata_for_display(
    metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Format metadata for display in UI.

    Simplifies complex structures for user-friendly display.
    """
    display_metadata = {}

    # Filesystem metadata
    if 'filesystem' in metadata:
        fs = metadata['filesystem']

        display_metadata['file_size'] = fs.get('file_size')
        display_metadata['creation_time'] = fs.get(
            'creation_time'
        )
        display_metadata['modification_time'] = fs.get(
            'modification_time'
        )
        display_metadata['access_time'] = fs.get(
            'access_time'
        )

    # Format-specific metadata
    if (
        'format_specific' in metadata
        and metadata['format_specific']
    ):
        fmt = metadata['format_specific']

        if 'format' in fmt:
            display_metadata['file_format'] = fmt['format']

        if 'mode' in fmt:
            display_metadata['color_mode'] = fmt['mode']

        if 'width' in fmt and 'height' in fmt:
            display_metadata['dimensions'] = (
                f"{fmt['width']} x {fmt['height']}"
            )

        if 'exif' in fmt:
            # Simplify EXIF for display
            display_metadata['has_exif'] = True
            display_metadata['exif_count'] = len(fmt['exif'])

    return display_metadata