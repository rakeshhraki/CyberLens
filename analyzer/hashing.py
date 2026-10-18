import hashlib
from typing import Dict


def calculate_md5(file_path: str) -> str:
    """
    Calculate MD5 hash of a file.
    MD5 is not cryptographically secure but widely used for file identification.
    """
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def calculate_sha1(file_path: str) -> str:
    """
    Calculate SHA-1 hash of a file.
    SHA-1 is deprecated for security but still used for legacy compatibility.
    """
    hash_sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()


def calculate_sha256(file_path: str) -> str:
    """
    Calculate SHA-256 hash of a file.
    SHA-256 is the primary file identifier for CyberLens.
    Cryptographically secure and widely adopted.
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def calculate_all_hashes(file_path: str) -> Dict[str, str]:
    """
    Calculate all hashes (MD5, SHA-1, SHA-256) for a file.
    Returns dictionary with hash values.
    """
    return {
        'md5': calculate_md5(file_path),
        'sha1': calculate_sha1(file_path),
        'sha256': calculate_sha256(file_path)
    }


def verify_hash(file_path: str, hash_type: str, expected_hash: str) -> bool:
    """
    Verify a file's hash against an expected value.
    Returns True if hash matches, False otherwise.
    """
    hash_type = hash_type.lower()
    
    if hash_type == 'md5':
        actual_hash = calculate_md5(file_path)
    elif hash_type == 'sha1':
        actual_hash = calculate_sha1(file_path)
    elif hash_type == 'sha256':
        actual_hash = calculate_sha256(file_path)
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")
    
    return actual_hash.lower() == expected_hash.lower()
