import hashlib

from analyzer.hashing import calculate_all_hashes


def test_calculate_all_hashes(tmp_path):
    test_file = tmp_path / "sample.txt"
    content = b"CyberLens test file"

    test_file.write_bytes(content)

    result = calculate_all_hashes(
        str(test_file)
    )

    assert result["md5"] == hashlib.md5(
        content
    ).hexdigest()

    assert result["sha1"] == hashlib.sha1(
        content
    ).hexdigest()

    assert result["sha256"] == hashlib.sha256(
        content
    ).hexdigest()