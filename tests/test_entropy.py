from analyzer.entropy import analyze_entropy


def test_entropy_analysis(tmp_path):
    test_file = tmp_path / "sample.txt"

    test_file.write_bytes(
        b"CyberLens entropy test data"
    )

    result = analyze_entropy(
        str(test_file)
    )

    assert isinstance(result, dict)
    assert "entropy" in result
    assert 0 <= result["entropy"] <= 8