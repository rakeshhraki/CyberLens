from analyzer.indicators import detect_all_indicators


def test_indicator_detection():
    analysis_data = {
        "identification": {
            "extension": ".exe",
            "file_type": "PE32 executable",
            "mime_type": "application/x-dosexec",
        },
        "strings": {
            "strings": [
                "powershell -enc test",
                "http://example.com",
            ]
        },
        "entropy": {
            "entropy": 7.5,
        },
        "pe_analysis": {},
    }

    result = detect_all_indicators(analysis_data)

    assert isinstance(result, dict)
    assert "detected_indicators" in result
    assert isinstance(
        result["detected_indicators"],
        list
    )