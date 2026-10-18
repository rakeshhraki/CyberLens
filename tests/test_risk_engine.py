from analyzer.risk_engine import (
    calculate_risk_score,
    get_risk_level,
    generate_verdict,
)


def test_risk_score():
    indicators = [
        {
            "id": "IND-001",
            "name": "Test Indicator",
            "category": "TEST",
            "severity": "HIGH",
            "score": 30,
            "evidence": "Test evidence",
        }
    ]

    result = calculate_risk_score(indicators)

    assert result["score"] == 30
    assert result["risk_level"] == "MEDIUM"
    assert result["indicator_count"] == 1


def test_risk_levels():
    assert get_risk_level(10) == "LOW"
    assert get_risk_level(30) == "MEDIUM"
    assert get_risk_level(60) == "HIGH"
    assert get_risk_level(90) == "CRITICAL"


def test_generate_verdict():
    risk_result = {
        "score": 80,
        "risk_level": "CRITICAL",
    }

    result = generate_verdict(risk_result)

    assert result["verdict"] == "Critical Risk"
    assert result["risk_level"] == "CRITICAL"
    assert result["score"] == 80