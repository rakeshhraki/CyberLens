from typing import Dict, List, Any


RISK_LEVELS = {
    "LOW": (0, 24),
    "MEDIUM": (25, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}


def calculate_risk_score(
    indicators: List[Dict[str, Any]]
) -> Dict[str, Any]:
    total_score = sum(
        indicator.get("score", 0)
        for indicator in indicators
        if isinstance(indicator, dict)
    )

    score = min(max(total_score, 0), 100)
    risk_level = get_risk_level(score)

    return {
        "score": score,
        "risk_level": risk_level,
        "indicator_count": len(indicators),
        "score_breakdown": build_score_breakdown(indicators),
    }


def get_risk_level(score: int) -> str:
    score = min(max(score, 0), 100)

    for level, (minimum, maximum) in RISK_LEVELS.items():
        if minimum <= score <= maximum:
            return level

    return "CRITICAL"


def build_score_breakdown(
    indicators: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    breakdown = []

    for indicator in indicators:
        if not isinstance(indicator, dict):
            continue

        breakdown.append({
            "id": indicator.get("id", "UNKNOWN"),
            "name": indicator.get(
                "name",
                "Unknown Indicator"
            ),
            "category": indicator.get(
                "category",
                "UNKNOWN"
            ),
            "severity": indicator.get(
                "severity",
                "UNKNOWN"
            ),
            "score": indicator.get("score", 0),
            "evidence": indicator.get(
                "evidence",
                ""
            ),
        })

    return breakdown


def get_risk_description(risk_level: str) -> str:
    descriptions = {
        "LOW": (
            "Few suspicious characteristics were identified. "
            "This does not guarantee that the file is safe."
        ),
        "MEDIUM": (
            "Some suspicious characteristics were identified. "
            "Further analysis is recommended."
        ),
        "HIGH": (
            "Multiple suspicious characteristics were identified. "
            "The file should be treated with caution and "
            "investigated further."
        ),
        "CRITICAL": (
            "Multiple high-risk characteristics were identified. "
            "The file requires detailed investigation and "
            "should not be trusted."
        ),
    }

    return descriptions.get(
        risk_level,
        "Risk could not be determined."
    )


def calculate_risk(
    analysis_data: Dict[str, Any]
) -> Dict[str, Any]:
    indicators_data = analysis_data.get(
        "indicators",
        {}
    )

    indicators = indicators_data.get(
        "detected_indicators",
        []
    )

    result = calculate_risk_score(indicators)

    result["description"] = get_risk_description(
        result["risk_level"]
    )

    return result


def generate_verdict(
    risk_result: Dict[str, Any]
) -> Dict[str, Any]:
    risk_level = risk_result.get(
        "risk_level",
        "UNKNOWN"
    )

    score = risk_result.get(
        "score",
        0
    )

    verdicts = {
        "LOW": {
            "verdict": "Likely Safe",
            "recommendation": (
                "No major suspicious indicators were detected. "
                "Continue normal security validation before "
                "trusting the file."
            ),
        },
        "MEDIUM": {
            "verdict": "Suspicious",
            "recommendation": (
                "Review the detected indicators and file "
                "characteristics before opening or distributing "
                "the file."
            ),
        },
        "HIGH": {
            "verdict": "High Risk",
            "recommendation": (
                "Treat the file as potentially malicious. "
                "Do not execute it. Perform additional "
                "investigation in an isolated analysis environment."
            ),
        },
        "CRITICAL": {
            "verdict": "Critical Risk",
            "recommendation": (
                "Treat the file as potentially malicious. "
                "Do not execute or distribute it. Escalate "
                "for detailed malware investigation."
            ),
        },
    }

    result = verdicts.get(
        risk_level,
        {
            "verdict": "Unknown",
            "recommendation": (
                "Insufficient information to determine "
                "the appropriate action."
            ),
        },
    )

    return {
        "verdict": result["verdict"],
        "recommendation": result["recommendation"],
        "risk_level": risk_level,
        "score": score,
    }