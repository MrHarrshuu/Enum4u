from __future__ import annotations

from enum4u.risk.severity import (
    normalize_severity,
    severity_score,
)


def _float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def calculate_confidence(
    finding: dict,
) -> str:
    score = 0

    if finding.get("template_id"):
        score += 1

    if finding.get("name"):
        score += 1

    if finding.get("matched_at"):
        score += 1

    if finding.get("host"):
        score += 1

    if finding.get("id"):
        score += 1

    if finding.get("source"):
        score += 1

    if score >= 5:
        return "high"

    if score >= 3:
        return "medium"

    return "low"


def calculate_priority(
    severity: str,
    confidence: str,
    cvss: float | None = None,
    epss: float | None = None,
    known_exploited: bool = False,
) -> str:

    severity = normalize_severity(
        severity
    )

    confidence = str(
        confidence or "low"
    ).lower()

    score = severity_score(
        severity
    )

    confidence_bonus = {
        "high": 2,
        "medium": 1,
        "low": 0,
    }.get(
        confidence,
        0,
    )

    score += confidence_bonus

    cvss_value = _float(cvss)
    epss_value = _float(epss)

    # CVSS reinforcement
    if cvss_value >= 9.0:
        score += 2
    elif cvss_value >= 7.0:
        score += 1

    # EPSS reinforcement
    if epss_value >= 0.90:
        score += 2
    elif epss_value >= 0.50:
        score += 1

    # CISA KEV = known exploitation
    if known_exploited:
        score += 3

    if score >= 10:
        return "critical"

    if score >= 7:
        return "high"

    if score >= 4:
        return "medium"

    if score >= 2:
        return "low"

    return "info"


def score_finding(
    finding: dict,
) -> dict:

    result = dict(
        finding
    )

    severity = normalize_severity(
        finding.get(
            "severity"
        )
    )

    confidence = calculate_confidence(
        finding
    )

    cvss = finding.get(
        "cvss"
    )

    epss = finding.get(
        "epss"
    )

    known_exploited = bool(
        finding.get(
            "known_exploited",
            False,
        )
    )

    priority = calculate_priority(
        severity=severity,
        confidence=confidence,
        cvss=cvss,
        epss=epss,
        known_exploited=known_exploited,
    )

    result["severity"] = severity
    result["confidence"] = confidence
    result["priority"] = priority

    return result