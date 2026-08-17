from enum4u.risk import (
    calculate_confidence,
    calculate_priority,
    prioritize_findings,
    score_finding,
)


def test_finding_confidence():
    finding = {
        "id": "CVE-TEST",
        "template_id": "test-template",
        "name": "Test vulnerability",
        "matched_at": "http://127.0.0.1/",
        "host": "127.0.0.1",
    }

    assert calculate_confidence(finding) == "high"


def test_high_severity_high_confidence_without_intelligence():
    result = calculate_priority(
        "high",
        "high",
    )

    # 4 severity + 2 confidence = 6
    assert result == "medium"


def test_high_priority_with_cvss():
    result = calculate_priority(
        "high",
        "high",
        cvss=7.5,
    )

    # 4 + 2 + 1 = 7
    assert result == "high"


def test_critical_priority_with_intelligence():
    result = calculate_priority(
        "high",
        "high",
        cvss=9.8,
        epss=0.95,
        known_exploited=True,
    )

    # 4 + 2 + 2 + 2 + 3 = 13
    assert result == "critical"


def test_medium_severity_medium_confidence():
    result = calculate_priority(
        "medium",
        "medium",
    )

    # 3 + 1 = 4
    assert result == "medium"


def test_low_severity_low_confidence():
    result = calculate_priority(
        "low",
        "low",
    )

    # 2 + 0 = 2
    assert result == "low"


def test_score_finding():
    finding = {
        "id": "CVE-TEST",
        "source": "NVD",
        "name": "Test vulnerability",
        "severity": "high",
        "host": "127.0.0.1",
        "template_id": "test-template",
        "matched_at": "http://127.0.0.1/",
        "cvss": 9.8,
        "epss": 0.95,
        "known_exploited": True,
    }

    result = score_finding(finding)

    assert result["severity"] == "high"
    assert result["confidence"] == "high"
    assert result["priority"] == "critical"


def test_prioritize_findings():
    findings = [
        {
            "id": "LOW",
            "name": "Low finding",
            "severity": "low",
        },
        {
            "id": "CRITICAL",
            "name": "Critical finding",
            "severity": "critical",
            "template_id": "critical",
            "matched_at": "http://127.0.0.1/",
            "host": "127.0.0.1",
        },
    ]

    result = prioritize_findings(findings)

    assert len(result) == 2
    assert result[0]["severity"] == "critical"
    assert result[1]["severity"] == "low"