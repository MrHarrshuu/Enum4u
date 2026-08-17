from enum4u.intelligence import (
    calculate_intelligence_confidence,
    enrich_intelligence_confidence,
)


def test_high_intelligence_confidence():
    finding = {
        "id": "CVE-2026-TEST",
        "cvss": 9.8,
        "epss": 0.95,
        "known_exploited": True,
        "source": "NVD",
    }

    result = calculate_intelligence_confidence(finding)

    assert result == "high"


def test_medium_intelligence_confidence():
    finding = {
        "id": "CVE-2026-TEST",
        "cvss": 7.5,
        "source": "NVD",
    }

    result = calculate_intelligence_confidence(finding)

    assert result == "medium"


def test_low_intelligence_confidence():
    finding = {
        "id": "CVE-2026-TEST",
    }

    result = calculate_intelligence_confidence(finding)

    assert result == "low"


def test_enrichment_adds_confidence():
    findings = [
        {
            "id": "CVE-2026-TEST",
            "cvss": 9.8,
            "epss": 0.95,
            "known_exploited": True,
            "source": "NVD",
        }
    ]

    result = enrich_intelligence_confidence(findings)

    assert len(result) == 1
    assert result[0]["intelligence_confidence"] == "high"


def test_enrichment_preserves_original_fields():
    finding = {
        "id": "CVE-2026-TEST",
        "name": "Synthetic vulnerability",
        "severity": "high",
    }

    result = enrich_intelligence_confidence([finding])

    assert result[0]["id"] == "CVE-2026-TEST"
    assert result[0]["name"] == "Synthetic vulnerability"
    assert result[0]["severity"] == "high"
    assert "intelligence_confidence" in result[0]