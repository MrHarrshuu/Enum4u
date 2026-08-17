from __future__ import annotations


def calculate_intelligence_confidence(
    finding: dict,
) -> str:
    """
    Calculate confidence for vulnerability intelligence.

    Signals:
      - CVE identifier
      - CVSS score
      - EPSS score
      - KEV status
      - NVD/source information
    """

    score = 0

    cve_id = str(
        finding.get(
            "id",
            finding.get(
                "cve",
                "",
            ),
        )
        or ""
    ).strip().upper()

    if cve_id.startswith("CVE-"):
        score += 1

    cvss = finding.get(
        "cvss"
    )

    if isinstance(
        cvss,
        dict,
    ):
        cvss = cvss.get(
            "score"
        )

    try:
        if cvss is not None:
            float(cvss)
            score += 1
    except (
        TypeError,
        ValueError,
    ):
        pass

    epss = finding.get(
        "epss"
    )

    if isinstance(
        epss,
        dict,
    ):
        epss = epss.get(
            "epss"
        )

    try:
        if epss is not None:
            float(epss)
            score += 1
    except (
        TypeError,
        ValueError,
    ):
        pass

    known_exploited = finding.get(
        "known_exploited",
        finding.get(
            "is_kev",
            False,
        ),
    )

    if bool(
        known_exploited
    ):
        score += 2

    source = str(
        finding.get(
            "source",
            "",
        )
        or ""
    ).strip().lower()

    if source in {
        "nvd",
        "cisa kev",
        "first",
    }:
        score += 1

    if score >= 5:
        return "high"

    if score >= 3:
        return "medium"

    return "low"


def enrich_intelligence_confidence(
    findings: list[dict],
) -> list[dict]:
    """
    Add intelligence confidence to each finding.
    """

    results = []

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        result = dict(
            finding
        )

        result[
            "intelligence_confidence"
        ] = calculate_intelligence_confidence(
            result
        )

        results.append(
            result
        )

    return results