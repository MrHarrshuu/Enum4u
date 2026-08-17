from __future__ import annotations


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}


ALIASES = {
    "informational": "info",
    "information": "info",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "notice": "info",
    "none": "info",
    "null": "unknown",
}


def normalize_severity(
    value: str | None,
) -> str:

    if value is None:
        return "unknown"

    value = str(
        value
    ).strip().lower()

    if value in SEVERITY_ORDER:
        return value

    return ALIASES.get(
        value,
        "unknown",
    )


def severity_score(
    value: str | None,
) -> int:

    severity = normalize_severity(
        value
    )

    return SEVERITY_ORDER.get(
        severity,
        0,
    )