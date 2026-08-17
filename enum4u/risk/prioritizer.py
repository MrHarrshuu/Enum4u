from __future__ import annotations

from enum4u.risk.scorer import (
    score_finding,
)

from enum4u.risk.severity import (
    severity_score,
)


def _finding_key(
    finding: dict,
) -> tuple:

    return (
        str(
            finding.get(
                "id",
                finding.get(
                    "template_id",
                    "",
                ),
            )
        ).lower(),
        str(
            finding.get(
                "host",
                finding.get(
                    "matched_at",
                    "",
                ),
            )
        ).lower(),
        str(
            finding.get(
                "port",
                "",
            )
        ),
    )


def prioritize_findings(
    findings: list[dict],
) -> list[dict]:

    scored = []

    seen = set()

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        key = _finding_key(
            finding
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        scored.append(
            score_finding(
                finding
            )
        )

    scored.sort(
        key=lambda item: (
            severity_score(
                item.get(
                    "priority"
                )
            ),
            severity_score(
                item.get(
                    "severity"
                )
            ),
            (
                float(
                    item.get(
                        "cvss"
                    )
                )
                if str(
                    item.get(
                        "cvss",
                        ""
                    )
                ).replace(
                    ".",
                    "",
                    1,
                ).isdigit()
                else 0
            ),
            str(
                item.get(
                    "name",
                    item.get(
                        "id",
                        "",
                    ),
                )
            ).lower(),
        ),
        reverse=True,
    )

    return scored