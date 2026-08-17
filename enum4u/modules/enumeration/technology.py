from __future__ import annotations

import re

from enum4u.core.context import ScanContext


TECHNOLOGY_PATTERNS = {
    "nginx": [
        r"nginx",
    ],
    "apache": [
        r"apache",
        r"httpd",
    ],
    "iis": [
        r"microsoft-iis",
        r"iis",
    ],
    "php": [
        r"php",
    ],
    "wordpress": [
        r"wordpress",
        r"wp-content",
        r"wp-includes",
    ],
    "nodejs": [
        r"node\.js",
        r"express",
    ],
    "django": [
        r"django",
    ],
    "flask": [
        r"flask",
        r"werkzeug",
    ],
    "laravel": [
        r"laravel",
    ],
    "jquery": [
        r"jquery",
    ],
    "react": [
        r"react",
    ],
    "vue": [
        r"vue\.js",
    ],
}


def _detect(
    text: str,
) -> list[str]:

    detected = []

    for technology, patterns in (
        TECHNOLOGY_PATTERNS.items()
    ):
        for pattern in patterns:
            if re.search(
                pattern,
                text,
                re.IGNORECASE,
            ):
                detected.append(
                    technology
                )
                break

    return sorted(
        set(detected)
    )


def run_technology_enumeration(
    context: ScanContext,
) -> None:

    technologies = set()

    # -------------------------------------------------
    # HTTP enumeration data
    # -------------------------------------------------

    http_data = context.metadata.get(
        "http",
        {},
    )

    if isinstance(
        http_data,
        dict,
    ):
        http_text = str(
            http_data
        )

        technologies.update(
            _detect(
                http_text
            )
        )

    # -------------------------------------------------
    # Crawled endpoint data
    # -------------------------------------------------

    endpoints = context.metadata.get(
        "endpoints",
        [],
    )

    if isinstance(
        endpoints,
        list,
    ):
        for endpoint in endpoints:

            if isinstance(
                endpoint,
                dict,
            ):
                text = " ".join(
                    str(value)
                    for value in endpoint.values()
                )
            else:
                text = str(
                    endpoint
                )

            technologies.update(
                _detect(text)
            )

    # -------------------------------------------------
    # Service enumeration data
    # -------------------------------------------------

    services_data = context.metadata.get(
        "services",
        {},
    )

    if isinstance(
        services_data,
        dict,
    ):
        services = services_data.get(
            "services",
            [],
        )

        for service in services:

            if not isinstance(
                service,
                dict,
            ):
                continue

            text = " ".join(
                str(
                    service.get(
                        key,
                        "",
                    )
                )
                for key in (
                    "service",
                    "version",
                )
            )

            technologies.update(
                _detect(text)
            )

    result = {
        "status": "completed",
        "count": len(
            technologies
        ),
        "technologies": sorted(
            technologies
        ),
    }

    context.metadata[
        "technology"
    ] = result