from __future__ import annotations

import re


def _clean(value: str) -> str:
    value = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9._-]+", "", value)


ALIASES = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgres": ("postgresql", "postgresql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "php": ("php", "php"),
    "node": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "iis": ("microsoft", "internet_information_services"),
}


def guess_cpe(
    product: str,
    version: str = "",
) -> str | None:
    product_clean = _clean(product)
    version_clean = _clean(version)

    if not product_clean:
        return None

    vendor, product_name = ALIASES.get(
        product_clean,
        (product_clean, product_clean),
    )

    # CPE 2.3:
    # cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    if version_clean:
        return (
            f"cpe:2.3:a:"
            f"{vendor}:"
            f"{product_name}:"
            f"{version_clean}:"
            f"*:*:*:*:*:*:*"
        )

    # Wildcard version.
    return (
        f"cpe:2.3:a:"
        f"{vendor}:"
        f"{product_name}:"
        f"*:*:*:*:*:*:*:*"
    )


def extract_product_version(
    service: dict,
) -> tuple[str, str]:
    product = str(
        service.get("service", "")
    ).strip()

    version = str(
        service.get("version", "")
    ).strip()

    # If Nmap already separated product/version,
    # keep those values.
    if product and version:
        return product, version

    # Sometimes the product/version is contained
    # entirely inside one field.
    combined = " ".join(
        value
        for value in (product, version)
        if value
    )

    match = re.search(
        r"([A-Za-z][A-Za-z0-9_.+-]*)"
        r"(?:[/\s_-]+)"
        r"([0-9]+(?:\.[0-9]+)+(?:[-._][A-Za-z0-9]+)*)",
        combined,
    )

    if match:
        return (
            match.group(1),
            match.group(2),
        )

    return product, version