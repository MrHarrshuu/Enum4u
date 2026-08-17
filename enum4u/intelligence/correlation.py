from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse


def _normalize(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def _host(value: str) -> str:
    value = str(value).strip()

    if "://" in value:
        return _normalize(urlparse(value).hostname or value)

    return _normalize(value.split("/")[0].split(":")[0])


def correlate_assets(context) -> dict:
    assets = {}

    def add_asset(
        value: str,
        asset_type: str,
        source: str,
        metadata: dict | None = None,
    ) -> None:
        if not value:
            return

        key = f"{asset_type}:{_normalize(value)}"

        if key not in assets:
            assets[key] = {
                "id": key,
                "type": asset_type,
                "value": value,
                "sources": [],
                "metadata": {},
            }

        if source not in assets[key]["sources"]:
            assets[key]["sources"].append(source)

        if metadata:
            assets[key]["metadata"].update(metadata)

    # Target
    add_asset(
        str(context.target),
        "target",
        "target",
    )

    # Subdomains
    recon = context.metadata.get(
        "recon",
        {},
    )

    for item in recon.get(
        "subdomains",
        [],
    ):
        if isinstance(item, dict):
            value = (
                item.get("subdomain")
                or item.get("host")
                or item.get("domain")
            )
        else:
            value = item

        if value:
            add_asset(
                str(value),
                "subdomain",
                "subfinder",
            )

    # IPs
    for item in recon.get(
        "ips",
        [],
    ):
        value = (
            item.get("ip")
            if isinstance(item, dict)
            else item
        )

        if value:
            add_asset(
                str(value),
                "ip",
                "dnsx",
            )

    # HTTP endpoints
    for item in context.metadata.get(
        "endpoints",
        [],
    ):
        value = (
            item.get("url")
            if isinstance(item, dict)
            else item
        )

        if value:
            add_asset(
                str(value),
                "endpoint",
                "httpx",
            )

    # Crawled URLs
    for item in context.metadata.get(
        "urls",
        [],
    ):
        if item:
            add_asset(
                str(item),
                "url",
                "katana",
            )

    # Ports / services
    ports = context.metadata.get(
        "ports",
        {},
    )

    for item in ports.get(
        "ports",
        [],
    ):
        if not isinstance(item, dict):
            continue

        port = item.get("port")

        if port is None:
            continue

        service = item.get(
            "service",
            "",
        )

        version = item.get(
            "version",
            "",
        )

        add_asset(
            f"{context.target}:{port}",
            "service",
            "nmap",
            {
                "port": port,
                "service": service,
                "version": version,
                "state": item.get("state"),
                "protocol": item.get("protocol"),
            },
        )

    # Provider intelligence
    provider_data = context.metadata.get(
        "provider_intelligence",
        {},
    )

    for provider_name, provider in provider_data.get(
        "providers",
        {},
    ).items():

        if provider.get("status") != "completed":
            continue

        for item in provider.get(
            "data",
            [],
        ):
            if not isinstance(item, dict):
                continue

            value = (
                item.get("host")
                or item.get("domain")
                or item.get("ip")
                or item.get("url")
            )

            if not value:
                continue

            asset_type = "ip"

            if "://" in str(value):
                asset_type = "url"
            elif "." in str(value) and not str(value).replace(
                ".",
                "",
            ).isdigit():
                asset_type = "domain"

            add_asset(
                str(value),
                asset_type,
                provider_name,
            )

    # Confidence
    for asset in assets.values():
        source_count = len(
            asset["sources"]
        )

        if source_count >= 3:
            confidence = "HIGH"
        elif source_count == 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        asset["confidence"] = confidence
        asset["source_count"] = source_count

    # Host relationships
    relationships = []

    for asset in assets.values():
        if asset["type"] not in {
            "endpoint",
            "url",
            "service",
        }:
            continue

        host = _host(
            asset["value"]
        )

        for parent in assets.values():
            if parent["type"] not in {
                "target",
                "subdomain",
                "domain",
                "ip",
            }:
                continue

            parent_value = _host(
                parent["value"]
            )

            if host == parent_value:
                relationships.append({
                    "source": parent["id"],
                    "target": asset["id"],
                    "relation": "hosts",
                })

    return {
        "status": "completed",
        "asset_count": len(assets),
        "relationship_count": len(relationships),
        "assets": list(
            assets.values()
        ),
        "relationships": relationships,
    }