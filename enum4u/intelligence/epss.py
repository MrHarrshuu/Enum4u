from __future__ import annotations

import json
import urllib.parse
import urllib.request


EPSS_API = "https://api.first.org/data/v1/epss"


def get_epss(
    cve_ids: list[str],
    timeout: int = 5,
) -> dict[str, dict]:
    """
    Fetch current EPSS scores for a small batch of CVEs.

    Returns:
        {
            "CVE-2024-1234": {
                "epss": 0.91,
                "percentile": 0.99,
                "source": "FIRST"
            }
        }
    """

    clean_ids = []

    for cve_id in cve_ids:
        value = str(cve_id or "").strip().upper()

        if value and value.startswith("CVE-"):
            if value not in clean_ids:
                clean_ids.append(value)

    if not clean_ids:
        return {}

    # FIRST supports comma-separated CVE IDs.
    query = urllib.parse.urlencode({
        "cve": ",".join(clean_ids),
    })

    url = f"{EPSS_API}?{query}"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Enum4u/0.1.0",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=max(1, int(timeout)),
        ) as response:
            raw = response.read().decode(
                "utf-8",
                errors="replace",
            )

        document = json.loads(raw)

    except Exception:
        return {}

    results = {}

    for item in document.get("data", []):
        cve = str(
            item.get("cve", "")
        ).strip().upper()

        if not cve:
            continue

        try:
            epss = float(
                item.get("epss", 0)
            )
        except (TypeError, ValueError):
            epss = 0.0

        try:
            percentile = float(
                item.get("percentile", 0)
            )
        except (TypeError, ValueError):
            percentile = 0.0

        results[cve] = {
            "epss": epss,
            "percentile": percentile,
            "source": "FIRST",
            "created": item.get("date")
            or item.get("created"),
        }

    return results