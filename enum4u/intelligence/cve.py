from __future__ import annotations

import json
import urllib.parse
import urllib.request


NVD_API = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)


def _extract_cvss(metrics: dict) -> dict | None:
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        metric_list = metrics.get(
            metric_name,
            [],
        )

        if not metric_list:
            continue

        metric = metric_list[0]
        data = metric.get(
            "cvssData",
            {},
        )

        return {
            "version": data.get("version"),
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity"),
            "vector": data.get("vectorString"),
        }

    return None


def search_cves(
    cpe: str | None = None,
    keyword: str | None = None,
    timeout: int = 10,
    limit: int = 10,
) -> list[dict]:

    if not cpe and not keyword:
        return []

    params = {
        "resultsPerPage": str(
            max(1, min(int(limit), 20))
        ),
    }

    if cpe:
        params["cpeName"] = cpe
    else:
        params["keywordSearch"] = keyword

    url = (
        NVD_API
        + "?"
        + urllib.parse.urlencode(params)
    )

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
        return []

    results = []

    for item in document.get(
        "vulnerabilities",
        [],
    ):
        cve = item.get("cve", {})

        cve_id = cve.get("id")

        if not cve_id:
            continue

        description = ""

        for desc in cve.get(
            "descriptions",
            [],
        ):
            if desc.get("lang") == "en":
                description = desc.get(
                    "value",
                    "",
                )
                break

        cvss = _extract_cvss(
            cve.get("metrics", {})
        )

        results.append({
            "id": cve_id,
            "description": description,
            "cvss": cvss,
            "published": cve.get("published"),
            "last_modified": cve.get(
                "lastModified"
            ),
            "source": "NVD",
        })

    return results