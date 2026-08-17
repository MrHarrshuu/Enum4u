from __future__ import annotations

import json
import urllib.request


KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def get_kev_catalog(
    timeout: int = 5,
) -> dict[str, dict]:
    """
    Download the CISA Known Exploited Vulnerabilities
    catalog and index it by CVE ID.
    """

    request = urllib.request.Request(
        KEV_CATALOG_URL,
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

    for item in document.get(
        "vulnerabilities",
        [],
    ):
        cve = str(
            item.get("cveID", "")
        ).strip().upper()

        if not cve:
            continue

        results[cve] = {
            "is_kev": True,
            "vendor_project": item.get(
                "vendorProject"
            ),
            "product": item.get(
                "product"
            ),
            "vulnerability_name": item.get(
                "vulnerabilityName"
            ),
            "date_added": item.get(
                "dateAdded"
            ),
            "due_date": item.get(
                "dueDate"
            ),
            "known_ransomware_campaign_use": item.get(
                "knownRansomwareCampaignUse"
            ),
            "notes": item.get(
                "notes"
            ),
            "source": "CISA KEV",
        }

    return results


def lookup_kev(
    cve_ids: list[str],
    timeout: int = 5,
) -> dict[str, dict]:
    """
    Return KEV information only for requested CVEs.
    """

    catalog = get_kev_catalog(
        timeout=timeout
    )

    if not catalog:
        return {}

    results = {}

    for cve_id in cve_ids:
        cve = str(
            cve_id or ""
        ).strip().upper()

        if cve in catalog:
            results[cve] = catalog[cve]

    return results