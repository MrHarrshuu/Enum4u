from __future__ import annotations

from enum4u.intelligence.cpe import (
    extract_product_version,
    guess_cpe,
)

from enum4u.intelligence.cve import (
    search_cves,
)

from enum4u.intelligence.epss import (
    get_epss,
)

from enum4u.intelligence.kev import (
    lookup_kev,
)

from enum4u.intelligence.confidence import (
    calculate_intelligence_confidence,
)


def enrich_services(context) -> dict:
    ports = context.metadata.get(
        "ports",
        {},
    )

    services = ports.get(
        "ports",
        [],
    )

    results = []

    engine_config = context.config.get(
        "engine",
        {},
    )

    timeout = int(
        engine_config.get(
            "timeout",
            10,
        )
    )

    mode = str(
        context.mode
    ).lower()

    limit = (
        5
        if mode == "fast"
        else 10
    )

    # -------------------------------------------------
    # SERVICE → CPE → CVE
    # -------------------------------------------------

    for service in services:

        if not isinstance(
            service,
            dict,
        ):
            continue

        state = str(
            service.get(
                "state",
                "",
            )
        ).lower()

        # Only enrich confirmed open services.
        if state != "open":
            continue

        product, version = (
            extract_product_version(
                service
            )
        )

        if not product:
            continue

        cpe = guess_cpe(
            product,
            version,
        )

        item = {
            "port": service.get(
                "port"
            ),
            "protocol": service.get(
                "protocol"
            ),
            "service": product,
            "version": version,
            "cpe": cpe,
            "cves": [],
            "cve_count": 0,
            "epss_count": 0,
            "kev_count": 0,
            "confidence_counts": {
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "status": "completed",
        }

        if not cpe and not version:

            item["status"] = (
                "insufficient_version"
            )

            results.append(
                item
            )

            continue

        keyword = (
            f"{product} {version}".strip()
        )

        # -------------------------------------------------
        # CVE LOOKUP
        # -------------------------------------------------

        cves = search_cves(
            cpe=cpe,
            keyword=(
                keyword
                if not cpe
                else None
            ),
            timeout=timeout,
            limit=limit,
        )

        # -------------------------------------------------
        # COLLECT CVE IDs
        # -------------------------------------------------

        cve_ids = [
            str(
                cve.get("id")
            )
            for cve in cves
            if cve.get("id")
        ]

        # -------------------------------------------------
        # EPSS
        # -------------------------------------------------

        epss_data = {}

        if cve_ids:

            epss_data = get_epss(
                cve_ids,
                timeout=min(
                    timeout,
                    5,
                ),
            )

        # -------------------------------------------------
        # CISA KEV
        # -------------------------------------------------

        kev_data = {}

        if cve_ids:

            kev_data = lookup_kev(
                cve_ids,
                timeout=min(
                    timeout,
                    5,
                ),
            )

        # -------------------------------------------------
        # ATTACH EPSS + KEV + CONFIDENCE
        # -------------------------------------------------

        enriched_cves = []

        for cve in cves:

            cve_id = str(
                cve.get(
                    "id",
                    "",
                )
            ).upper()

            epss = epss_data.get(
                cve_id
            )

            kev = kev_data.get(
                cve_id
            )

            enriched = dict(
                cve
            )

            enriched["epss"] = (
                epss
                if epss
                else None
            )

            enriched["kev"] = (
                kev
                if kev
                else None
            )

            enriched[
                "known_exploited"
            ] = bool(
                kev
            )

            # -----------------------------------------
            # INTELLIGENCE CONFIDENCE
            # -----------------------------------------

            confidence_input = dict(
                enriched
            )

            confidence_input[
                "source"
            ] = cve.get(
                "source",
                "NVD",
            )

            confidence = (
                calculate_intelligence_confidence(
                    confidence_input
                )
            )

            enriched[
                "intelligence_confidence"
            ] = confidence

            if confidence in item[
                "confidence_counts"
            ]:

                item[
                    "confidence_counts"
                ][confidence] += 1

            enriched_cves.append(
                enriched
            )

        item[
            "cves"
        ] = enriched_cves

        item[
            "cve_count"
        ] = len(
            enriched_cves
        )

        item[
            "epss_count"
        ] = sum(
            1
            for cve in enriched_cves
            if cve.get(
                "epss"
            )
        )

        item[
            "kev_count"
        ] = sum(
            1
            for cve in enriched_cves
            if cve.get(
                "known_exploited"
            )
        )

        results.append(
            item
        )

    # -------------------------------------------------
    # SUMMARY
    # -------------------------------------------------

    total_cves = sum(
        item.get(
            "cve_count",
            0,
        )
        for item in results
    )

    total_epss = sum(
        item.get(
            "epss_count",
            0,
        )
        for item in results
    )

    total_kev = sum(
        item.get(
            "kev_count",
            0,
        )
        for item in results
    )

    total_confidence = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for item in results:

        counts = item.get(
            "confidence_counts",
            {},
        )

        for level in (
            "high",
            "medium",
            "low",
        ):

            total_confidence[
                level
            ] += counts.get(
                level,
                0,
            )

    return {
        "status": "completed",
        "service_count": len(
            results
        ),
        "services": results,
        "cve_count": total_cves,
        "epss_count": total_epss,
        "kev_count": total_kev,
        "confidence_counts": total_confidence,
    }