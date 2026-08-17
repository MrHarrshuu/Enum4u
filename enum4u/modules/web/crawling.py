from __future__ import annotations

from enum4u.core.context import ScanContext
from enum4u.tools.katana import KatanaTool


def run_crawling(context: ScanContext) -> None:
    tool = KatanaTool()

    result = {
        "status": "skipped",
        "count": 0,
        "urls": [],
        "reason": None,
        "method": None,
    }

    if not tool.check_available():
        result["reason"] = "Katana is not available"
        context.metadata["crawl"] = result
        return

    endpoints = context.metadata.get(
        "endpoints",
        [],
    )

    targets = list(endpoints)

    if not targets:
        target = str(context.target).strip()

        if target:
            if not target.startswith(
                ("http://", "https://")
            ):
                target = f"http://{target}"

            targets = [target]

    if not targets:
        result["reason"] = "No HTTP targets available"
        context.metadata["crawl"] = result
        return

    # =========================================================
    # FAST MODE
    # =========================================================
    #
    # For FAST mode, don't perform broad crawling.
    # The HTTP endpoint itself is already a useful result.
    #
    if context.mode == "fast":
        urls = sorted(set(targets))

        result["status"] = "completed"
        result["count"] = len(urls)
        result["urls"] = urls
        result["method"] = "endpoint-only"

        context.metadata["crawl"] = result

        all_urls = context.metadata.setdefault(
            "urls",
            [],
        )

        for url in urls:
            if url not in all_urls:
                all_urls.append(url)

        return

    # =========================================================
    # DEEP MODE
    # =========================================================

    discovered = set()

    timeout = int(
        context.config.get(
            "engine",
            {},
        ).get(
            "timeout",
            60,
        )
    )

    for target in targets:
        try:
            execution = tool.execute(
                target,
                timeout=timeout,
            )
        except Exception as exc:
            result["reason"] = str(exc)
            continue

        if not execution.success:
            continue

        for url in tool.parse_output(
            execution.stdout
        ):
            discovered.add(url)

    urls = sorted(discovered)

    result["status"] = "completed"
    result["count"] = len(urls)
    result["urls"] = urls
    result["method"] = "katana"

    context.metadata["crawl"] = result

    all_urls = context.metadata.setdefault(
        "urls",
        [],
    )

    for url in urls:
        if url not in all_urls:
            all_urls.append(url)