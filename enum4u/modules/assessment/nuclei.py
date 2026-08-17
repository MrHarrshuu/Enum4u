from __future__ import annotations

from enum4u.core.context import ScanContext
from enum4u.tools.nuclei import NucleiTool


def run_nuclei_assessment(
    context: ScanContext,
) -> None:

    tool = NucleiTool()

    mode = str(
        context.mode
    ).lower()

    result = {
        "status": "skipped",
        "reason": None,
        "count": 0,
        "findings": [],
        "mode": mode,
        "target_count": 0,
    }

    if mode == "passive":

        result["reason"] = (
            "Nuclei disabled in passive mode"
        )

        context.metadata[
            "nuclei"
        ] = result

        return

    if not tool.check_available():

        result["reason"] = (
            "Nuclei is not available"
        )

        context.metadata[
            "nuclei"
        ] = result

        return

    targets = sorted(
        set(
            context.metadata.get(
                "endpoints",
                [],
            )
        )
    )

    if not targets:
        targets = [
            context.target
        ]

    result[
        "target_count"
    ] = len(targets)

    findings = []

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

        execution = tool.execute(
            target,
            timeout=timeout,
            mode=mode,
        )

        if not execution.success:
            continue

        findings.extend(
            tool.parse_output(
                execution.stdout
            )
        )

    result[
        "status"
    ] = "completed"

    result[
        "count"
    ] = len(findings)

    result[
        "findings"
    ] = findings

    context.metadata[
        "nuclei"
    ] = result