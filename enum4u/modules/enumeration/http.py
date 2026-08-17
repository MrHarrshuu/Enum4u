from __future__ import annotations

from enum4u.core.context import ScanContext
from enum4u.tools.httpx import HttpxTool


def _store_endpoint(context: ScanContext, endpoint: str) -> None:
    """
    Store an HTTP endpoint without requiring ScanContext.add_endpoint().

    This keeps the HTTP module compatible with the current ScanContext
    implementation while preserving a clean metadata representation.
    """

    endpoints = context.metadata.setdefault("endpoints", [])

    if endpoint not in endpoints:
        endpoints.append(endpoint)

    # If a future ScanContext implementation provides add_endpoint(),
    # use it as well. This keeps the module forward-compatible.
    add_endpoint = getattr(context, "add_endpoint", None)

    if callable(add_endpoint):
        try:
            add_endpoint(endpoint)
        except (AttributeError, TypeError):
            # Metadata storage above is already successful.
            pass


def _build_targets(context: ScanContext) -> list[str]:
    """
    Build unique HTTP targets for ProjectDiscovery httpx.
    """

    targets: list[str] = []

    # Prefer discovered subdomains.
    for target in sorted(context.subdomains):
        target = str(target).strip()

        if target and target not in targets:
            targets.append(target)

    # If no subdomains exist, use the original target.
    if not targets:
        target = str(context.target).strip()

        if target:
            targets.append(target)

    return targets


def run_http_enumeration(context: ScanContext) -> None:
    """
    Execute ProjectDiscovery httpx against discovered targets.

    Results are stored in:
        context.metadata["http"]
        context.metadata["endpoints"]
    """

    tool = HttpxTool()

    result = {
        "status": "skipped",
        "reason": None,
        "count": 0,
        "targets": 0,
    }

    # ---------------------------------------------------------
    # Tool availability
    # ---------------------------------------------------------

    if not tool.check_available():
        result["reason"] = (
            "ProjectDiscovery httpx is not available"
        )

        context.metadata["http"] = result
        return

    # ---------------------------------------------------------
    # Build targets
    # ---------------------------------------------------------

    targets = _build_targets(context)

    result["targets"] = len(targets)

    if not targets:
        result["reason"] = "No HTTP targets available"
        context.metadata["http"] = result
        return

    # ---------------------------------------------------------
    # Execute httpx
    # ---------------------------------------------------------

    timeout = int(
        context.config.get("engine", {}).get(
            "timeout",
            60,
        )
    )

    execution = tool.execute_input(
        targets,
        timeout=timeout,
    )

    # ---------------------------------------------------------
    # Handle execution failure
    # ---------------------------------------------------------

    if not execution.success:
        result["status"] = "failed"

        result["reason"] = (
            execution.stderr.strip()
            or f"httpx exited with code {execution.return_code}"
        )

        context.metadata["http"] = result
        return

    # ---------------------------------------------------------
    # Parse httpx output
    # ---------------------------------------------------------

    endpoints = tool.parse_output(
        execution.stdout
    )

    # Ensure deterministic, duplicate-free results.
    unique_endpoints = sorted(
        {
            str(endpoint).strip()
            for endpoint in endpoints
            if str(endpoint).strip()
        }
    )

    # ---------------------------------------------------------
    # Store endpoints
    # ---------------------------------------------------------

    for endpoint in unique_endpoints:
        _store_endpoint(
            context,
            endpoint,
        )

    # ---------------------------------------------------------
    # Final result
    # ---------------------------------------------------------

    result["status"] = "completed"
    result["count"] = len(unique_endpoints)

    context.metadata["http"] = result