from enum4u.core.context import ScanContext
from enum4u.tools.subfinder import SubfinderTool


def run_subdomain_recon(context: ScanContext) -> None:
    tool = SubfinderTool()

    result = {
        "status": "skipped",
        "reason": None,
        "count": 0,
    }

    if not tool.check_available():
        result["reason"] = "subfinder is not available"
        context.metadata["recon"] = result
        return

    execution = tool.execute(
        context.target,
        timeout=context.config.get("engine", {}).get(
            "timeout",
            60,
        ),
    )

    if not execution.success:
        result["status"] = "failed"
        result["reason"] = (
            execution.stderr.strip()
            or f"subfinder exited with code {execution.return_code}"
        )

        context.metadata["recon"] = result
        return

    subdomains = tool.parse_output(execution.stdout)

    for subdomain in subdomains:
        context.add_subdomain(subdomain)

    result["status"] = "completed"
    result["count"] = len(subdomains)

    context.metadata["recon"] = result