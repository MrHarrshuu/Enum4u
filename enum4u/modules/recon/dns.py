from enum4u.core.context import ScanContext
from enum4u.tools.dnsx import DnsxTool


def run_dns_recon(context: ScanContext) -> None:
    tool = DnsxTool()

    result = {
        "status": "skipped",
        "reason": None,
        "count": 0,
    }

    if not context.subdomains:
        result["reason"] = "no subdomains available"
        context.metadata["dns"] = result
        return

    if not tool.check_available():
        result["reason"] = "dnsx is not available"
        context.metadata["dns"] = result
        return

    execution = tool.execute_input(
        sorted(context.subdomains),
        timeout=context.config.get("engine", {}).get(
            "timeout",
            60,
        ),
    )

    if not execution.success:
        result["status"] = "failed"
        result["reason"] = (
            execution.stderr.strip()
            or f"dnsx exited with code {execution.return_code}"
        )

        context.metadata["dns"] = result
        return

    addresses = tool.parse_output(execution.stdout)

    for address in addresses:
        context.add_ip(address)

    result["status"] = "completed"
    result["count"] = len(addresses)

    context.metadata["dns"] = result