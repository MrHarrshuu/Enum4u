from __future__ import annotations

import socket
from urllib.parse import urlparse

from enum4u.core.context import ScanContext
from enum4u.tools.nmap import NmapTool


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
}


def _extract_target(
    target: str,
) -> tuple[str, int | None]:
    value = str(target).strip()

    if "://" in value:
        parsed = urlparse(value)

        host = parsed.hostname

        if not host:
            return value, None

        return host, parsed.port

    if value.startswith("["):
        closing = value.find("]")

        if closing != -1:
            host = value[1:closing]
            remainder = value[closing + 1:]

            if remainder.startswith(":"):
                port = remainder[1:]

                if port.isdigit():
                    return host, int(port)

            return host, None

    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)

        if port.isdigit():
            return host, int(port)

    return value, None


def _fast_tcp_check(
    host: str,
    port: int,
    timeout: float = 1.0,
) -> dict:
    service = COMMON_SERVICES.get(
        port,
        "unknown",
    )

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(timeout)

    try:
        result = sock.connect_ex(
            (host, port)
        )

        if result == 0:
            state = "open"
        elif result in {
            10061,  # Windows connection refused
            111,    # Linux connection refused
        }:
            state = "closed"
        else:
            state = "filtered"

    except socket.timeout:
        state = "filtered"

    except OSError:
        state = "filtered"

    finally:
        sock.close()

    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "service": service,
        "version": "",
    }


def _parse_nmap_output(
    stdout: str,
) -> list[dict]:
    import re

    pattern = re.compile(
        r"^(\d+)\/(\w+)\s+"
        r"(open|closed|filtered|open\|filtered)\s+"
        r"(\S+)"
        r"(?:\s+(.*))?$"
    )

    ports = []

    for line in stdout.splitlines():
        line = line.strip()

        match = pattern.match(line)

        if not match:
            continue

        ports.append(
            {
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": (
                    match.group(5) or ""
                ).strip(),
            }
        )

    return ports


def run_port_enumeration(
    context: ScanContext,
) -> None:

    result = {
        "status": "skipped",
        "count": 0,
        "ports": [],
        "reason": None,
        "method": None,
    }

    host, explicit_port = _extract_target(
        context.target
    )

    # =========================================================
    # FAST MODE
    # =========================================================
    #
    # If the user supplied target:port, don't launch Nmap.
    # A direct TCP connect is dramatically faster for this case.
    #
    if (
        context.mode == "fast"
        and explicit_port is not None
    ):
        try:
            port_info = _fast_tcp_check(
                host,
                explicit_port,
                timeout=1.0,
            )

            ports = [port_info]

            result["status"] = "completed"
            result["count"] = len(ports)
            result["ports"] = ports
            result["method"] = "tcp-connect"

            context.metadata["ports"] = result

            recon = context.metadata.setdefault(
                "recon",
                {},
            )

            recon["port_count"] = len(ports)
            recon["ports"] = ports

            return

        except Exception as exc:
            result["status"] = "failed"
            result["reason"] = str(exc)

            context.metadata["ports"] = result
            return

    # =========================================================
    # NMAP MODE
    # =========================================================

    tool = NmapTool()

    if not tool.check_available():
        result["reason"] = (
            "Nmap is not available"
        )

        context.metadata["ports"] = result
        return

    timeout = int(
        context.config.get(
            "engine",
            {},
        ).get(
            "timeout",
            60,
        )
    )

    try:
        execution = tool.execute(
            context.target,
            timeout=timeout,
            fast=False,
        )

    except Exception as exc:
        result["status"] = "failed"
        result["reason"] = str(exc)

        context.metadata["ports"] = result
        return

    if not execution.success:
        result["status"] = "failed"
        result["reason"] = (
            execution.stderr.strip()
            or (
                "Nmap exited with code "
                f"{execution.return_code}"
            )
        )

        context.metadata["ports"] = result
        return

    ports = _parse_nmap_output(
        execution.stdout
    )

    result["status"] = "completed"
    result["count"] = len(ports)
    result["ports"] = ports
    result["method"] = "nmap"

    context.metadata["ports"] = result

    recon = context.metadata.setdefault(
        "recon",
        {},
    )

    recon["port_count"] = len(ports)
    recon["ports"] = ports