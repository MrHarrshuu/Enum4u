from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from enum4u.core.context import ScanContext


def _parse_target(
    target: str,
) -> tuple[str, int]:

    value = str(
        target
    ).strip()

    parsed = urlparse(
        value
        if "://" in value
        else f"//{value}",
    )

    hostname = (
        parsed.hostname
        or value.split(
            ":",
            1,
        )[0]
    )

    port = (
        parsed.port
        or (
            443
            if parsed.scheme == "https"
            else 443
        )
    )

    return hostname, port


def run_tls_enumeration(
    context: ScanContext,
) -> None:

    target = str(
        context.target
    ).strip()

    hostname, port = _parse_target(
        target
    )

    result = {
        "status": "skipped",
        "reason": None,
        "target": target,
        "hostname": hostname,
        "port": port,
        "tls": None,
    }

    if not hostname:
        result["reason"] = (
            "hostname could not be determined"
        )

        context.metadata[
            "tls"
        ] = result

        return

    try:
        timeout = float(
            context.config.get(
                "engine",
                {},
            ).get(
                "timeout",
                10,
            )
        )

        tls_context = (
            ssl.create_default_context()
        )

        with socket.create_connection(
            (
                hostname,
                port,
            ),
            timeout=timeout,
        ) as raw_socket:

            with tls_context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket:

                cipher = (
                    tls_socket.cipher()
                )

                peer_certificate = (
                    tls_socket.getpeercert()
                )

                result["tls"] = {
                    "version": tls_socket.version(),
                    "cipher": (
                        cipher[0]
                        if cipher
                        else None
                    ),
                    "cipher_protocol": (
                        cipher[1]
                        if cipher
                        else None
                    ),
                    "cipher_bits": (
                        cipher[2]
                        if cipher
                        else None
                    ),
                    "certificate_present": bool(
                        peer_certificate
                    ),
                    "certificate_subject": (
                        peer_certificate.get(
                            "subject"
                        )
                        if peer_certificate
                        else None
                    ),
                    "certificate_issuer": (
                        peer_certificate.get(
                            "issuer"
                        )
                        if peer_certificate
                        else None
                    ),
                    "certificate_expiry": (
                        peer_certificate.get(
                            "notAfter"
                        )
                        if peer_certificate
                        else None
                    ),
                }

                result[
                    "status"
                ] = "completed"

    except ssl.SSLError as exc:
        result["status"] = "failed"
        result["reason"] = (
            f"TLS error: {exc}"
        )

    except (
        OSError,
        TimeoutError,
    ) as exc:
        result["status"] = "failed"
        result["reason"] = (
            f"connection error: {exc}"
        )

    except Exception as exc:
        result["status"] = "failed"
        result["reason"] = str(
            exc
        )

    context.metadata[
        "tls"
    ] = result