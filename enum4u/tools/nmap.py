from __future__ import annotations

import re
import shutil

from enum4u.tools.base import Tool


class NmapTool(Tool):
    name = "nmap"

    def check_available(self) -> bool:
        return shutil.which(self.name) is not None

    def _extract_target(
        self,
        target: str,
    ) -> tuple[str, str | None]:
        target = str(target).strip()

        target = re.sub(
            r"^https?://",
            "",
            target,
            flags=re.IGNORECASE,
        )

        if target.startswith("["):
            closing = target.find("]")

            if closing != -1:
                host = target[1:closing]
                remainder = target[closing + 1:]

                if remainder.startswith(":"):
                    port = remainder[1:]

                    if port.isdigit():
                        return host, port

                return host, None

        if target.count(":") == 1:
            host, port = target.rsplit(":", 1)

            if port.isdigit():
                return host, port

        return target, None

    def build_command(
        self,
        target: str,
        fast: bool = False,
    ) -> list[str]:
        host, port = self._extract_target(target)

        command = [
            self.name,
            "-Pn",
        ]

        if fast:
            # FAST:
            # only determine whether the target port is reachable.
            command.extend([
                "-T4",
                "-sT",
            ])
        else:
            # DEEP:
            # perform service/version detection.
            command.extend([
                "-sV",
            ])

        if port:
            command.extend([
                "-p",
                port,
            ])

        command.extend([
            "--",
            host,
        ])

        return command

    def execute(
        self,
        target: str,
        timeout: int = 60,
        fast: bool = False,
    ):
        command = self.build_command(
            target,
            fast=fast,
        )

        return self.runner.run(
            command,
            timeout=timeout,
        )