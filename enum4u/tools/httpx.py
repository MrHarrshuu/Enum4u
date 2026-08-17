from __future__ import annotations

import shutil

from enum4u.tools.base import Tool


class HttpxTool(Tool):
    name = "httpx"

    def check_available(self) -> bool:
        executable = shutil.which(self.name)

        if not executable:
            return False

        result = self.runner.run(
            [executable, "-version"],
            timeout=5,
        )

        if not result.success:
            return False

        output = (
            result.stdout + "\n" + result.stderr
        ).lower()

        return (
            "projectdiscovery" in output
            or "httpx" in output
        )

    def build_command(self, target: str) -> list[str]:
        command = [
            self.name,
            "-silent",
        ]

        # Empty target means targets will be supplied through stdin.
        if not target:
            return command

        target = str(target).strip()

        if target.startswith(("http://", "https://")):
            url = target
        else:
            url = f"http://{target}"

        command.extend([
            "-u",
            url,
        ])

        return command

    def parse_output(self, stdout: str) -> list[str]:
        results: set[str] = set()

        for line in stdout.splitlines():
            value = line.strip()

            if not value:
                continue

            if value.startswith(("http://", "https://")):
                results.add(value)

        return sorted(results)