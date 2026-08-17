from __future__ import annotations

import shutil

from enum4u.tools.base import Tool


class KatanaTool(Tool):
    name = "katana"

    def check_available(self) -> bool:
        return shutil.which(self.name) is not None

    def build_command(self, target: str) -> list[str]:
        target = str(target).strip()

        if not target:
            raise ValueError("Katana target cannot be empty")

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        return [
            self.name,
            "-silent",
            "-d",
            "2",
            "-u",
            target,
        ]

    def parse_output(self, stdout: str) -> list[str]:
        results = set()

        for line in stdout.splitlines():
            value = line.strip()

            if not value:
                continue

            if value.startswith(("http://", "https://")):
                results.add(value)

        return sorted(results)