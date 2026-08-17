import shutil

from enum4u.tools.base import Tool


class DnsxTool(Tool):
    name = "dnsx"

    def check_available(self) -> bool:
        return shutil.which(self.name) is not None

    def build_command(self, target: str) -> list[str]:
        return [
            self.name,
            "-silent",
        ]

    def parse_output(self, stdout: str) -> list[str]:
        results = set()

        for line in stdout.splitlines():
            value = line.strip()

            if value:
                results.add(value)

        return sorted(results)