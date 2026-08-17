import shutil

from enum4u.tools.base import Tool


class SubfinderTool(Tool):
    name = "subfinder"

    def check_available(self) -> bool:
        return shutil.which(self.name) is not None

    def build_command(self, target: str) -> list[str]:
        return [
            self.name,
            "-d",
            target,
            "-silent",
        ]

    def parse_output(self, stdout: str) -> list[str]:
        results = set()

        for line in stdout.splitlines():
            value = line.strip().lower()

            if value and "." in value:
                results.add(value)

        return sorted(results)