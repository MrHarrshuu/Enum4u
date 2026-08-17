from __future__ import annotations

import shutil

from enum4u.tools.base import Tool


class NucleiTool(Tool):
    name = "nuclei"

    def check_available(self) -> bool:
        executable = shutil.which(
            self.name
        )

        if not executable:
            return False

        result = self.runner.run(
            [
                executable,
                "-version",
            ],
            timeout=5,
        )

        return result.success

    def build_command(
        self,
        target: str,
        mode: str = "fast",
    ) -> list[str]:

        if not target:
            raise ValueError(
                "Nuclei target cannot be empty"
            )

        mode = str(
            mode or "fast"
        ).lower()

        command = [
            self.name,
            "-u",
            target,
            "-jsonl",
            "-silent",
        ]

        if mode == "fast":
            command.extend(
                [
                    "-severity",
                    "critical,high,medium",
                ]
            )

        elif mode == "deep":
            command.extend(
                [
                    "-severity",
                    "critical,high,medium,low,info",
                ]
            )

        elif mode == "passive":
            raise ValueError(
                "Nuclei assessment is disabled "
                "in passive mode"
            )

        else:
            command.extend(
                [
                    "-severity",
                    "critical,high,medium",
                ]
            )

        return command

    def execute(
        self,
        target: str,
        timeout: int | None = None,
        mode: str = "fast",
    ):
        command = self.build_command(
            target,
            mode=mode,
        )

        result = self.runner.run(
            command,
            timeout=timeout,
        )

        return self._to_tool_result(
            result
        )

    def parse_output(
        self,
        stdout: str,
    ) -> list[dict]:

        import json

        findings = []

        for line in stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                item = json.loads(
                    line
                )

            except json.JSONDecodeError:
                continue

            info = item.get(
                "info",
                {},
            )

            if not isinstance(
                info,
                dict,
            ):
                info = {}

            finding = {
                "template_id": item.get(
                    "template-id"
                ),
                "name": info.get(
                    "name"
                ),
                "severity": info.get(
                    "severity"
                ),
                "matched_at": item.get(
                    "matched-at"
                ),
                "type": item.get(
                    "type"
                ),
                "host": item.get(
                    "host"
                ),
            }

            findings.append(
                finding
            )

        return findings