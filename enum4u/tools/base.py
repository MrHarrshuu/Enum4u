from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Sequence

from enum4u.utils.process import ProcessResult, ProcessRunner


@dataclass
class ToolResult:
    tool: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    timed_out: bool = False


class Tool(ABC):
    name: str

    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self.runner = runner or ProcessRunner()

    @abstractmethod
    def check_available(self) -> bool:
        pass

    @abstractmethod
    def build_command(self, target: str) -> list[str]:
        pass

    def execute(
        self,
        target: str,
        timeout: int | None = None,
    ) -> ToolResult:
        command = self.build_command(target)

        result = self.runner.run(
            command,
            timeout=timeout,
        )

        return self._to_tool_result(result)

    def execute_input(
        self,
        values: Sequence[str],
        timeout: int | None = None,
    ) -> ToolResult:
        command = self.build_command("")

        result = self.runner.run_input(
            command,
            "\n".join(values),
            timeout=timeout,
        )

        return self._to_tool_result(result)

    def _to_tool_result(
        self,
        result: ProcessResult,
    ) -> ToolResult:
        return ToolResult(
            tool=self.name,
            success=result.success,
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.return_code,
            timed_out=result.timed_out,
        )

    def __repr__(self) -> str:
        return f"Tool(name={self.name!r})"