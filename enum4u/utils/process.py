from dataclasses import dataclass
import subprocess
from typing import Sequence


@dataclass
class ProcessResult:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.return_code == 0 and not self.timed_out


class ProcessRunner:
    def __init__(self, default_timeout: int = 30) -> None:
        self.default_timeout = default_timeout

    def run(
        self,
        command: Sequence[str],
        timeout: int | None = None,
    ) -> ProcessResult:
        return self._execute(
            command=command,
            timeout=timeout,
            stdin_data=None,
        )

    def run_input(
        self,
        command: Sequence[str],
        stdin_data: str,
        timeout: int | None = None,
    ) -> ProcessResult:
        return self._execute(
            command=command,
            timeout=timeout,
            stdin_data=stdin_data,
        )

    def _execute(
        self,
        command: Sequence[str],
        timeout: int | None,
        stdin_data: str | None,
    ) -> ProcessResult:
        command = [str(part) for part in command]
        timeout = timeout or self.default_timeout

        try:
            completed = subprocess.run(
                command,
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            return ProcessResult(
                command=command,
                return_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )

        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""

            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")

            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")

            return ProcessResult(
                command=command,
                return_code=-1,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )

        except FileNotFoundError as exc:
            return ProcessResult(
                command=command,
                return_code=127,
                stdout="",
                stderr=str(exc),
            )