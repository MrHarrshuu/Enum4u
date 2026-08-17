from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Task:
    name: str
    action: Callable[..., Any]
    depends_on: list[str] = field(default_factory=list)

    def run(self, context: Any) -> Any:
        return self.action(context)