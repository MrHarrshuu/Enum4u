from __future__ import annotations

from enum4u.core.context import ScanContext
from enum4u.core.pipeline import Pipeline
from enum4u.core.task import Task


class Engine:
    def __init__(
        self,
        target: str,
        mode: str,
        config: dict,
        selected_modules: set[str] | None = None,
    ) -> None:
        self.target = target
        self.mode = mode
        self.config = config

        self.selected_modules = (
            set(selected_modules)
            if selected_modules
            else set()
        )

        self.context = ScanContext(
            target=target,
            mode=mode,
            config=config,
        )

        self.pipeline = Pipeline()

    @property
    def tasks(self) -> list[Task]:
        return self.pipeline.tasks

    def register_task(
        self,
        task: Task,
    ) -> None:
        self.pipeline.add_task(task)

    def run(self) -> ScanContext:
        self.context.add_asset(
            self.target
        )

        self.context.metadata["engine"] = {
            "timeout": self.config.get(
                "engine",
                {},
            ).get(
                "timeout",
                60,
            ),
            "concurrency": self.config.get(
                "engine",
                {},
            ).get(
                "concurrency",
                4,
            ),
        }

        self.context.metadata["modules"] = (
            self.config.get(
                "modules",
                {},
            )
        )

        self.context.metadata[
            "selected_modules"
        ] = sorted(
            self.selected_modules
        )

        self.pipeline.run(
            self.context
        )

        return self.context