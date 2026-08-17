from __future__ import annotations

import time

from enum4u.core.task import Task


class Pipeline:
    def __init__(self) -> None:
        self.tasks: list[Task] = []

    def add_task(self, task: Task) -> None:
        self.tasks.append(task)

    def run(self, context: object) -> None:
        completed: set[str] = set()
        failed: dict[str, str] = {}
        timings: dict[str, float] = {}

        pipeline_start = time.perf_counter()

        while len(completed) < len(self.tasks):
            progress = False

            for task in self.tasks:
                if task.name in completed:
                    continue

                if not all(
                    dependency in completed
                    for dependency in task.depends_on
                ):
                    continue

                start = time.perf_counter()

                try:
                    task.run(context)
                except Exception as exc:
                    elapsed = time.perf_counter() - start

                    timings[task.name] = round(
                        elapsed,
                        3,
                    )

                    failed[task.name] = str(exc)

                    context.metadata.setdefault(
                        "pipeline",
                        {},
                    )

                    context.metadata["pipeline"][
                        "failed"
                    ] = failed

                    raise

                elapsed = time.perf_counter() - start

                timings[task.name] = round(
                    elapsed,
                    3,
                )

                completed.add(task.name)
                progress = True

            if not progress:
                unresolved = [
                    task.name
                    for task in self.tasks
                    if task.name not in completed
                ]

                raise RuntimeError(
                    "Unable to resolve task dependencies: "
                    f"{unresolved}"
                )

        total_time = time.perf_counter() - pipeline_start

        slowest_task = None
        slowest_time = 0.0

        fastest_task = None
        fastest_time = None

        for name, elapsed in timings.items():
            if elapsed > slowest_time:
                slowest_task = name
                slowest_time = elapsed

            if fastest_time is None or elapsed < fastest_time:
                fastest_task = name
                fastest_time = elapsed

        context.metadata["pipeline"] = {
            "status": "completed",
            "completed": sorted(completed),
            "failed": failed,
            "timings": timings,
            "total_time": round(
                total_time,
                3,
            ),
            "task_count": len(self.tasks),
            "slowest_task": slowest_task,
            "slowest_time": round(
                slowest_time,
                3,
            ),
            "fastest_task": fastest_task,
            "fastest_time": round(
                fastest_time or 0.0,
                3,
            ),
        }