"""
Worker supervision module for NetVisor.

Provides automatic restart with exponential backoff for critical async workers.
Tracks health, restart counts, and last exceptions for operational visibility.
"""

import asyncio
import logging
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger("netvisor.worker_supervisor")

try:
    from backend.middleware.prometheus_middleware import WORKER_RESTART_COUNT
except Exception:
    WORKER_RESTART_COUNT = None


@dataclass
class WorkerState:
    """Tracks the state of a supervised worker."""
    name: str
    running: bool = False
    restart_count: int = 0
    last_heartbeat: float = 0.0
    last_exception: Optional[str] = None
    last_exception_time: float = 0.0
    started_at: float = 0.0
    task: Optional[asyncio.Task] = field(default=None, repr=False)

    def record_heartbeat(self) -> None:
        self.last_heartbeat = time.time()

    def record_exception(self, exc: Exception) -> None:
        self.last_exception = f"{type(exc).__name__}: {exc}"
        self.last_exception_time = time.time()

    def record_restart(self) -> None:
        self.restart_count += 1
        self.started_at = time.time()

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "running": self.running,
            "restart_count": self.restart_count,
            "last_heartbeat": self.last_heartbeat,
            "last_exception": self.last_exception,
            "last_exception_time": self.last_exception_time,
            "uptime_seconds": time.time() - self.started_at if self.started_at else 0,
        }


class WorkerSupervisor:
    """
    Supervises async workers with automatic restart and exponential backoff.

    Usage:
        supervisor = WorkerSupervisor()

        async def my_worker():
            while True:
                # ... do work ...
                await asyncio.sleep(1)

        supervisor.register("my_worker", my_worker)
        await supervisor.start_all()
        # ... later ...
        await supervisor.stop_all()
    """

    def __init__(
        self,
        max_restarts: int = 10,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        heartbeat_interval: float = 10.0,
    ) -> None:
        self._workers: dict[str, WorkerState] = {}
        self._coroutines: dict[str, Callable[[], Coroutine]] = {}
        self._max_restarts = max_restarts
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    def register(self, name: str, coroutine_factory: Callable[[], Coroutine]) -> None:
        """Register a worker coroutine factory."""
        self._workers[name] = WorkerState(name=name)
        self._coroutines[name] = coroutine_factory
        logger.info("Registered worker: %s", name)

    def _increment_restart_metric(self) -> None:
        """Increment the Prometheus restart counter."""
        try:
            if WORKER_RESTART_COUNT is not None:
                WORKER_RESTART_COUNT.inc()
        except Exception:
            pass

    async def _run_with_supervision(self, name: str) -> None:
        """Run a worker with automatic restart and exponential backoff."""
        state = self._workers[name]
        coroutine_factory = self._coroutines[name]

        while not self._stop_event.is_set():
            state.running = True
            state.record_restart()
            self._increment_restart_metric()
            logger.info(
                "Starting worker '%s' (restart #%d)",
                name,
                state.restart_count,
            )

            try:
                coro = coroutine_factory()
                await coro
                # If stop event was signaled, exit cleanly without restarting
                if self._stop_event.is_set():
                    state.running = False
                    return
                logger.warning(
                    "Worker '%s' exited normally (unexpected). Restarting.",
                    name,
                )
            except asyncio.CancelledError:
                logger.info("Worker '%s' cancelled (shutdown).", name)
                state.running = False
                return
            except Exception as exc:
                if self._stop_event.is_set():
                    state.running = False
                    return
                state.record_exception(exc)
                logger.error(
                    "Worker '%s' crashed: %s\n%s",
                    name,
                    exc,
                    traceback.format_exc(),
                )
            finally:
                state.running = False

            if self._stop_event.is_set():
                return

            # Exponential backoff with jitter
            delay = min(
                self._max_delay,
                self._base_delay * (2 ** min(state.restart_count - 1, 10)),
            )
            logger.info(
                "Worker '%s' will restart in %.1f seconds (restart #%d)",
                name,
                delay,
                state.restart_count,
            )
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                return

            if self._stop_event.is_set():
                return

    async def start_all(self) -> None:
        """Start all registered workers."""
        for name in self._coroutines:
            task = asyncio.create_task(self._run_with_supervision(name))
            self._workers[name].task = task
            self._workers[name].started_at = time.time()
        # Start heartbeat reporter
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("All %d workers started.", len(self._workers))

    async def stop_all(self) -> None:
        """Stop all workers gracefully."""
        self._stop_event.set()
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Concurrently cancel and await all running worker tasks
        tasks_to_cancel = [
            (name, state)
            for name, state in self._workers.items()
            if state.task and not state.task.done()
        ]
        for name, state in tasks_to_cancel:
            state.task.cancel()

        for name, state in tasks_to_cancel:
            try:
                await asyncio.wait_for(asyncio.shield(state.task), timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            state.running = False
            logger.info("Worker '%s' stopped.", name)

    async def _heartbeat_loop(self) -> None:
        """Periodically update heartbeat timestamps for all workers."""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self._heartbeat_interval)
            except asyncio.CancelledError:
                return
            for state in self._workers.values():
                if state.running:
                    state.record_heartbeat()

    def get_status(self) -> list[dict[str, Any]]:
        """Return status snapshots for all workers."""
        return [state.snapshot() for state in self._workers.values()]

    def get_worker_state(self, name: str) -> Optional[WorkerState]:
        """Get the state of a specific worker."""
        return self._workers.get(name)


# Global supervisor instance for the backend
worker_supervisor = WorkerSupervisor()
