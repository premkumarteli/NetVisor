"""
Tests for Worker Supervision (Task 3):
- WorkerState tracking
- WorkerSupervisor restart logic
- Status snapshots
"""

import asyncio
import pytest
from backend.services.worker_supervisor import WorkerSupervisor, WorkerState


@pytest.fixture
def supervisor():
    return WorkerSupervisor(max_restarts=5, base_delay=0.01, max_delay=0.1)


class TestWorkerState:
    def test_initial_state(self):
        state = WorkerState(name="test_worker")
        assert state.name == "test_worker"
        assert state.running is False
        assert state.restart_count == 0
        assert state.last_exception is None

    def test_record_heartbeat(self):
        state = WorkerState(name="test_worker")
        state.record_heartbeat()
        assert state.last_heartbeat > 0

    def test_record_exception(self):
        state = WorkerState(name="test_worker")
        exc = ValueError("test error")
        state.record_exception(exc)
        assert "ValueError" in state.last_exception
        assert "test error" in state.last_exception
        assert state.last_exception_time > 0

    def test_record_restart(self):
        state = WorkerState(name="test_worker")
        state.record_restart()
        assert state.restart_count == 1
        assert state.started_at > 0

    def test_snapshot(self):
        state = WorkerState(name="test_worker")
        snap = state.snapshot()
        assert snap["name"] == "test_worker"
        assert snap["running"] is False
        assert snap["restart_count"] == 0


class TestWorkerSupervisor:
    def test_register(self, supervisor):
        async def dummy():
            await asyncio.sleep(10)

        supervisor.register("dummy", dummy)
        assert "dummy" in supervisor._workers
        assert "dummy" in supervisor._coroutines

    def test_get_status_empty(self, supervisor):
        status = supervisor.get_status()
        assert status == []

    def test_get_status_after_register(self, supervisor):
        async def dummy():
            await asyncio.sleep(10)

        supervisor.register("dummy", dummy)
        status = supervisor.get_status()
        assert len(status) == 1
        assert status[0]["name"] == "dummy"

    def test_get_worker_state(self, supervisor):
        async def dummy():
            await asyncio.sleep(10)

        supervisor.register("dummy", dummy)
        state = supervisor.get_worker_state("dummy")
        assert state is not None
        assert state.name == "dummy"

    def test_get_worker_state_missing(self, supervisor):
        state = supervisor.get_worker_state("nonexistent")
        assert state is None

    def test_worker_restarts_on_exception(self, supervisor):
        call_count = [0]

        async def failing_worker():
            call_count[0] += 1
            if call_count[0] < 3:
                raise RuntimeError("boom")
            await asyncio.sleep(10)

        supervisor.register("failing", failing_worker)

        async def run_test():
            await supervisor.start_all()
            await asyncio.sleep(0.5)
            await supervisor.stop_all()

        asyncio.run(run_test())
        assert call_count[0] >= 2

    def test_stop_all(self, supervisor):
        async def dummy():
            while True:
                await asyncio.sleep(0.1)

        supervisor.register("dummy", dummy)

        async def run_test():
            await supervisor.start_all()
            await asyncio.sleep(0.05)
            await supervisor.stop_all()
            for state in supervisor._workers.values():
                assert state.task is None or state.task.done()

        asyncio.run(run_test())
