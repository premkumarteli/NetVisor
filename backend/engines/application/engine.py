import time
import threading
from engine import BaseEngine, EngineResult

class ApplicationEngine(BaseEngine):
    def __init__(self) -> None:
        self._executions = 0
        self._findings_generated = 0
        self._total_time_ms = 0.0
        self._lock = threading.RLock()

    @property
    def name(self) -> str:
        return "application"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_contexts(self) -> list[str]:
        return ["application", "flow"]

    def analyze(self, context: dict) -> EngineResult:
        start_time = time.perf_counter()
        with self._lock:
            self._executions += 1
        
        from backend.services.application_service import application_compatibility_wrapper
        res = application_compatibility_wrapper(context)
        
        duration = (time.perf_counter() - start_time) * 1000.0
        with self._lock:
            self._total_time_ms += duration
            self._findings_generated += len(res.findings)

        return res

    def metrics(self) -> dict:
        with self._lock:
            avg_time = (self._total_time_ms / self._executions) if self._executions > 0 else 0.0
            return {
                "executions": self._executions,
                "findings_generated": self._findings_generated,
                "avg_execution_ms": round(avg_time, 2)
            }
