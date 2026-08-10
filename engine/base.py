from abc import ABC, abstractmethod
from .result import EngineResult

class BaseEngine(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of the engine."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Return the current version of the engine."""
        pass

    @abstractmethod
    def analyze(self, context: dict) -> EngineResult:
        """Execute analysis logic against the input context."""
        pass

    @property
    def supported_contexts(self) -> list[str]:
        """Return the list of context keys/tags supported by this engine."""
        return []

    def metrics(self) -> dict:
        """Return runtime execution metrics for the engine."""
        return {
            "executions": 0,
            "findings_generated": 0,
            "avg_execution_ms": 0.0
        }

