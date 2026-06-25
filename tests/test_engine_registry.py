import pytest
from app.engines.registry import EngineRegistry
from app.engines.common.config import EngineConfig
from app.engines.device.engine import DeviceEngine
from shared.engine import BaseEngine, EngineResult, Finding, Severity

class MockEngine(BaseEngine):
    def __init__(self, name: str, version: str = "1.0.0") -> None:
        self._name = name
        self._version = version
        self._executions = 0
        self._findings_generated = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    @property
    def supported_contexts(self) -> list[str]:
        return ["mock"]

    def analyze(self, context: dict) -> EngineResult:
        self._executions += 1
        finding = Finding(
            engine=self._name,
            finding_type="mock_finding",
            severity=Severity.INFO,
            confidence=1.0,
            evidence=[f"Mock finding from {self._name}"]
        )
        self._findings_generated += 1
        return EngineResult(findings=[finding], metadata={"mock_meta": "yes"})

    def metrics(self) -> dict:
        return {
            "executions": self._executions,
            "findings_generated": self._findings_generated,
            "avg_execution_ms": 0.0
        }

def test_default_engine_registration():
    registry = EngineRegistry()
    engines = registry.list_engines()

    assert "device" in engines
    assert "threat" in engines
    assert "application" in engines
    assert "vpn" in engines

    # Retrieve engine
    device_engine = registry.get("device")
    assert isinstance(device_engine, DeviceEngine)

def test_duplicate_registration_protection():
    registry = EngineRegistry()

    # Try to register a duplicate DeviceEngine
    with pytest.raises(ValueError, match="already registered"):
        registry.register(DeviceEngine())

def test_unknown_engine_selective_execution():
    registry = EngineRegistry()

    with pytest.raises(ValueError, match="Unknown engine: 'does_not_exist'"):
        registry.analyze_selective({}, ["device", "does_not_exist"])

def test_empty_registry_execution():
    registry = EngineRegistry()
    registry.clear()
    assert len(registry.list_engines()) == 0

    result = registry.analyze_selective({})
    assert isinstance(result, EngineResult)
    assert len(result.findings) == 0
    assert result.metadata["executed_engines"] == []
    assert result.metadata["engine_results"] == {}

def test_selective_execution_and_meta_preservation():
    registry = EngineRegistry()
    registry.clear()

    # Register mock engines
    engine1 = MockEngine("mock1")
    engine2 = MockEngine("mock2")
    registry.register(engine1)
    registry.register(engine2)

    context = {"test": "context"}
    # Run only mock1
    result = registry.analyze_selective(context, ["mock1"])
    assert len(result.findings) == 1
    assert result.findings[0].engine == "mock1"

    # Verify metadata contains individual engine results and executed engines
    metadata = result.metadata
    assert metadata["executed_engines"] == ["mock1"]
    assert "mock1" in metadata["engine_results"]
    assert "mock2" not in metadata["engine_results"]

    mock1_result = metadata["engine_results"]["mock1"]
    assert len(mock1_result["findings"]) == 1
    assert mock1_result["findings"][0]["finding_type"] == "mock_finding"
    assert mock1_result["metadata"]["mock_meta"] == "yes"

def test_shared_config_injection():
    config = EngineConfig()
    config.port_scan_threshold = 999

    registry = EngineRegistry(config)
    assert registry.config == config

    # Threat engine should share the same config object
    threat_engine = registry.get("threat")
    assert threat_engine.config == config
    assert threat_engine.config.port_scan_threshold == 999

def test_registry_metrics_aggregation():
    registry = EngineRegistry()
    registry.clear()

    mock = MockEngine("mock_metrics")
    registry.register(mock)

    # Execute
    registry.analyze_selective({})

    metrics = registry.metrics()
    assert "mock_metrics" in metrics
    assert metrics["mock_metrics"]["executions"] == 1
    assert metrics["mock_metrics"]["findings_generated"] == 1
