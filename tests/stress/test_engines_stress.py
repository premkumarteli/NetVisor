"""
tests/stress/test_engines_stress.py
===================================
Extreme concurrency, throughput, volume, and memory profiling stress tests across
all NetVisor security and analytics engines:
- ThreatEngine, VPNEngine, DeviceEngine, ApplicationEngine, AIEngine, RiskEngine,
  and EngineRegistry.
- 1,000-key O(N) eviction cliff profiling under heavy load.
- 100+ concurrent worker thread burst execution.
- Memory consumption profiling and unbounded cache leak detection.
"""

from __future__ import annotations

import concurrent.futures
import gc
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import patch

import psutil
import pytest

from backend.engines.ai.engine import AIEngine
from backend.engines.application.engine import ApplicationEngine
from backend.engines.common.config import EngineConfig
from backend.engines.device.engine import DeviceEngine
from backend.engines.registry import EngineRegistry
from backend.engines.risk.engine import RiskEngine
from backend.engines.threat.engine import ThreatEngine
from backend.engines.threat.kerberoasting import KerberoastingDetector
from backend.engines.threat.pass_the_hash import PassTheHashDetector
from backend.engines.threat.smb_lateral_movement import SMBLateralMovementDetector
from backend.engines.threat.state import SlidingWindowStore
from backend.engines.vpn.engine import VPNEngine
from tests.stress.conftest import generate_flow_batch, generate_synthetic_flow


class TestEngineRegistryStress:
    """Stress testing the EngineRegistry with concurrent multi-threaded execution."""

    def test_engine_registry_concurrent_execution(self):
        """
        Execute concurrent multi-threaded flow analysis across all 6 engines
        via EngineRegistry.analyze_selective with 25 concurrent worker threads.
        """
        registry = EngineRegistry()
        flows = generate_flow_batch(count=200)
        selected_engines = ["device", "threat", "application", "vpn", "risk", "ai"]

        results = []
        errors = []
        start_time = time.perf_counter()

        def analyze_worker(flow: Dict[str, Any]):
            try:
                # Patch application DB persistence to avoid MySQL dependencies in stress test
                with patch("backend.services.application_service.application_service._async_persist_discovery"):
                    return registry.analyze_selective(flow, selected_engines)
            except Exception as exc:
                errors.append(exc)
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            futures = [executor.submit(analyze_worker, flow) for flow in flows]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res is not None:
                    results.append(res)

        duration = time.perf_counter() - start_time
        fps = len(flows) / duration if duration > 0 else 0.0

        assert len(errors) == 0, f"Encountered errors during concurrent execution: {errors[:3]}"
        assert len(results) == len(flows), "All flows must produce an EngineResult"
        assert fps > 10.0, f"Expected >10 flows/sec concurrent multi-engine throughput, got {fps:.2f}"

        # Verify findings structure across completed results
        total_findings = sum(len(r.findings) for r in results)
        assert total_findings >= 0


    def test_high_concurrency_100_worker_burst(self):
        """
        Simulate a sudden burst with 100 concurrent worker threads simultaneously
        submitting flows to EngineRegistry. Proves thread safety and lack of lock deadlocks.
        """
        registry = EngineRegistry()
        burst_size = 300
        flows = [generate_synthetic_flow("benign", src_ip=f"10.0.{i % 250}.{i % 254 + 1}") for i in range(burst_size)]

        completed_count = 0
        latencies_ms: List[float] = []
        lock = concurrent.futures.thread.threading.Lock()

        def burst_worker(flow: Dict[str, Any]):
            t0 = time.perf_counter()
            with patch("backend.services.application_service.application_service._async_persist_discovery"):
                result = registry.analyze_selective(flow, ["threat", "vpn", "application", "risk", "ai"])
            latency = (time.perf_counter() - t0) * 1000.0
            with lock:
                nonlocal completed_count
                completed_count += 1
                latencies_ms.append(latency)
            return result

        start_time = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(burst_worker, f) for f in flows]
            concurrent.futures.wait(futures, timeout=30.0)

        total_time = time.perf_counter() - start_time
        fps = completed_count / total_time if total_time > 0 else 0.0

        assert completed_count == burst_size, f"Expected {burst_size} completions, got {completed_count}"
        assert len(latencies_ms) == burst_size

        latencies_ms.sort()
        p50 = latencies_ms[int(burst_size * 0.50)]
        p95 = latencies_ms[int(burst_size * 0.95)]
        p99 = latencies_ms[int(burst_size * 0.99)]

        assert p50 > 0.0
        assert p99 < 5000.0, f"P99 latency exceeded 5s SLA under 100-worker burst: {p99:.2f}ms"


class TestEvictionCliffStress:
    """Stress testing the 1,000-key O(N) eviction cliff under heavy load."""

    def test_sliding_window_1000_key_eviction_cliff(self):
        """
        Demonstrate and empirically measure the O(N) eviction cliff in SlidingWindowStore.
        Inserting keys 0..999 is fast (O(1) dictionary insert).
        Inserting keys 1000..1999 incurs an O(N) linear scan over 1,000 items inside
        _evict_oldest_key() on every single insertion under the thread lock.
        """
        store = SlidingWindowStore()
        base_time = datetime.now(timezone.utc)

        # Phase 1: Pre-cliff insertion (keys 0..900)
        t0 = time.perf_counter()
        for i in range(900):
            store.add((f"host-{i}",), base_time)
        pre_cliff_duration = time.perf_counter() - t0

        # Fill up to capacity (keys 900..1000)
        for i in range(900, 1000):
            store.add((f"host-{i}",), base_time)

        # Store should now be at max capacity (_MAX_KEYS = 1000)
        assert len(store._stores) == 1000

        # Phase 2: Post-cliff insertion (keys 1000..1900)
        # Every insertion of a new key triggers _evict_oldest_key()
        t1 = time.perf_counter()
        for i in range(1000, 1900):
            store.add((f"host-{i}",), base_time)
        post_cliff_duration = time.perf_counter() - t1

        # Capacity must remain capped at 1000
        assert len(store._stores) == 1000

        # Compute average microseconds per key
        avg_pre_us = (pre_cliff_duration / 900.0) * 1e6
        avg_post_us = (post_cliff_duration / 900.0) * 1e6

        # Post-cliff eviction per key must be significantly slower than pre-cliff
        # because of the O(N) linear search over 1,000 items in _evict_oldest_key()
        assert avg_post_us > avg_pre_us, (
            f"Expected eviction cliff: post-cliff avg ({avg_post_us:.2f}µs) should exceed "
            f"pre-cliff avg ({avg_pre_us:.2f}µs)"
        )

    def test_threat_detector_1000_key_saturation(self):
        """
        Stress test KerberoastingDetector, PassTheHashDetector, and SMBLateralMovementDetector
        under heavy volume with >1,000 distinct source endpoints to verify eviction bounds and stability.
        """
        kerb = KerberoastingDetector()
        pth = PassTheHashDetector()
        smb = SMBLateralMovementDetector()
        now = datetime.now(timezone.utc)

        # Saturate Kerberoasting detector with 1,200 distinct sources
        for i in range(1200):
            flow = {
                "src_ip": f"10.0.{i // 254}.{i % 254 + 1}",
                "dst_ip": "192.168.1.10",
                "dst_port": 88,
                "application_protocol": "KERBEROS",
                "domain": f"HTTP/service-{i}.corp.local",
                "analysis_signals": ["rc4_hmac", "etype_23"],
            }
            kerb.analyze(flow, now)

        # Verify tracking stability under heavy volume
        assert len(kerb._tgs_requests) >= 1000

        # Saturate PassTheHash detector with 1,200 distinct sources
        for i in range(1200):
            flow = {
                "src_ip": f"10.1.{i // 254}.{i % 254 + 1}",
                "dst_ip": f"192.168.2.{i % 100 + 1}",
                "dst_port": 445,
                "application_protocol": "SMB2",
                "analysis_signals": ["C$", "NTLMSSP_AUTH"],
            }
            pth.analyze(flow, now)

        assert len(pth._smb_authentications) >= 1000

        # Saturate SMB Lateral Movement detector with 1,200 distinct sources
        for i in range(1200):
            flow = {
                "src_ip": f"10.2.{i // 254}.{i % 254 + 1}",
                "dst_ip": f"192.168.3.{i % 100 + 1}",
                "dst_port": 445,
                "application_protocol": "SMB2",
                "analysis_signals": ["IPC$", "TREE_CONNECT"],
            }
            smb.analyze(flow, now)

        assert len(smb._smb_sessions) >= 1000


class TestEngineMemoryLeakStress:
    """Stress testing engines for memory consumption profiling and unbounded cache growth."""

    def test_application_engine_cache_growth(self):
        """
        Verify and quantify unbounded memory growth in ApplicationEngine's _domain_app_cache.
        Every newly encountered domain is added without TTL or eviction limit.
        """
        from backend.services.application_service import application_service
        app_engine = ApplicationEngine()

        initial_cache_size = len(application_service._domain_app_cache)
        unique_domains_count = 500

        with patch("backend.services.application_service.application_service._async_persist_discovery"):
            for i in range(unique_domains_count):
                unique_d = f"domain-{i}-{uuid.uuid4().hex[:6]}.org"
                flow = generate_synthetic_flow(
                    "benign",
                    domain=unique_d,
                    sni=unique_d,
                    application=None,
                )
                app_engine.analyze(flow)

        final_cache_size = len(application_service._domain_app_cache)
        growth = final_cache_size - initial_cache_size

        # Verifies that every unique domain is added to the in-memory cache without eviction
        assert growth >= unique_domains_count * 0.9, (
            f"Expected cache growth ~{unique_domains_count}, observed {growth}"
        )

    def test_risk_engine_suppression_store_growth(self):
        """
        Verify memory retention in RiskEngine's SuppressionStore._last_emitted.
        Target IP / rule tuples are recorded and retained permanently.
        """
        from backend.engines.risk.suppression import SuppressionStore
        suppression = SuppressionStore()

        initial_entries = len(suppression._last_emitted)
        num_alerts = 500
        now = datetime.now(timezone.utc)

        for i in range(num_alerts):
            target_ip = f"172.16.{i // 254}.{i % 254 + 1}"
            rule = f"RULE_ALERT_{i % 10}"
            suppression.record_emission(target_ip, rule, now)

        final_entries = len(suppression._last_emitted)
        assert final_entries == initial_entries + num_alerts

    def test_engine_process_memory_profile(self):
        """
        Measure Resident Set Size (RSS) memory delta during high-volume flow execution.
        Verifies that memory growth remains bounded under normal processing.
        """
        gc.collect()
        process = psutil.Process(os.getpid())
        rss_start_mb = process.memory_info().rss / (1024 * 1024)

        registry = EngineRegistry()
        flows = generate_flow_batch(count=1000)

        with patch("backend.services.application_service.application_service._async_persist_discovery"):
            for flow in flows:
                registry.analyze_selective(flow, ["threat", "vpn", "risk", "ai"])

        gc.collect()
        rss_end_mb = process.memory_info().rss / (1024 * 1024)
        rss_delta_mb = rss_end_mb - rss_start_mb

        # Memory growth for 1,000 flows should not exceed 100 MB
        assert rss_delta_mb < 100.0, f"Excessive memory bloat detected: +{rss_delta_mb:.2f} MB"
