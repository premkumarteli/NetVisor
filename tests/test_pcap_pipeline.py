import os
import pytest
import dataclasses
import time
from datetime import datetime, timezone
from scapy.all import rdpcap
from pydantic import ValidationError

from collector.flow_manager import FlowManager
from collector.observations import PacketObservation
from app.schemas.flow_schema import FlowBase
from app.engines.registry import EngineRegistry

def run_pcap_through_flow_manager(pcap_path: str) -> list:
    flows = []
    
    def on_flow_expired(summary):
        flows.append(summary)
        
    flow_manager = FlowManager(
        agent_id="AGENT-TEST-PCAP",
        organization_id="org-pcap-test",
        on_flow_expired=on_flow_expired,
        start_worker=False
    )
    
    packets = rdpcap(pcap_path)
    for pkt in packets:
        pkt_time = float(getattr(pkt, "time", time.time()))
        obs = PacketObservation.from_packet(
            pkt,
            source_type="agent",
            observed_at=pkt_time
        )
        if obs:
            flow_manager.update_from_observation(obs)
            
    # Force flush all flows at the end of PCAP
    with flow_manager._lock:
        for key, state in flow_manager._flows.items():
            if state.packet_count > 0:
                summary = flow_manager._build_summary(key, state)
                flows.append(summary)
        flow_manager._flows.clear()
        
    return flows


def test_standard_pipeline():
    """
    Ensure the standard PCAP parses into valid FlowBase flows,
    and runs through the engine registry without generating threats.
    """
    flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/standard.pcap")
    assert len(flows) > 0
    
    registry = EngineRegistry()
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()
            
    for summary in flows:
        summary_dict = dataclasses.asdict(summary)
        
        # 1. Validate against flow schema validation layer
        flow_obj = FlowBase(**summary_dict)
        assert flow_obj.src_ip in ("192.168.1.50", "192.168.1.100", "192.168.1.1")
        
        # 2. Execute the engine registry
        context = summary_dict.copy()
        context["bytes_out"] = summary_dict["byte_count"]
        
        result = registry.analyze_selective(context, ["threat", "risk", "ai"])
        
        # Check no malicious threat findings are generated
        threat_findings = [f for f in result.findings if f.engine == "threat"]
        assert len(threat_findings) == 0


def test_scan_pipeline():
    """
    Ensure the scan PCAP triggers the port_scan threat detector.
    """
    flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/scan.pcap")
    assert len(flows) >= 10
    
    registry = EngineRegistry()
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()
            
    findings = []
    for summary in flows:
        summary_dict = dataclasses.asdict(summary)
        FlowBase(**summary_dict) # validation
        
        context = summary_dict.copy()
        context["bytes_out"] = summary_dict["byte_count"]
        
        res = registry.analyze_selective(context, ["threat"])
        findings.extend(res.findings)
        
    port_scans = [f for f in findings if f.finding_type == "port_scan"]
    assert len(port_scans) > 0
    assert port_scans[0].target_ip == "192.168.1.50"


def test_tunnel_pipeline():
    """
    Ensure the tunnel PCAP triggers the dns_tunneling threat detector.
    """
    flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/tunnel.pcap")
    
    registry = EngineRegistry()
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()
            
    findings = []
    for summary in flows:
        summary_dict = dataclasses.asdict(summary)
        FlowBase(**summary_dict)
        
        context = summary_dict.copy()
        context["bytes_out"] = summary_dict["byte_count"]
        
        res = registry.analyze_selective(context, ["threat"])
        findings.extend(res.findings)
        
    tunnels = [f for f in findings if f.finding_type == "dns_tunneling"]
    assert len(tunnels) > 0
    assert tunnels[0].target_ip == "192.168.1.50"


def test_beacon_pipeline():
    """
    Ensure the beacon PCAP triggers the beaconing threat detector.
    """
    flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/beacon.pcap")
    
    registry = EngineRegistry()
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()
            
    findings = []
    for summary in flows:
        summary_dict = dataclasses.asdict(summary)
        FlowBase(**summary_dict)
        
        context = summary_dict.copy()
        context["bytes_out"] = summary_dict["byte_count"]
        
        res = registry.analyze_selective(context, ["threat"])
        findings.extend(res.findings)
        
    beacons = [f for f in findings if f.finding_type == "beaconing"]
    assert len(beacons) > 0
    assert beacons[0].target_ip == "192.168.1.50"


def test_tor_pipeline():
    """
    Ensure the Tor PCAP triggers the vpn_detected threat alert
    (by Tor Exit node IP) and supports test-time JA4 enrichment.
    """
    flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/tor.pcap")
    assert len(flows) > 0
    
    registry = EngineRegistry()
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()
            
    findings = []
    for summary in flows:
        summary_dict = dataclasses.asdict(summary)
        FlowBase(**summary_dict)
        
        context = summary_dict.copy()
        # Test-time JA4 enrichment injection (Tor Browser)
        context["ja4"] = "t13d1516h2_9a12_108a"
        context["bytes_out"] = summary_dict["byte_count"]
        
        # Run threat, vpn, application, risk
        res = registry.analyze_selective(context, ["threat", "vpn", "application", "risk"])
        findings.extend(res.findings)
        
    vpn_alerts = [f for f in findings if f.finding_type == "vpn_detected"]
    app_alerts = [f for f in findings if f.finding_type == "suspicious_application_detected"]
    
    assert len(vpn_alerts) > 0
    assert "Tor exit node" in vpn_alerts[0].evidence[0]
    assert len(app_alerts) > 0
    assert app_alerts[0].details.get("application_name") == "Tor Browser"


def test_mixed_attack_pipeline():
    """
    Ensure the mixed attack PCAP (Port Scan + DNS Tunnel + Large Upload)
    exercises Threat Engine -> Risk Correlation -> AI Engine sequentially,
    generating correct alerts and an AI security summary finding.
    """
    flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/mixed.pcap")
    
    registry = EngineRegistry()
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()
            
    findings = []
    
    # We feed the flows sequentially to simulate real packet ingestion
    for summary in flows:
        summary_dict = dataclasses.asdict(summary)
        FlowBase(**summary_dict)
        
        context = summary_dict.copy()
        context["bytes_out"] = summary_dict["byte_count"]
        
        # Run Threat, Risk, AI engines
        res = registry.analyze_selective(context, ["threat", "risk", "ai"])
        findings.extend(res.findings)
        
    # 1. Assert threat engine detections
    port_scans = [f for f in findings if f.finding_type == "port_scan"]
    tunnels = [f for f in findings if f.finding_type == "dns_tunneling"]
    large_uploads = [f for f in findings if f.finding_type == "large_upload"]
    
    assert len(port_scans) > 0
    assert len(tunnels) > 0
    assert len(large_uploads) > 0
    
    # 2. Assert risk engine summary
    risk_summaries = [f for f in findings if f.finding_type == "risk_summary"]
    assert len(risk_summaries) > 0
    
    # Overall risk score should be elevated (max of threat engines + 10% other contributing scores)
    max_risk = max(f.details.get("risk_score", 0) for f in risk_summaries)
    assert max_risk >= 80  # Critical severity
    
    # 3. Assert AI Engine summary
    ai_findings = [f for f in findings if f.finding_type == "ai_analysis"]
    assert len(ai_findings) > 0
    
    ai_finding = ai_findings[-1]
    assert ai_finding.details["risk_score"] >= 80
    assert ai_finding.details["severity"] in ("HIGH", "CRITICAL")
    assert len(ai_finding.details["recommendations"]) > 0


def test_wireguard_pipeline():
    """
    Ensure the WireGuard PCAP triggers the vpn_detected finding using modular heuristics.
    """
    from unittest.mock import patch
    with patch("app.engines.vpn.asn_detector.asn_lookup_service.lookup_asn_details") as mock_lookup:
        mock_lookup.return_value = {"asn": 9009, "organization": "M247 Ltd"}

        flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/wireguard.pcap")
        assert len(flows) > 0

        registry = EngineRegistry()
        for name in registry.list_engines():
            engine = registry.get(name)
            if hasattr(engine, "clear_state"):
                engine.clear_state()

        findings = []
        for summary in flows:
            summary_dict = dataclasses.asdict(summary)
            FlowBase(**summary_dict)

            context = summary_dict.copy()
            context["bytes_out"] = summary_dict["byte_count"]

            # Run VPN engine
            res = registry.analyze_selective(context, ["vpn"])
            findings.extend(res.findings)

        vpn_alerts = [f for f in findings if f.finding_type == "vpn_detected"]
        assert len(vpn_alerts) > 0
        assert vpn_alerts[0].details.get("provider") == "M247"
        assert vpn_alerts[0].details.get("vpn_type") == "WireGuard"
        assert any("WireGuard" in ev for ev in vpn_alerts[0].evidence)


def test_openvpn_pipeline():
    """
    Ensure the OpenVPN PCAP triggers the vpn_detected finding using opcode signatures.
    """
    flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/openvpn.pcap")
    assert len(flows) > 0

    registry = EngineRegistry()
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()

    findings = []
    for summary in flows:
        summary_dict = dataclasses.asdict(summary)
        FlowBase(**summary_dict)

        context = summary_dict.copy()
        context["bytes_out"] = summary_dict["byte_count"]

        # Run VPN engine
        res = registry.analyze_selective(context, ["vpn"])
        findings.extend(res.findings)

    vpn_alerts = [f for f in findings if f.finding_type == "vpn_detected"]
    assert len(vpn_alerts) > 0
    assert vpn_alerts[0].details.get("vpn_type") == "OpenVPN"
    assert any("OpenVPN" in ev for ev in vpn_alerts[0].evidence)


def test_normal_udp_stream_pipeline():
    """
    Ensure the normal UDP stream PCAP does NOT trigger any vpn_detected findings.
    """
    flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/normal_udp_stream.pcap")
    assert len(flows) > 0

    registry = EngineRegistry()
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()

    findings = []
    for summary in flows:
        summary_dict = dataclasses.asdict(summary)
        FlowBase(**summary_dict)

        context = summary_dict.copy()
        context["bytes_out"] = summary_dict["byte_count"]

        # Run VPN engine
        res = registry.analyze_selective(context, ["vpn"])
        findings.extend(res.findings)

    vpn_alerts = [f for f in findings if f.finding_type == "vpn_detected"]
    assert len(vpn_alerts) == 0


def test_wireguard_without_asn_reputation():
    """
    Ensure that a WireGuard-only signature (0.35) without ASN reputation
    is below the threshold (0.50) and does NOT trigger a vpn_detected finding.
    """
    from unittest.mock import patch
    with patch("app.engines.vpn.asn_detector.asn_lookup_service.lookup_asn_details") as mock_lookup:
        mock_lookup.return_value = None

        flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/wireguard.pcap")
        assert len(flows) > 0

        registry = EngineRegistry()
        for name in registry.list_engines():
            engine = registry.get(name)
            if hasattr(engine, "clear_state"):
                engine.clear_state()

        findings = []
        for summary in flows:
            summary_dict = dataclasses.asdict(summary)
            FlowBase(**summary_dict)

            context = summary_dict.copy()
            context["bytes_out"] = summary_dict["byte_count"]

            # Run VPN engine
            res = registry.analyze_selective(context, ["vpn"])
            findings.extend(res.findings)

        vpn_alerts = [f for f in findings if f.finding_type == "vpn_detected"]
        assert len(vpn_alerts) == 0


def test_wireguard_plus_tls():
    """
    Ensure that WireGuard (0.35) + TLS SNI (0.20) = 0.55 meets the threshold (0.50)
    and triggers a vpn_detected finding.
    """
    from unittest.mock import patch
    with patch("app.engines.vpn.asn_detector.asn_lookup_service.lookup_asn_details") as mock_lookup:
        mock_lookup.return_value = None

        flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/wireguard.pcap")
        assert len(flows) > 0

        registry = EngineRegistry()
        for name in registry.list_engines():
            engine = registry.get(name)
            if hasattr(engine, "clear_state"):
                engine.clear_state()

        findings = []
        for summary in flows:
            summary_dict = dataclasses.asdict(summary)
            FlowBase(**summary_dict)

            context = summary_dict.copy()
            context["bytes_out"] = summary_dict["byte_count"]
            context["sni"] = "ny-tunnel.mullvad.net"

            # Run VPN engine
            res = registry.analyze_selective(context, ["vpn"])
            findings.extend(res.findings)

        vpn_alerts = [f for f in findings if f.finding_type == "vpn_detected"]
        assert len(vpn_alerts) > 0
        assert vpn_alerts[0].confidence == 0.55
        assert vpn_alerts[0].details.get("provider") == "Mullvad"
        assert vpn_alerts[0].details.get("vpn_type") == "WireGuard"


