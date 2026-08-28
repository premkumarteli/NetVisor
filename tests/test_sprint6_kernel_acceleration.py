import pytest
from packet_engine.af_packet_backend import AFPacketMmapBackend
from packet_engine.bpf_filter import BPFFilterEngine
from packet_engine.cpu_affinity import CPUAffinityManager
from packet_engine.exporter import FlowExporterPipeline
from packet_engine.advanced_decoders import JA3Fingerprinter, SMB2Dissector, KerberosDissector


def test_bpf_filter_engine_noise_dropping():
    filter_engine = BPFFilterEngine()

    # Synthetic mDNS frame (Port 5353) with IPv4 IHL 20 (0x45)
    mdns_pkt = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00\x45" + (b"\x00" * 8) + b"\x11" + (b"\x00" * 10) + b"\x14\xe9\x14\xe9"
    assert filter_engine.should_pass_packet(mdns_pkt) is False

    # Synthetic DNS frame (Port 53) with IPv4 IHL 20 (0x45)
    dns_pkt = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00\x45" + (b"\x00" * 8) + b"\x11" + (b"\x00" * 10) + b"\x00\x35\x00\x35"
    assert filter_engine.should_pass_packet(dns_pkt) is True


def test_cpu_affinity_manager():
    mgr = CPUAffinityManager()
    core_assigned = mgr.get_core_assignment_for_shard(shard_index=3, total_shards=16)
    assert isinstance(core_assigned, int)


def test_flow_exporter_pipeline():
    exporter = FlowExporterPipeline(export_format="jsonl")
    flow_data = {
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "application_protocol": "HTTPS",
        "byte_count": 1024,
        "packet_count": 10,
    }

    jsonl_str = exporter.export_flow(flow_data)
    assert isinstance(jsonl_str, str)
    assert "192.168.1.10" in jsonl_str
    assert "HTTPS" in jsonl_str


def test_ja3_fingerprinter():
    ja3 = JA3Fingerprinter.calculate_ja3(
        tls_version=771,  # TLS 1.2
        ciphers=[47, 53, 255],
        extensions=[0, 10, 11],
        curves=[23, 24],
        point_formats=[0],
    )
    assert ja3.ja3_string == "771,47-53-255,0-10-11,23-24,0"
    assert len(ja3.ja3_hash) == 32  # 32-char MD5 hex digest


def test_smb2_dissector():
    # SMB2 Header payload: Magic \xfeSMB + Command 0x0000 (SMB2_NEGOTIATE) (64 bytes minimum header)
    smb_bytes = b"\xfeSMB" + (b"\x00" * 60)
    smb_hdr = SMB2Dissector.parse_smb2_header(smb_bytes)
    assert smb_hdr is not None
    assert smb_hdr.command_name == "SMB2_NEGOTIATE"
