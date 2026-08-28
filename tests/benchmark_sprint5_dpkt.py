import time
import socket
import dpkt
from scapy.all import Ether, IP, TCP, raw
from packet_engine.parser import PacketObservation


def benchmark_parser_dpkt_vs_scapy():
    # Build 1 synthetic raw packet bytes
    scapy_pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=54321, dport=443, flags="S")
    raw_pkt_bytes = raw(scapy_pkt)

    iterations = 50_000

    # 1. Benchmark Scapy Packet parsing
    start_scapy = time.perf_counter()
    for _ in range(iterations):
        obs_scapy = PacketObservation.from_packet(scapy_pkt)
        assert obs_scapy is not None
    dur_scapy = time.perf_counter() - start_scapy
    pps_scapy = iterations / dur_scapy

    # 2. Benchmark DPKT raw bytes parsing
    start_dpkt = time.perf_counter()
    for _ in range(iterations):
        obs_dpkt = PacketObservation.from_raw_bytes(raw_pkt_bytes)
        assert obs_dpkt is not None
    dur_dpkt = time.perf_counter() - start_dpkt
    pps_dpkt = iterations / dur_dpkt

    speedup = pps_dpkt / pps_scapy if pps_scapy > 0 else 0

    print(f"\n--- SPRINT 5 DPKT CUTOVER BENCHMARK RESULTS ({iterations:,} iterations) ---")
    print(f"Scapy PyObject Parsing:  {pps_scapy:12,.2f} packets/sec ({dur_scapy:.4f}s)")
    print(f"DPKT Binary Struct Cutover: {pps_dpkt:12,.2f} packets/sec ({dur_dpkt:.4f}s)")
    print(f"Performance Acceleration Gain: {speedup:.2f}x Speedup!")

    assert pps_dpkt > pps_scapy
    assert speedup >= 2.0


if __name__ == "__main__":
    benchmark_parser_dpkt_vs_scapy()
