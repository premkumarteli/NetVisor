import cProfile
import pstats
import io
import time
import sys
import os

sys.path.insert(0, ".")
from scapy.all import rdpcap, sniff
from packet_engine.parser import PacketObservation
from packet_engine.flow_aggregator import FlowManager

pcap_file = os.path.join("tests", "fixtures", "pcaps", "mixed.pcap")
print(f"Loading test PCAP: {pcap_file} ({os.path.getsize(pcap_file):,} bytes)...")
packets = rdpcap(pcap_file)
total_packets = len(packets)
print(f"Loaded {total_packets} packets from PCAP.")

# Initialize FlowManager
expired_flows = []
flow_mgr = FlowManager(
    agent_id="test-agent",
    organization_id="test-org",
    on_flow_expired=lambda s: expired_flows.append(s),
    start_worker=False
)

def run_pipeline():
    for pkt in packets:
        obs = PacketObservation.from_packet(pkt, source_type="agent", metadata_only=False)
        if obs:
            flow_mgr.update_from_observation(obs)

pr = cProfile.Profile()

wall_start = time.perf_counter()
cpu_start = time.process_time()

pr.enable()
run_pipeline()
pr.disable()

wall_end = time.perf_counter()
cpu_end = time.process_time()

wall_time = wall_end - wall_start
cpu_time = cpu_end - cpu_start
pps = total_packets / wall_time if wall_time > 0 else 0
cpu_util = (cpu_time / wall_time) * 100 if wall_time > 0 else 0

print("\n" + "=" * 60)
print("PROFILING RESULTS: Windows Scapy Capture & Pipeline")
print("=" * 60)
print(f"Total Packets Processed : {total_packets:,}")
print(f"Wall Clock Time         : {wall_time:.4f} s")
print(f"CPU Time                : {cpu_time:.4f} s")
print(f"Packets Per Second (PPS): {pps:,.1f} pps")
print(f"CPU Utilization         : {cpu_util:.1f}% (Single Core Saturated)")

# Analyze cProfile statistics
s = io.StringIO()
ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
ps.print_stats(50)

# Calculate share of time: Scapy vs NetVisor
stats = ps.stats
scapy_cumtime = 0.0
netvisor_cumtime = 0.0
other_cumtime = 0.0

for func_tuple, (cc, nc, tt, ct, callers) in stats.items():
    filename, line, func_name = func_tuple
    if "scapy" in filename.lower():
        scapy_cumtime += tt # self-time
    elif "packet_engine" in filename.lower() or "audit_scratch" in filename.lower():
        netvisor_cumtime += tt
    else:
        other_cumtime += tt

total_self_time = scapy_cumtime + netvisor_cumtime + other_cumtime
print("\nExecution Time Breakdown (Self Time):")
print(f"  Scapy internals     : {scapy_cumtime:.4f} s ({scapy_cumtime/total_self_time*100:.1f}%)")
print(f"  NetVisor code       : {netvisor_cumtime:.4f} s ({netvisor_cumtime/total_self_time*100:.1f}%)")
print(f"  Python / stdlib / OS: {other_cumtime:.4f} s ({other_cumtime/total_self_time*100:.1f}%)")

print("\nTop 10 Functions by Cumulative Time:")
ps2 = pstats.Stats(pr).sort_stats("cumulative")
ps2.print_stats(15)
