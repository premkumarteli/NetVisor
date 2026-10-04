import sys
import time

sys.path.insert(0, ".")
from packet_engine.tcp_stream import TCPStreamBuffer, TCPStreamTrackerManager, TCPStreamStateEnum

# 1. Test Conflicting Overlapping Segments
stream = TCPStreamBuffer(flow_key=("A", "B", 1000, 2000, "TCP"))
# Initial handshake
stream.process_segment(seq=100, ack=0, payload=b"", flags="S")

# Segment 1 arrives in-order: seq 101, payload b"AAAA"
res1 = stream.process_segment(seq=101, ack=0, payload=b"AAAA", flags="A")
print("Conflicting Segments Test:")
print(f"  Segment 1 (seq 101, b'AAAA') flushed: {res1}")

# Conflicting Segment 2 arrives with identical seq 101, payload b"BBBB"
res2 = stream.process_segment(seq=101, ack=0, payload=b"BBBB", flags="A")
print(f"  Segment 2 (seq 101, b'BBBB') flushed: {res2}")
print(f"  Retransmissions count: {stream.retransmissions_count}")
print(f"  Which bytes won? {'Segment 1 (AAAA)' if res1 == b'AAAA' and res2 == b'' else 'Segment 2 (BBBB)'}")

# Partial overlap: seq 103, payload b"CCCC" (overlapping 103..105, new bytes 105)
res3 = stream.process_segment(seq=103, ack=0, payload=b"CCCC", flags="A")
print(f"  Segment 3 (seq 103, len 4: overlaps 103-104, new 105-106) flushed: {res3}")
print(f"  Next expected seq: {stream.next_expected_seq}")

# 2. Test Stream Tracker Manager Memory and Bound on Concurrent Streams
mgr = TCPStreamTrackerManager(max_global_memory_bytes=1000) # Small 1KB limit

# Add stream with 600 bytes
f1 = ("1.1.1.1", "2.2.2.2", 100, 200, "TCP")
mgr.process_bidirectional_segment(f1, seq=1, ack=0, payload=b"X" * 600, flags="A")
print(f"\nGlobal Memory after Stream 1 (600 bytes buffered in OOO? Wait, in-order flushes immediately!):")
print(f"  Global mem: {mgr.current_global_memory_bytes()} bytes")

# Out of order segment buffers memory:
mgr.process_bidirectional_segment(f1, seq=1000, ack=0, payload=b"X" * 600, flags="A")
print(f"  Global mem after OOO (seq 1000, 600 bytes): {mgr.current_global_memory_bytes()} bytes")

# Add second stream with OOO exceeding 1000 byte cap:
f2 = ("3.3.3.3", "4.4.4.4", 300, 400, "TCP")
mgr.process_bidirectional_segment(f2, seq=2000, ack=0, payload=b"Y" * 600, flags="A")
print(f"  Global mem after second stream: {mgr.current_global_memory_bytes()} bytes")

# Zero-payload SYN flood test:
mgr2 = TCPStreamTrackerManager(max_global_memory_bytes=1024)
for i in range(100):
    k = (f"10.0.0.{i}", "10.0.0.1", 10000 + i, 80, "TCP")
    mgr2.process_bidirectional_segment(k, seq=1, ack=0, payload=b"", flags="S")
total_streams = sum(len(s) for s in mgr2._shards)
print(f"\nSYN-flood stream count with zero payload:")
print(f"  Total streams in table: {total_streams}")
print(f"  Reported global memory: {mgr2.current_global_memory_bytes()} bytes")
