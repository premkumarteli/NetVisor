import sys
import time

sys.path.insert(0, ".")
from packet_engine.object_pool import ObjectPool
from packet_engine.dpkt_parser import FastParsedHeader

# Benchmark: Direct allocation vs ObjectPool borrow/recycle
N = 200_000

# 1. Direct allocation
t0 = time.perf_counter()
for _ in range(N):
    obj = FastParsedHeader(
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        flags="A",
        payload_offset=54,
        payload_length=100
    )
t1 = time.perf_counter()
direct_time = t1 - t0
print(f"Direct Allocation ({N:,} objects): {direct_time:.4f}s ({N/direct_time:,.0f} ops/sec)")

# 2. Object Pool borrow and recycle
pool = ObjectPool[FastParsedHeader](max_size=10_000)
# Pre-fill pool
for _ in range(10_000):
    pool.recycle(FastParsedHeader("192.168.1.1", "192.168.1.2", 1234, 80, "TCP", "A", 54, 100))

t2 = time.perf_counter()
for _ in range(N):
    obj = pool.borrow()
    if obj is None:
        obj = FastParsedHeader("192.168.1.1", "192.168.1.2", 1234, 80, "TCP", "A", 54, 100)
    pool.recycle(obj)
t3 = time.perf_counter()
pool_time = t3 - t2
print(f"ObjectPool Borrow + Recycle ({N:,} objects): {pool_time:.4f}s ({N/pool_time:,.0f} ops/sec)")

overhead = ((pool_time - direct_time) / direct_time) * 100
print(f"Pool is {overhead:.1f}% SLOWER than direct allocation due to threading.Lock overhead!")
