import sys
import queue
import threading
import time

sys.path.insert(0, ".")
from packet_engine.ring_buffer import DualRingBuffer, RawPacketEnvelope, wfq_worker_drain_loop

# 1. Test queue drop behavior
buf = DualRingBuffer(control_capacity=3, data_capacity=3)

# Fill control queue (capacity 3)
buf.push(b"ctrl_1", priority=0, timestamp=1.0)
buf.push(b"ctrl_2", priority=0, timestamp=2.0)
buf.push(b"ctrl_3", priority=0, timestamp=3.0)
# 4th control push when full:
res_ctrl_4 = buf.push(b"ctrl_4", priority=0, timestamp=4.0)

print("Control Queue Full Test:")
print(f"  Pushing 4th packet into capacity-3 queue returned: {res_ctrl_4}")
# Check what is in control queue:
c_items = []
while True:
    it = buf.pop_control_nowait()
    if it is None: break
    c_items.append(it.raw_bytes)
print(f"  Items in control queue: {c_items}")
print(f"  Did ctrl_4 get dropped (newest)? {'ctrl_4' not in [x.decode() for x in c_items]}")

# Fill data queue (capacity 3)
buf.push(b"data_1", priority=2, timestamp=1.0)
buf.push(b"data_2", priority=2, timestamp=2.0)
buf.push(b"data_3", priority=2, timestamp=3.0)
# 4th data push when full:
res_data_4 = buf.push(b"data_4", priority=2, timestamp=4.0)

print("\nData Queue Full Test:")
print(f"  Pushing 4th packet into capacity-3 data queue returned: {res_data_4}")
d_items = []
while True:
    it = buf.pop_data_nowait()
    if it is None: break
    d_items.append(it.raw_bytes)
print(f"  Items in data queue: {d_items}")
print(f"  Was data_1 (OLDEST) dropped? {'data_1' not in [x.decode() for x in d_items]}")
print(f"  Was data_4 (NEWEST) retained? {'data_4' in [x.decode() for x in d_items]}")

metrics = buf.get_health_metrics()
print("\nMetrics check:")
print(f"  control_queue_drops_total: {metrics['control_queue_drops_total']}")
print(f"  data_queue_drops_total: {metrics['data_queue_drops_total']}")
print(f"  packets_dropped_total: {metrics['packets_dropped_total']}")

# 2. Test WFQ Drain loop under Control Queue Saturation
flood_buf = DualRingBuffer(control_capacity=1000, data_capacity=1000)
# Fill control with 200 items, data with 50 items
for i in range(200):
    flood_buf.push(f"flood_ctrl_{i}".encode(), priority=0)
for i in range(50):
    flood_buf.push(f"normal_data_{i}".encode(), priority=2)

processed_order = []
stop_ev = threading.Event()

def drain_worker():
    def callback(env):
        processed_order.append(env.raw_bytes.decode()[:4]) # "floo" or "norm"
        if len(processed_order) >= 80: # 2 bursts: 32 ctrl + 8 data + 32 ctrl + 8 data = 80
            stop_ev.set()
    wfq_worker_drain_loop(flood_buf, callback, stop_ev, max_control_burst=32, min_data_batch=8)

t = threading.Thread(target=drain_worker)
t.start()
t.join(timeout=2.0)

print("\nWFQ Drain Under Control Flood Test (80 processed items):")
burst1_ctrl = processed_order[:32].count("floo")
burst1_data = processed_order[32:40].count("norm")
burst2_ctrl = processed_order[40:72].count("floo")
burst2_data = processed_order[72:80].count("norm")
print(f"  Burst 1 Control count: {burst1_ctrl} (expected 32)")
print(f"  Burst 1 Data count:    {burst1_data} (expected 8)")
print(f"  Burst 2 Control count: {burst2_ctrl} (expected 32)")
print(f"  Burst 2 Data count:    {burst2_data} (expected 8)")
