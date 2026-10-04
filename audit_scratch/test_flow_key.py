import sys
from packet_engine.parser import PacketObservation

# Create two flows:
# Flow 1: A:1000 <-> B:2000
# Flow 2: A:2000 <-> B:1000
# Where A = "192.168.1.10", B = "192.168.1.20"

obs1_fwd = PacketObservation(
    observed_at=1000.0,
    source_type="agent",
    metadata_only=False,
    src_ip="192.168.1.10",
    dst_ip="192.168.1.20",
    src_port=1000,
    dst_port=2000,
    protocol="TCP",
    packet_size=100,
    src_mac="aa:bb:cc:dd:ee:01",
    dst_mac="aa:bb:cc:dd:ee:02",
    vlan_id=0
)

obs1_rev = PacketObservation(
    observed_at=1000.1,
    source_type="agent",
    metadata_only=False,
    src_ip="192.168.1.20",
    dst_ip="192.168.1.10",
    src_port=2000,
    dst_port=1000,
    protocol="TCP",
    packet_size=100,
    src_mac="aa:bb:cc:dd:ee:02",
    dst_mac="aa:bb:cc:dd:ee:01",
    vlan_id=0
)

obs2_fwd = PacketObservation(
    observed_at=1000.0,
    source_type="agent",
    metadata_only=False,
    src_ip="192.168.1.10",
    dst_ip="192.168.1.20",
    src_port=2000,
    dst_port=1000,
    protocol="TCP",
    packet_size=100,
    src_mac="aa:bb:cc:dd:ee:01",
    dst_mac="aa:bb:cc:dd:ee:02",
    vlan_id=0
)

obs2_rev = PacketObservation(
    observed_at=1000.1,
    source_type="agent",
    metadata_only=False,
    src_ip="192.168.1.20",
    dst_ip="192.168.1.10",
    src_port=1000,
    dst_port=2000,
    protocol="TCP",
    packet_size=100,
    src_mac="aa:bb:cc:dd:ee:02",
    dst_mac="aa:bb:cc:dd:ee:01",
    vlan_id=0
)

print("Flow 1 (A:1000 -> B:2000):")
print("  Forward key:", obs1_fwd.canonical_conversation_key)
print("  Reverse key:", obs1_rev.canonical_conversation_key)
print("  Keys match?", obs1_fwd.canonical_conversation_key == obs1_rev.canonical_conversation_key)

print("\nFlow 2 (A:2000 -> B:1000):")
print("  Forward key:", obs2_fwd.canonical_conversation_key)
print("  Reverse key:", obs2_rev.canonical_conversation_key)
print("  Keys match?", obs2_fwd.canonical_conversation_key == obs2_rev.canonical_conversation_key)

print("\nCollision check between Flow 1 and Flow 2:")
print("  Key 1:", obs1_fwd.canonical_conversation_key)
print("  Key 2:", obs2_fwd.canonical_conversation_key)
collides = obs1_fwd.canonical_conversation_key == obs2_fwd.canonical_conversation_key
print(f"  Do Flow 1 and Flow 2 collide? {collides}")

# Check endpoint pair sorting:
print(f"\nNetVisor endpoint sorting:")
print(f"  obs1_fwd is_forward_direction: {obs1_fwd.is_forward_direction}")
print(f"  obs2_fwd is_forward_direction: {obs2_fwd.is_forward_direction}")
print(f"  obs1 port_pair: {obs1_fwd.canonical_conversation_key[1]}")
print(f"  obs2 port_pair: {obs2_fwd.canonical_conversation_key[1]}")

# Router crossing check:
obs_before_router = PacketObservation(
    observed_at=1000.0,
    source_type="agent",
    metadata_only=False,
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    src_port=54321,
    dst_port=53,
    protocol="UDP",
    packet_size=60,
    src_mac="aa:bb:cc:dd:ee:01",
    dst_mac="11:22:33:44:55:01", # Router LAN MAC
    vlan_id=0
)
obs_after_router = PacketObservation(
    observed_at=1000.0,
    source_type="agent",
    metadata_only=False,
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    src_port=54321,
    dst_port=53,
    protocol="UDP",
    packet_size=60,
    src_mac="11:22:33:44:55:02", # Router WAN MAC
    dst_mac="99:88:77:66:55:44", # Next hop / ISP MAC
    vlan_id=0
)
print("\nRouter crossing check:")
print("  Before router key:", obs_before_router.canonical_conversation_key)
print("  After router key: ", obs_after_router.canonical_conversation_key)
print("  Does key change across router? ", obs_before_router.canonical_conversation_key != obs_after_router.canonical_conversation_key)
