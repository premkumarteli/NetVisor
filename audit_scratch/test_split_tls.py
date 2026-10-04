import sys
import struct
sys.path.insert(0, ".")

from packet_engine.classifier_fast import classify_packet_tier_fast
from packet_engine.tls_consumer import parse_tls_client_hello_record, TlsStreamConsumer
from packet_engine.metadata import extract_ja4_fingerprint
from packet_engine.tcp_stream import TCPStreamBuffer

# Construct a real valid TLS 1.3 / 1.2 ClientHello
rand = b"\x11" * 32
sess_id = b"\x20" + (b"\x22" * 32)
ciphers = b"\x00\x04\x13\x01\x13\x02"
comp = b"\x01\x00"

# Extensions:
# 1. SNI (0x0000): "netvisor.example.com" (len 20)
sni_host = b"netvisor.example.com"
sni_entry = b"\x00" + len(sni_host).to_bytes(2, "big") + sni_host
sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
ext_sni = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

# 2. Supported Versions (0x002B)
ext_ver = b"\x00\x2b\x00\x03\x02\x03\x04"

# 3. ALPN (0x0010): "h2"
alpn_val = b"\x02h2"
alpn_list = len(alpn_val).to_bytes(2, "big") + alpn_val
ext_alpn = b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list

exts_body = ext_sni + ext_ver + ext_alpn
exts_header = len(exts_body).to_bytes(2, "big") + exts_body

body = b"\x03\x03" + rand + sess_id + ciphers + comp + exts_header
hs = b"\x01" + len(body).to_bytes(3, "big") + body
full_tls_record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs

print(f"Total ClientHello record length: {len(full_tls_record)} bytes")

# Test 1: Full record parsing
full_ja4 = extract_ja4_fingerprint(full_tls_record)
full_meta = parse_tls_client_hello_record(full_tls_record)
print("Full Single-Segment ClientHello:")
print(f"  SNI: {full_meta.sni if full_meta else None}")
print(f"  JA4: {full_ja4}")
assert full_meta and full_meta.sni == "netvisor.example.com"

# Now split across 2 TCP segments:
# Segment 1: first 70 bytes (contains record header, ciphers, but NOT full extensions)
# Segment 2: remainder
split_point = 70
seg1_payload = full_tls_record[:split_point]
seg2_payload = full_tls_record[split_point:]

print(f"\nSplit into Seg 1 ({len(seg1_payload)} B) and Seg 2 ({len(seg2_payload)} B):")

# Test 2: Direct tls_consumer / metadata on individual segments
ja4_seg1 = extract_ja4_fingerprint(seg1_payload)
meta_seg1 = parse_tls_client_hello_record(seg1_payload)
print("Segment 1 alone:")
print(f"  SNI: {meta_seg1.sni if meta_seg1 else None}")
print(f"  JA4: {ja4_seg1}")

ja4_seg2 = extract_ja4_fingerprint(seg2_payload)
meta_seg2 = parse_tls_client_hello_record(seg2_payload)
print("Segment 2 alone:")
print(f"  SNI: {meta_seg2.sni if meta_seg2 else None}")
print(f"  JA4: {ja4_seg2}")

# Test 3: TCPStreamBuffer reassembly behavior
stream = TCPStreamBuffer(flow_key=("10.0.0.1", "10.0.0.2", 50000, 443, "TCP"))
stream.process_segment(seq=1000, ack=0, payload=b"", flags="S") # Handshake SYN

flushed_1 = stream.process_segment(seq=1001, ack=0, payload=seg1_payload, flags="A")
print("\nTCPStreamBuffer processing in-order Seg 1:")
print(f"  Flushed chunk size: {len(flushed_1)} (flushed immediately without waiting for rest of TLS record!)")
meta_flushed_1 = parse_tls_client_hello_record(flushed_1)
print(f"  SNI from flushed chunk 1: {meta_flushed_1.sni if meta_flushed_1 else None}")

flushed_2 = stream.process_segment(seq=1001 + split_point, ack=0, payload=seg2_payload, flags="A")
print("TCPStreamBuffer processing in-order Seg 2:")
print(f"  Flushed chunk size: {len(flushed_2)}")
meta_flushed_2 = parse_tls_client_hello_record(flushed_2)
print(f"  SNI from flushed chunk 2: {meta_flushed_2.sni if meta_flushed_2 else None}")

# Test 4: classifier_fast on Ethernet/IP/TCP frame wrapping Seg 1 vs Seg 2
def make_tcp_frame(payload):
    # Ethernet (14) + IP (20) + TCP (20) + payload
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = b"\x45\x00" + (40 + len(payload)).to_bytes(2, "big") + b"\x00\x01\x00\x00\x40\x06\x00\x00" + b"\x0a\x00\x00\x01\x0a\x00\x00\x02"
    tcp = (50000).to_bytes(2, "big") + (443).to_bytes(2, "big") + b"\x00\x00\x03\xe9\x00\x00\x00\x00\x50\x18\x20\x00\x00\x00\x00\x00"
    return eth + ip + tcp + payload

frame1 = make_tcp_frame(seg1_payload)
frame2 = make_tcp_frame(seg2_payload)

tier1 = classify_packet_tier_fast(frame1)
tier2 = classify_packet_tier_fast(frame2)
print("\nclassifier_fast on split frames:")
print(f"  Frame 1 priority tier: {tier1} (0 = High/Control)")
print(f"  Frame 2 priority tier: {tier2} (0 = High/Control, 1 = App metadata, 2 = Bulk)")

# Create PCAP file with these split packets in audit_scratch/split_tls.pcap
def write_pcap(filename, packets):
    # PCAP Global Header: magic 0xa1b2c3d4, v2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
    pcap_hdr = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    with open(filename, "wb") as f:
        f.write(pcap_hdr)
        for i, pkt in enumerate(packets):
            # Packet header: ts_sec, ts_usec, incl_len, orig_len
            pkt_hdr = struct.pack("!IIII", 1000 + i, 0, len(pkt), len(pkt))
            f.write(pkt_hdr)
            f.write(pkt)

pcap_path = "audit_scratch/split_tls.pcap"
write_pcap(pcap_path, [frame1, frame2])
print(f"\nWritten test pcap to {pcap_path}")
