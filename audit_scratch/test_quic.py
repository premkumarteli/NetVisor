import sys
import os
import inspect

sys.path.insert(0, ".")
from packet_engine.quic_parser import extract_quic_metadata

# 1. Inspect source code of extract_quic_metadata
source = inspect.getsource(extract_quic_metadata)
has_hkdf = "hkdf" in source.lower()
has_aead = "aes" in source.lower() or "gcm" in source.lower() or "decrypt" in source.lower()
has_hp = "header_protection" in source.lower() or "mask" in source.lower()
has_multipacket = "reassemble" in source.lower() or "buffer" in source.lower()

print("QUIC Parser Code Inspection:")
print(f"  Contains HKDF derivation: {has_hkdf}")
print(f"  Contains AEAD/AES-GCM decryption: {has_aead}")
print(f"  Contains header protection removal: {has_hp}")
print(f"  Contains multi-packet reassembly: {has_multipacket}")

# 2. Test with real encrypted QUIC Initial packet from RFC 9001 Appendix A.1 (Test Vectors)
# RFC 9001 A.1 specifies the exact client Initial packet wire bytes for DCID: 0x8394c8f03e515708
# The wire packet as captured on the network:
rfc9001_initial_wire = bytes.fromhex(
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c7e8d315572ebee1c7"
    "24e93149c4eeeb7bb432ff4802c63f"
    "476c" # Packet number protected
    # Followed by encrypted ciphertext + tag (1162 bytes padded)
)
# Let's test extract_quic_metadata with real wire bytes:
result_wire = extract_quic_metadata(rfc9001_initial_wire)
print("\nTest with RFC 9001 real wire QUIC Initial packet:")
print(f"  Result: {result_wire}")
if result_wire:
    print(f"  SNI extracted: {result_wire.sni}")
    print(f"  JA4: {result_wire.ja4}")
else:
    print("  Failed to extract metadata from real wire QUIC Initial (packet rejected or offset mismatch).")

# 3. Test with synthetic plaintext payload (as done in tests/test_sprint4_protocol_visibility.py):
rec_hdr = b"\x16\x03\x01\x00\x43"
hs_hdr = b"\x01\x00\x00\x3f"
ch_base = b"\x03\x03" + (b"\xAA" * 32) + b"\x00"
ciphers = b"\x00\x02\x00\x2f"
comp = b"\x01\x00"
exts_hdr = b"\x00\x14"
ext_sni = b"\x00\x00\x00\x10\x00\x0e\x00\x00\x0bexample.com"
ch_payload = rec_hdr + hs_hdr + ch_base + ciphers + comp + exts_hdr + ext_sni
header = b"\x80\x00\x00\x00\x01\x08" + (b"\x01" * 8) + b"\x08" + (b"\x02" * 8) + b"\x00\x40\x43"
synthetic_packet = header + ch_payload

result_synthetic = extract_quic_metadata(synthetic_packet)
print("\nTest with synthetic UNENCRYPTED packet:")
print(f"  Result: {result_synthetic}")
if result_synthetic:
    print(f"  SNI: {result_synthetic.sni}")
