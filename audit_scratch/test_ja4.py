import sys
import hashlib
sys.path.insert(0, ".")

from packet_engine.metadata import extract_ja4_fingerprint, _is_grease

# Verify GREASE function against RFC 8701 values
grease_values = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
                 0x8A8A, 0x9A9A, 0xAAAA, 0xBA0A, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA]

print("GREASE verification:")
for g in [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa]:
    assert _is_grease(g), f"Failed to identify GREASE {hex(g)}"
assert not _is_grease(0x002f), "False positive on non-GREASE 0x002f"
assert not _is_grease(0x1301), "False positive on TLS_AES_128_GCM_SHA256"
print("  All RFC 8701 GREASE values verified correctly.")

# Let's inspect JA4 string generation format:
# In metadata.py lines 376-388:
# part_a = f"{proto_char}{version_str}{sni_char}{ciphers_count:02d}{ext_count:02d}{alpn_str}"
# sorted_ciphers = sorted(ciphers)
# ciphers_hex_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
# part_b = hashlib.sha256(ciphers_hex_str.encode("utf-8")).hexdigest()[:12]
# sorted_exts = sorted(extensions)
# exts_hex_str = ",".join(f"{e:04x}" for e in sorted_exts)
# if sig_algs:
#     exts_hex_str += "_" + ",".join(f"{s:04x}" for s in sig_algs)
# part_c = hashlib.sha256(exts_hex_str.encode("utf-8")).hexdigest()[:12]
print("\nJA4 Implementation Analysis:")
print("  Part A format: proto(1) + ver(2) + sni(1) + cipher_cnt(2) + ext_cnt(2) + alpn(2)")
print("  Part B format: sha256(sorted_ciphers_hex_comma_separated)[:12]")
print("  Part C format: sha256(sorted_exts_hex_comma_separated + optional '_' + sig_algs)[:12]")
