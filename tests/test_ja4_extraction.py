import unittest
from packet_engine.metadata import extract_ja4_fingerprint
from packet_engine.parser import PacketObservation, FlowObservation


class TestJA4Extraction(unittest.TestCase):
    def test_extract_ja4_non_tls_returns_none(self):
        self.assertIsNone(extract_ja4_fingerprint(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        self.assertIsNone(extract_ja4_fingerprint(b""))
        self.assertIsNone(extract_ja4_fingerprint(b"\x16\x03\x03\x00"))

    def test_extract_ja4_synthetic_client_hello(self):
        rand = b"\x00" * 32
        sess_id = b"\x00"
        ciphers = b"\x00\x04\x13\x01\x13\x02"
        comp = b"\x01\x00"
        ext_sni = b"\x00\x00\x00\x05\x00\x03\x00\x00\x00"
        ext_ver = b"\x00\x2b\x00\x03\x02\x03\x04"
        exts = b"\x00\x12" + ext_sni + ext_ver

        body = b"\x03\x03" + rand + sess_id + ciphers + comp + exts
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        payload = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs

        ja4 = extract_ja4_fingerprint(payload, transport_protocol="TCP")
        self.assertIsNotNone(ja4)
        self.assertTrue(ja4.startswith("t13d020100_"))

    def test_observation_dataclasses_contain_ja4(self):
        p_obs = PacketObservation(
            observed_at=1000.0,
            source_type="agent",
            metadata_only=False,
            src_ip="192.168.1.50",
            dst_ip="1.1.1.1",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            packet_size=120,
            domain="cloudflare.com",
            sni="cloudflare.com",
            ja4="t13d1516h2_9a12_108a",
        )
        self.assertEqual(p_obs.ja4, "t13d1516h2_9a12_108a")

        f_obs = FlowObservation.from_packet_observation(
            p_obs, agent_id="ag-1", organization_id="org-1"
        )
        self.assertEqual(f_obs.ja4, "t13d1516h2_9a12_108a")
        self.assertEqual(f_obs.as_dict()["ja4"], "t13d1516h2_9a12_108a")


if __name__ == "__main__":
    unittest.main()
