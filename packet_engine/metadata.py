from __future__ import annotations

import ipaddress
import time
from functools import lru_cache


@lru_cache(maxsize=1)
def _load_scapy_primitives():
    from scapy.all import DNS, DNSQR, DNSRR, IP, Raw, TCP  # type: ignore

    return DNS, DNSQR, DNSRR, IP, Raw, TCP


def _normalize_domain(domain: str | None) -> str | None:
    if not domain:
        return None

    value = domain.strip().lower().rstrip(".")
    if not value or " " in value:
        return None
    return value


def _is_ip_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_trackable_private_ip(value: str | None) -> bool:
    if not _is_ip_address(value):
        return False

    ip = ipaddress.ip_address(value)
    return (
        ip.version == 4
        and ip.is_private
        and not ip.is_loopback
        and not ip.is_multicast
        and not ip.is_unspecified
        and not ip.is_reserved
        and not ip.is_link_local
    )


def _select_remote_ip(packet) -> str | None:
    _, _, _, IP, _, _ = _load_scapy_primitives()
    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_private = _is_trackable_private_ip(src_ip)
    dst_private = _is_trackable_private_ip(dst_ip)

    if src_private and not dst_private:
        return dst_ip
    if dst_private and not src_private:
        return src_ip
    return None


def _iter_dns_answers(answer, answer_count: int, dns_rr_type):
    yielded = 0
    current = answer

    if isinstance(current, dns_rr_type):
        while yielded < answer_count and isinstance(current, dns_rr_type):
            yield current
            yielded += 1
            current = current.payload
        return

    try:
        iterator = iter(current)
    except TypeError:
        return

    for item in iterator:
        if yielded >= answer_count:
            break
        if isinstance(item, dns_rr_type):
            yield item
            yielded += 1


class DomainHintCache:
    def __init__(self, ttl_seconds: int = 300, max_entries: int = 2048) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: dict[str, tuple[str, float]] = {}

    def _prune(self) -> None:
        if not self._entries:
            return

        now = time.time()
        expired = [ip for ip, (_, expires_at) in self._entries.items() if expires_at <= now]
        for ip in expired:
            self._entries.pop(ip, None)

        if len(self._entries) <= self.max_entries:
            return

        oldest = sorted(self._entries.items(), key=lambda item: item[1][1])[: len(self._entries) - self.max_entries]
        for ip, _ in oldest:
            self._entries.pop(ip, None)

    def remember(self, ip_value: str | None, domain: str | None) -> None:
        normalized_domain = _normalize_domain(domain)
        if not normalized_domain or not _is_ip_address(ip_value):
            return

        self._prune()
        self._entries[str(ip_value)] = (normalized_domain, time.time() + self.ttl_seconds)

    def lookup(self, ip_value: str | None) -> str | None:
        if not _is_ip_address(ip_value):
            return None

        self._prune()
        record = self._entries.get(str(ip_value))
        if not record:
            return None
        return record[0]

    def observe_dns(self, packet) -> str | None:
        DNS, DNSQR, DNSRR, _, _, _ = _load_scapy_primitives()
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None

        question_name = _normalize_domain(packet[DNSQR].qname.decode(errors="ignore"))
        dns_layer = packet[DNS]

        if dns_layer.qr != 1:
            return question_name

        answer_count = int(getattr(dns_layer, "ancount", 0) or 0)
        for answer in _iter_dns_answers(dns_layer.an, answer_count, DNSRR):
            answer_domain = _normalize_domain(
                answer.rrname.decode(errors="ignore") if hasattr(answer.rrname, "decode") else str(answer.rrname)
            ) or question_name
            if answer.type in (1, 28):
                self.remember(str(answer.rdata), answer_domain)

        return question_name


def _extract_tls_sni(payload: bytes) -> str | None:
    if len(payload) < 5 or payload[0] != 0x16:
        return None

    record_length = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + record_length:
        return None

    handshake = payload[5 : 5 + record_length]
    if len(handshake) < 4 or handshake[0] != 0x01:
        return None

    body = handshake[4:]
    if len(body) < 34:
        return None

    index = 34
    if index >= len(body):
        return None

    session_id_length = body[index]
    index += 1 + session_id_length
    if index + 2 > len(body):
        return None

    cipher_suites_length = int.from_bytes(body[index : index + 2], "big")
    index += 2 + cipher_suites_length
    if index >= len(body):
        return None

    compression_length = body[index]
    index += 1 + compression_length
    if index + 2 > len(body):
        return None

    extensions_length = int.from_bytes(body[index : index + 2], "big")
    index += 2
    extensions_end = min(len(body), index + extensions_length)

    while index + 4 <= extensions_end:
        extension_type = int.from_bytes(body[index : index + 2], "big")
        extension_size = int.from_bytes(body[index + 2 : index + 4], "big")
        extension_start = index + 4
        extension_end = extension_start + extension_size
        if extension_end > extensions_end:
            return None

        if extension_type == 0x0000 and extension_size >= 5:
            server_name_list_length = int.from_bytes(body[extension_start : extension_start + 2], "big")
            pointer = extension_start + 2
            list_end = min(extension_end, pointer + server_name_list_length)
            while pointer + 3 <= list_end:
                name_type = body[pointer]
                name_length = int.from_bytes(body[pointer + 1 : pointer + 3], "big")
                pointer += 3
                if pointer + name_length > list_end:
                    return None
                if name_type == 0:
                    return _normalize_domain(body[pointer : pointer + name_length].decode("utf-8", errors="ignore"))
                pointer += name_length

        index = extension_end

    return None


import re

_HTTP_HOST_REGEX = re.compile(rb"(?i)\r?\nHost:\s*([^\r\n]+)")

def _extract_http_host(payload: bytes) -> str | None:
    if not payload or len(payload) < 10:
        return None

    prefix = payload[:8]
    if not (
        prefix.startswith(b"GET ")
        or prefix.startswith(b"POST ")
        or prefix.startswith(b"PUT ")
        or prefix.startswith(b"PATCH ")
        or prefix.startswith(b"DELETE ")
        or prefix.startswith(b"HEAD ")
        or prefix.startswith(b"OPTIONS ")
        or prefix.startswith(b"CONNECT ")
        or prefix.startswith(b"HTTP/")
    ):
        return None

    # Limit header search window to first 1,024 bytes to avoid CPU DoS on large payloads
    header_chunk = payload[:1024]
    match = _HTTP_HOST_REGEX.search(header_chunk)
    if match:
        raw_host = match.group(1).decode("utf-8", errors="ignore").strip()
        return _normalize_domain(raw_host)

    return None

import hashlib


def _is_grease(val: int) -> bool:
    return (val & 0x0F0F) == 0x0A0A and ((val >> 8) & 0xFF) == (val & 0xFF)


def extract_ja4_fingerprint(payload: bytes, transport_protocol: str = "TCP") -> str | None:
    if not payload or len(payload) < 5 or payload[0] != 0x16:
        return None

    record_length = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + record_length:
        return None

    handshake = payload[5 : 5 + record_length]
    if len(handshake) < 6 or handshake[0] != 0x01:
        return None

    client_version_raw = int.from_bytes(handshake[4:6], "big")
    body = handshake[4:]
    if len(body) < 34:
        return None

    index = 34
    if index >= len(body):
        return None
    session_id_length = body[index]
    index += 1 + session_id_length

    if index + 2 > len(body):
        return None
    cipher_suites_length = int.from_bytes(body[index : index + 2], "big")
    index += 2
    if index + cipher_suites_length > len(body):
        return None

    cipher_bytes = body[index : index + cipher_suites_length]
    ciphers: list[int] = []
    for i in range(0, len(cipher_bytes) - 1, 2):
        val = int.from_bytes(cipher_bytes[i : i + 2], "big")
        if not _is_grease(val):
            ciphers.append(val)
    index += cipher_suites_length

    if index >= len(body):
        return None
    compression_length = body[index]
    index += 1 + compression_length

    extensions: list[int] = []
    has_sni = False
    alpn_str = "00"
    sig_algs: list[int] = []
    supported_versions: list[int] = []

    if index + 2 <= len(body):
        extensions_length = int.from_bytes(body[index : index + 2], "big")
        index += 2
        extensions_end = min(len(body), index + extensions_length)

        while index + 4 <= extensions_end:
            ext_type = int.from_bytes(body[index : index + 2], "big")
            ext_size = int.from_bytes(body[index + 2 : index + 4], "big")
            ext_start = index + 4
            ext_end = min(extensions_end, ext_start + ext_size)

            if not _is_grease(ext_type):
                if ext_type == 0x0000:
                    has_sni = True
                elif ext_type == 0x0010:
                    if ext_start + 2 <= ext_end:
                        alpn_list_len = int.from_bytes(body[ext_start : ext_start + 2], "big")
                        ptr = ext_start + 2
                        if ptr < ext_end:
                            proto_len = body[ptr]
                            ptr += 1
                            if ptr + proto_len <= ext_end:
                                proto_bytes = body[ptr : ptr + proto_len]
                                if proto_bytes:
                                    first_ch = chr(proto_bytes[0]) if 32 <= proto_bytes[0] <= 126 else "0"
                                    last_ch = chr(proto_bytes[-1]) if 32 <= proto_bytes[-1] <= 126 else "0"
                                    alpn_str = f"{first_ch}{last_ch}"
                elif ext_type == 0x000D:
                    extensions.append(ext_type)
                    if ext_start + 2 <= ext_end:
                        sig_len = int.from_bytes(body[ext_start : ext_start + 2], "big")
                        s_ptr = ext_start + 2
                        while s_ptr + 2 <= min(ext_end, s_ptr + sig_len):
                            s_val = int.from_bytes(body[s_ptr : s_ptr + 2], "big")
                            if not _is_grease(s_val):
                                sig_algs.append(s_val)
                            s_ptr += 2
                elif ext_type == 0x002B:
                    extensions.append(ext_type)
                    if ext_start + 1 <= ext_end:
                        v_len = body[ext_start]
                        v_ptr = ext_start + 1
                        while v_ptr + 2 <= min(ext_end, v_ptr + v_len):
                            v_val = int.from_bytes(body[v_ptr : v_ptr + 2], "big")
                            if not _is_grease(v_val):
                                supported_versions.append(v_val)
                            v_ptr += 2
                else:
                    extensions.append(ext_type)

            index = ext_end

    version_str = "00"
    if 0x0304 in supported_versions or client_version_raw == 0x0304:
        version_str = "13"
    elif 0x0303 in supported_versions or client_version_raw == 0x0303:
        version_str = "12"
    elif 0x0302 in supported_versions or client_version_raw == 0x0302:
        version_str = "11"
    elif 0x0301 in supported_versions or client_version_raw == 0x0301:
        version_str = "10"

    proto_char = "u" if transport_protocol.upper() == "UDP" else "t"
    sni_char = "d" if has_sni else "i"
    ciphers_count = min(len(ciphers), 99)
    ext_count = min(len(extensions), 99)

    part_a = f"{proto_char}{version_str}{sni_char}{ciphers_count:02d}{ext_count:02d}{alpn_str}"

    sorted_ciphers = sorted(ciphers)
    ciphers_hex_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
    part_b = hashlib.sha256(ciphers_hex_str.encode("utf-8")).hexdigest()[:12]

    sorted_exts = sorted(extensions)
    exts_hex_str = ",".join(f"{e:04x}" for e in sorted_exts)
    if sig_algs:
        exts_hex_str += "_" + ",".join(f"{s:04x}" for s in sig_algs)
    part_c = hashlib.sha256(exts_hex_str.encode("utf-8")).hexdigest()[:12]

    return f"{part_a}_{part_b}_{part_c}"



import sys

def _get_extract_tls_sni():
    mod = sys.modules.get("collector.analysis") or sys.modules.get("packet_engine.classifier")
    if mod and hasattr(mod, "_extract_tls_sni"):
        return mod._extract_tls_sni
    return _extract_tls_sni


def _get_extract_http_host():
    mod = sys.modules.get("collector.analysis") or sys.modules.get("packet_engine.classifier")
    if mod and hasattr(mod, "_extract_http_host"):
        return mod._extract_http_host
    return _extract_http_host


def extract_flow_hints(packet, domain_cache: DomainHintCache | None = None) -> dict[str, str | None]:
    DNS, DNSQR, _, _, Raw, TCP = _load_scapy_primitives()
    ja4 = None

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain = (
            domain_cache.observe_dns(packet)
            if domain_cache
            else _normalize_domain(packet[DNSQR].qname.decode(errors="ignore"))
        )
        return {"domain": domain, "sni": None, "ja4": None}

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_payload = bytes(packet[Raw].load)
        http_domain = _get_extract_http_host()(raw_payload)
        if http_domain:
            if domain_cache:
                domain_cache.remember(_select_remote_ip(packet), http_domain)
            return {"domain": http_domain, "sni": None, "ja4": None}

        tls_domain = _get_extract_tls_sni()(raw_payload)
        ja4 = extract_ja4_fingerprint(raw_payload, transport_protocol="TCP")
        if tls_domain and domain_cache:
            domain_cache.remember(_select_remote_ip(packet), tls_domain)
        if tls_domain or ja4:
            return {"domain": tls_domain, "sni": tls_domain, "ja4": ja4}

    if domain_cache:
        cached_domain = domain_cache.lookup(_select_remote_ip(packet))
        return {"domain": cached_domain, "sni": None, "ja4": None}

    return {"domain": None, "sni": None, "ja4": None}


def extract_domain_hint(packet, domain_cache: DomainHintCache | None = None) -> str | None:
    hints = extract_flow_hints(packet, domain_cache)
    return hints.get("sni") or hints.get("domain")

