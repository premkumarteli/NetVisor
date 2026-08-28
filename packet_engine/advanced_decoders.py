from __future__ import annotations

import hashlib
import struct
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict

logger = logging.getLogger("netvisor.packet_engine.advanced_decoders")


@dataclass(slots=True)
class JA3Fingerprint:
    ja3_string: str
    ja3_hash: str


class JA3Fingerprinter:
    """
    TLS JA3 Client Fingerprinter (RFC / Salesforce Specification).
    Computes MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats).
    """

    @staticmethod
    def calculate_ja3(
        tls_version: int,
        ciphers: List[int],
        extensions: List[int],
        curves: List[int],
        point_formats: List[int],
    ) -> JA3Fingerprint:
        # Filter GREASE values (0x0a0a, 0x1a1a, 0x2a2a, etc.)
        grease = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

        clean_ciphers = [str(c) for c in ciphers if c not in grease]
        clean_exts = [str(e) for e in extensions if e not in grease]
        clean_curves = [str(cr) for cr in curves if cr not in grease]
        clean_formats = [str(pf) for pf in point_formats if pf not in grease]

        ja3_str = f"{tls_version},{'-'.join(clean_ciphers)},{'-'.join(clean_exts)},{'-'.join(clean_curves)},{'-'.join(clean_formats)}"
        ja3_md5 = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()

        return JA3Fingerprint(ja3_string=ja3_str, ja3_hash=ja3_md5)


@dataclass(slots=True)
class SMB2Header:
    command_code: int
    command_name: str
    status: int
    tree_id: int
    session_id: int


class SMB2Dissector:
    """
    SMB2 / SMB3 Protocol Dissector.
    Parses SMB2 header (Magic 0xFE 'S' 'M' 'B'), extracting command codes, session IDs, and tree connections.
    """

    COMMAND_MAP = {
        0x0000: "SMB2_NEGOTIATE",
        0x0001: "SMB2_SESSION_SETUP",
        0x0002: "SMB2_LOGOFF",
        0x0003: "SMB2_TREE_CONNECT",
        0x0004: "SMB2_TREE_DISCONNECT",
        0x0005: "SMB2_CREATE",
        0x0006: "SMB2_CLOSE",
        0x0007: "SMB2_FLUSH",
        0x0008: "SMB2_READ",
        0x0009: "SMB2_WRITE",
        0x000E: "SMB2_IOCTL",
    }

    @classmethod
    def parse_smb2_header(cls, payload: bytes) -> SMB2Header | None:
        if not payload or len(payload) < 64:
            return None

        # Check SMB2 Protocol ID: 0xFE 'S' 'M' 'B' (0xfe534d42)
        if payload[0:4] != b"\xfeSMB":
            return None

        cmd = int.from_bytes(payload[12:14], "little")
        status = int.from_bytes(payload[8:12], "little")
        tree_id = int.from_bytes(payload[36:40], "little")
        session_id = int.from_bytes(payload[40:48], "little")

        cmd_name = cls.COMMAND_MAP.get(cmd, f"SMB2_CMD_{cmd:#06x}")

        return SMB2Header(
            command_code=cmd,
            command_name=cmd_name,
            status=status,
            tree_id=tree_id,
            session_id=session_id,
        )


@dataclass(slots=True)
class KerberosMessage:
    msg_type: int
    msg_name: str
    realm: Optional[str] = None


class KerberosDissector:
    """
    Kerberos v5 Dissector.
    Detects AS-REQ (0x0a), AS-REP (0x0b), TGS-REQ (0x0c), TGS-REP (0x0d) ticket requests.
    """

    MSG_TYPE_MAP = {
        0x0a: "AS-REQ",
        0x0b: "AS-REP",
        0x0c: "TGS-REQ",
        0x0d: "TGS-REP",
        0x0e: "AP-REQ",
        0x0f: "AP-REP",
        0x1e: "KRB-ERROR",
    }

    @classmethod
    def parse_kerberos_message(cls, payload: bytes) -> KerberosMessage | None:
        if not payload or len(payload) < 10:
            return None

        # Scan for ASN.1 DER tag 0x60 (Application 0-30)
        idx = 0
        if payload[0] == 0x60:  # Application tag
            idx += 2
        elif payload[:4] == b"\x00\x00\x00":  # NetBIOS / Length prefix
            idx = 4

        if idx + 4 > len(payload):
            return None

        tag = payload[idx]
        msg_type_code = tag & 0x1F

        if msg_type_code in cls.MSG_TYPE_MAP:
            msg_name = cls.MSG_TYPE_MAP[msg_type_code]
            return KerberosMessage(msg_type=msg_type_code, msg_name=msg_name)

        return None
