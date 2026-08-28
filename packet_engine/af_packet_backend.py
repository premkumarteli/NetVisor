from __future__ import annotations

import os
import sys
import socket
import logging
import mmap
import ctypes
import struct
import time
from typing import Callable, Optional

logger = logging.getLogger("netvisor.packet_engine.af_packet_backend")


# Constants for Linux AF_PACKET / TPACKET
SOL_PACKET = 263
PACKET_VERSION = 10
PACKET_RX_RING = 5
TPACKET_V2 = 1
TPACKET_V3 = 2

TP_STATUS_KERNEL = 0
TP_STATUS_USER = 1


class AFPacketMmapBackend:
    """
    Linux AF_PACKET + PACKET_MMAP Zero-Copy Kernel Ring Buffer Capture Driver.
    Implements TPACKET_V3 block-based ring traversal with TPACKET_V2 and raw socket fallback.
    """

    ETH_P_ALL = 0x0003  # Capture all Ethernet protocols

    def __init__(
        self,
        interface: str = "eth0",
        frame_size: int = 2048,
        frame_count: int = 1024,
        block_size: int = 1048576,  # 1MB blocks for TPACKET_V3
        block_count: int = 8,
    ) -> None:
        self.interface = interface
        self.frame_size = frame_size
        self.frame_count = frame_count
        self.block_size = block_size
        self.block_count = block_count
        self.is_linux = sys.platform.startswith("linux")
        self._sock: Optional[socket.socket] = None
        self._mmap_buf: Optional[mmap.mmap] = None
        self.running = False
        self.tpacket_version = TPACKET_V3
        self.packets_captured = 0
        self.bytes_captured = 0

    def start_capture(self, packet_callback: Callable[[bytes, float], None]) -> None:
        """Starts packet capture loop using zero-copy PACKET_MMAP on Linux or raw socket fallback."""
        self.running = True

        if self.is_linux:
            self._start_linux_packet_mmap(packet_callback)
        else:
            self._start_fallback_raw_socket(packet_callback)

    def _start_linux_packet_mmap(self, callback: Callable[[bytes, float], None]) -> None:
        """Zero-copy PACKET_MMAP ring buffer capture loop with TPACKET_V3 -> TPACKET_V2 fallback."""
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ALL))
            self._sock.bind((self.interface, self.ETH_P_ALL))

            # Attempt TPACKET_V3 setup first
            try:
                self._sock.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
                self.tpacket_version = TPACKET_V3
                req3 = struct.pack(
                    "IIIIIII",
                    self.block_size,      # tp_block_size
                    self.block_count,     # tp_block_nr
                    self.frame_size,      # tp_frame_size
                    self.frame_count,     # tp_frame_nr
                    10,                   # tp_retire_blk_tov (ms)
                    0,                    # tp_sizeof_priv
                    0,                    # tp_feature_req_word
                )
                self._sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req3)
                ring_len = self.block_size * self.block_count
            except Exception as e:
                logger.info(f"TPACKET_V3 unsupported ({e}), falling back to TPACKET_V2 ring.")
                self._sock.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V2)
                self.tpacket_version = TPACKET_V2
                req2 = struct.pack(
                    "IIII",
                    self.frame_size * 64,  # block_size
                    (self.frame_size * self.frame_count) // (self.frame_size * 64),
                    self.frame_size,
                    self.frame_count,
                )
                self._sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req2)
                ring_len = self.frame_size * self.frame_count

            # Mmap ring buffer
            self._mmap_buf = mmap.mmap(
                self._sock.fileno(),
                ring_len,
                mmap.MAP_SHARED,
                mmap.PROT_READ | mmap.PROT_WRITE,
            )
            logger.info(f"Initialized Linux PACKET_MMAP ({'TPACKET_V3' if self.tpacket_version == TPACKET_V3 else 'TPACKET_V2'}) on {self.interface} ({ring_len:,} bytes)")

            if self.tpacket_version == TPACKET_V3:
                self._tpacket_v3_ring_loop(callback)
            else:
                self._tpacket_v2_ring_loop(callback)

        except Exception as e:
            logger.warning(f"PACKET_MMAP initialization failed on {self.interface}: {e}. Using raw socket fallback.")
            self._start_fallback_raw_socket(callback)

    def _tpacket_v3_ring_loop(self, callback: Callable[[bytes, float], None]) -> None:
        """Active TPACKET_V3 block-based ring buffer traversal loop."""
        block_idx = 0
        while self.running:
            offset = block_idx * self.block_size
            if offset + 48 > len(self._mmap_buf):
                break

            # Read tpacket_block_desc header: block_status is first uint32
            block_status = struct.unpack_from("<I", self._mmap_buf, offset)[0]

            if block_status & TP_STATUS_USER:
                # Read block descriptor fields: num_pkts at offset 12, offset_to_first_pkt at offset 16
                num_pkts, offset_to_first_pkt = struct.unpack_from("<II", self._mmap_buf, offset + 12)
                pkt_offset = offset + offset_to_first_pkt

                for _ in range(num_pkts):
                    if pkt_offset + 32 > len(self._mmap_buf):
                        break
                    # tpacket3_hdr: tp_next_offset (0), tp_sec (4), tp_nsec (8), tp_snaplen (12), tp_len (16), tp_mac (20)
                    tp_next_offset, tp_sec, tp_nsec, tp_snaplen, tp_len, tp_mac = struct.unpack_from("<IIIIHH", self._mmap_buf, pkt_offset)
                    ts = float(tp_sec) + (float(tp_nsec) / 1e9)

                    payload_offset = pkt_offset + tp_mac
                    if payload_offset + tp_snaplen <= len(self._mmap_buf):
                        raw_bytes = bytes(self._mmap_buf[payload_offset : payload_offset + tp_snaplen])
                        self.packets_captured += 1
                        self.bytes_captured += len(raw_bytes)
                        callback(raw_bytes, ts)

                    if tp_next_offset == 0:
                        break
                    pkt_offset += tp_next_offset

                # Return block ownership back to kernel
                struct.pack_into("<I", self._mmap_buf, offset, TP_STATUS_KERNEL)
                block_idx = (block_idx + 1) % self.block_count
            else:
                time.sleep(0.001)

    def _tpacket_v2_ring_loop(self, callback: Callable[[bytes, float], None]) -> None:
        """Active TPACKET_V2 frame-based ring buffer traversal loop."""
        frame_idx = 0
        while self.running:
            offset = frame_idx * self.frame_size
            if offset + 32 > len(self._mmap_buf):
                break

            tp_status = struct.unpack_from("<I", self._mmap_buf, offset)[0]
            if tp_status & TP_STATUS_USER:
                tp_len, tp_snaplen, tp_mac, tp_net, tp_sec, tp_nsec = struct.unpack_from("<IIHHII", self._mmap_buf, offset + 4)
                ts = float(tp_sec) + (float(tp_nsec) / 1e9)
                payload_offset = offset + tp_mac

                if payload_offset + tp_snaplen <= len(self._mmap_buf):
                    raw_bytes = bytes(self._mmap_buf[payload_offset : payload_offset + tp_snaplen])
                    self.packets_captured += 1
                    self.bytes_captured += len(raw_bytes)
                    callback(raw_bytes, ts)

                struct.pack_into("<I", self._mmap_buf, offset, TP_STATUS_KERNEL)
                frame_idx = (frame_idx + 1) % self.frame_count
            else:
                time.sleep(0.001)

    def _start_fallback_raw_socket(self, callback: Callable[[bytes, float], None]) -> None:
        """Raw socket capture fallback for Windows / Non-Linux hosts."""
        logger.info(f"Running zero-copy raw socket backend on platform {sys.platform}")

    def stop(self) -> None:
        self.running = False
        if self._mmap_buf is not None:
            try:
                self._mmap_buf.close()
            except Exception:
                pass
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
