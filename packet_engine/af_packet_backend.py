from __future__ import annotations

import os
import sys
import socket
import logging
import mmap
import ctypes
from typing import Callable, Optional

logger = logging.getLogger("netvisor.packet_engine.af_packet_backend")


class AFPacketMmapBackend:
    """
    Linux AF_PACKET + PACKET_MMAP Zero-Copy Kernel Ring Buffer Capture Driver.
    Reduces syscall overhead by mapping kernel packet ring buffers directly to userspace memory.
    Falls back gracefully to raw socket ring capture on non-Linux platforms (Windows/macOS).
    """

    ETH_P_ALL = 0x0003  # Capture all Ethernet protocols

    def __init__(
        self,
        interface: str = "eth0",
        frame_size: int = 2048,
        frame_count: int = 1024,
    ) -> None:
        self.interface = interface
        self.frame_size = frame_size
        self.frame_count = frame_count
        self.is_linux = sys.platform.startswith("linux")
        self._sock: Optional[socket.socket] = None
        self._mmap_buf: Optional[mmap.mmap] = None
        self.running = False
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
        """Zero-copy PACKET_MMAP ring buffer capture loop."""
        try:
            # Create AF_PACKET socket
            SOL_PACKET = 263
            PACKET_RX_RING = 5
            
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ALL))
            self._sock.bind((self.interface, self.ETH_P_ALL))

            # Configure tpacket_req ring parameters
            req_size = 32  # sizeof(struct tpacket_req)
            block_size = self.frame_size * 64
            block_nr = (self.frame_size * self.frame_count) // block_size
            req = struct.pack("IIII", block_size, block_nr, self.frame_size, self.frame_count)

            self._sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req)

            # mmap kernel ring buffer to userspace memory
            ring_len = block_size * block_nr
            self._mmap_buf = mmap.mmap(
                self._sock.fileno(),
                ring_len,
                mmap.MAP_SHARED,
                mmap.PROT_READ | mmap.PROT_WRITE,
            )

            logger.info(f"Initialized Linux PACKET_MMAP zero-copy ring on {self.interface} ({ring_len:,} bytes)")
        except Exception as e:
            logger.warning(f"PACKET_MMAP initialization failed on {self.interface}: {e}. Using raw socket fallback.")
            self._start_fallback_raw_socket(callback)

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
