from __future__ import annotations

import os
import sys
import time
import argparse
import logging
import dpkt
from typing import Callable, Optional

logger = logging.getLogger("netvisor.packet_engine.pcap_replay")


class PCAPReplayer:
    """
    Offline PCAP / PCAPNG Replay Engine for NetVisor NDR.
    Reads binary trace files and streams frames through NetVisor's ingestion ring buffers
    at configurable speeds (realtime, scaled, or max throughput).
    """

    def __init__(self, pcap_path: str, speed_multiplier: float = 1.0) -> None:
        self.pcap_path = pcap_path
        self.speed_multiplier = speed_multiplier
        self.packets_replayed = 0
        self.bytes_replayed = 0

    def replay(self, packet_callback: Callable[[bytes, float], None]) -> int:
        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        with open(self.pcap_path, "rb") as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                try:
                    reader = dpkt.pcapng.Reader(f)
                except Exception as e:
                    logger.error(f"Failed to parse PCAP file {self.pcap_path}: {e}")
                    return 0

            first_pkt_ts: Optional[float] = None
            start_wall_clock: Optional[float] = None

            for ts, buf in reader:
                if first_pkt_ts is None:
                    first_pkt_ts = ts
                    start_wall_clock = time.time()

                # Calculate pacing delay if speed_multiplier > 0
                if self.speed_multiplier > 0 and start_wall_clock is not None:
                    pkt_elapsed = (ts - first_pkt_ts) / self.speed_multiplier
                    wall_elapsed = time.time() - start_wall_clock
                    sleep_needed = pkt_elapsed - wall_elapsed
                    if sleep_needed > 0.001:
                        time.sleep(sleep_needed)

                self.packets_replayed += 1
                self.bytes_replayed += len(buf)
                packet_callback(buf, ts)

        return self.packets_replayed


def main():
    parser = argparse.ArgumentParser(description="NetVisor PCAP Replay Framework")
    parser.add_argument("pcap_file", help="Path to input .pcap or .pcapng file")
    parser.add_argument("--speed", type=float, default=1.0, help="Replay speed multiplier (0 = fastest / offline)")
    args = parser.parse_args()

    replayer = PCAPReplayer(args.pcap_file, speed_multiplier=args.speed)

    def dummy_callback(raw_bytes: bytes, ts: float):
        pass

    count = replayer.replay(dummy_callback)
    print(f"Successfully replayed {count:,} packets ({replayer.bytes_replayed:,} bytes) from {args.pcap_file}")


if __name__ == "__main__":
    main()
