import socket
from typing import Optional, Dict

class ActiveProber:
    COMMON_PORTS = {
        445: "Windows Device",
        22: "Linux/Unix Device",
        80: "Web Device",
        443: "Secure Web Device",
        7000: "Smart TV / AirPlay Device",
        8008: "Chromecast / Smart TV",
        8009: "Chromecast / Smart TV",
        8060: "Roku / Smart TV",
        9100: "Printer",
        502: "PLC / Industrial Device",
        3000: "Development / API Server"
    }

    def __init__(self, ports_dict: Dict[int, str] = None) -> None:
        self.ports = ports_dict if ports_dict is not None else self.COMMON_PORTS

    def probe(self, ip: str) -> str:
        if not ip or ip == "0.0.0.0" or ip == "127.0.0.1":
            return "Unknown"
        for port, device_type in self.ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                sock.connect((ip, port))
                sock.close()
                return device_type
            except Exception:
                continue
        return "Unknown"

