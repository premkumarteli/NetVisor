import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess
import time
import urllib.request
import xml.etree.ElementTree as ET

import psutil
from scapy.all import ARP, Ether, srp
import logging

logger = logging.getLogger(__name__)

OUI_VENDOR_PREFIXES = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "00:1C:14": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "D8:3A:DD": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
    "00:11:32": "Synology",
    "06:C9:80": "OPPO / Android",
    "24:A1:60": "OPPO / Android",
    "48:74:6E": "OPPO / Android",
    "80:35:C1": "OPPO / Android",
    "A4:83:E7": "OPPO / Android",
    "B0:19:21": "OPPO / Android",
    "F4:1A:9C": "OPPO / Android",
    "28:6A:BA": "Apple",
    "3C:22:FB": "Apple",
    "7C:D1:C3": "Apple",
    "A4:C3:F0": "Apple",
    "F0:18:98": "Apple",
    "18:65:90": "Samsung",
    "34:23:BA": "Samsung",
    "5C:F6:DC": "Samsung",
    "A0:21:B7": "Samsung",
    "D0:17:C2": "Samsung",
    "64:CC:2E": "Xiaomi",
    "78:02:F8": "Xiaomi",
    "A4:50:46": "Xiaomi",
    "C8:3A:35": "Xiaomi",
    "F8:A4:5F": "Xiaomi",
}

MOBILE_VENDOR_MARKERS = {"android", "oppo", "samsung", "xiaomi", "redmi", "oneplus", "vivo", "realme", "apple"}
HOSTNAME_TYPE_HINTS = {
    "iphone": "Mobile Phone",
    "ipad": "Tablet",
    "android": "Mobile Phone",
    "oppo": "Mobile Phone",
    "reno": "Mobile Phone",
    "samsung": "Mobile Phone",
    "galaxy": "Mobile Phone",
    "redmi": "Mobile Phone",
    "xiaomi": "Mobile Phone",
    "oneplus": "Mobile Phone",
    "vivo": "Mobile Phone",
    "realme": "Mobile Phone",
    "printer": "Printer",
    "chromecast": "Chromecast / Smart TV",
    "roku": "Roku / Smart TV",
    "tv": "Smart TV",
    "desktop": "Windows Device",
    "laptop": "Laptop",
    "raspberry": "Linux/IoT Device",
    "synology": "NAS / Storage",
}


class DeviceDetector:
    def __init__(self, network=None, local_ip=None):
        self.network = network
        self.local_ip = local_ip
        self._upnp_cache = {"expires_at": 0.0, "locations_by_ip": {}}

    def set_network(self, network):
        self.network = network

    def infer_local_network(self, local_ip=None):
        ip_value = local_ip or self.local_ip
        if not ip_value:
            return None

        try:
            target_ip = ipaddress.ip_address(ip_value)
        except ValueError:
            return None

        try:
            for addresses in psutil.net_if_addrs().values():
                for addr in addresses:
                    if addr.family != socket.AF_INET or addr.address != ip_value:
                        continue
                    if addr.netmask:
                        interface = ipaddress.ip_interface(f"{ip_value}/{addr.netmask}")
                        return str(interface.network)
        except Exception as e:
            logger.debug("Exception: %s", e)

        if isinstance(target_ip, ipaddress.IPv4Address) and target_ip.is_private:
            return str(ipaddress.ip_network(f"{ip_value}/24", strict=False))
        return None

    def arp_scan(self, network=None):
        target_network = network or self.network
        if not target_network:
            return []
        print(f"\n[+] Scanning network: {target_network}")
        devices = []
        try:
            arp = ARP(pdst=target_network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=2, retry=1, verbose=0)[0]

            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc.lower()
                if self._is_candidate_device(ip, mac):
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                    })
        except Exception as e:
            print(f"[-] Error during ARP scan: {e}")

        return devices

    def parse_arp_table(self):
        """Parses the local system's ARP table (Windows/Linux)."""
        arp_results = {}
        try:
            output = subprocess.check_output(["arp", "-a"], stderr=subprocess.STDOUT).decode(errors="ignore")
            pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{17})")

            for line in output.splitlines():
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    if self._is_unicast_entry(ip, mac):
                        arp_results[ip] = mac
        except Exception as e:
            print(f"[-] Error parsing ARP table: {e}")

        return arp_results

    def _is_unicast_entry(self, ip, mac):
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        if ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_reserved:
            return False

        if mac.lower() == "ff:ff:ff:ff:ff:ff":
            return False

        if isinstance(ip_obj, ipaddress.IPv4Address):
            octets = ip.split(".")
            if octets[-1] == "255":
                return False

        return True

    def _is_candidate_device(self, ip, mac):
        if not self._is_unicast_entry(ip, mac):
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        if not ip_obj.is_private:
            return False

        if self.local_ip and ip == self.local_ip:
            return False

        return True

    def collect_arp_candidates(self, network=None):
        target_network = network or self.network
        discovered = {}

        for ip, mac in self.parse_arp_table().items():
            if self._is_candidate_device(ip, mac):
                discovered[ip] = mac

        for device in self.arp_scan(target_network):
            ip = device.get("ip")
            mac = device.get("mac", "").lower()
            if self._is_candidate_device(ip, mac):
                discovered[ip] = mac

        return discovered

    def get_netbios_name(self, ip):
        netbios_query = (
            b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)

        try:
            sock.sendto(netbios_query, (ip, 137))
            data, _ = sock.recvfrom(1024)

            if len(data) > 57:
                num_names = data[56]
                offset = 57

                for _ in range(num_names):
                    name = data[offset:offset+15].decode(errors="ignore").strip()
                    if name and name != "*":
                        return self._normalize_hostname(name, ip)
                    offset += 18
        except Exception as e:
            logger.debug("Exception: %s", e)
        finally:
            sock.close()

        return None

    def get_dns_name(self, ip):
        try:
            return self._normalize_hostname(socket.gethostbyaddr(ip)[0], ip)
        except Exception as e:
            logger.debug("Probe failed: %s", e)
            return None

    def get_nbtstat_name(self, ip):
        if platform.system().lower() != "windows":
            return None

        try:
            output = subprocess.check_output(
                ["nbtstat", "-A", ip],
                stderr=subprocess.STDOUT,
                timeout=0.5,
            ).decode(errors="ignore")
        except Exception as e:
            logger.debug("Probe failed: %s", e)
            return None

        for line in output.splitlines():
            match = re.search(r"^\s*([^\s<].*?)\s+<00>\s+UNIQUE\s+Registered", line, re.IGNORECASE)
            if match:
                return self._normalize_hostname(match.group(1), ip)
        return None

    def get_ping_name(self, ip):
        system_name = platform.system().lower()
        if system_name == "windows":
            command = ["ping", "-a", "-n", "1", "-w", "500", ip]
        else:
            command = ["ping", "-c", "1", "-W", "1", ip]

        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,
                timeout=0.6,
            ).decode(errors="ignore")
        except Exception as e:
            logger.debug("Probe failed: %s", e)
            return None

        return self._parse_ping_hostname(output, ip)

    def _http_get_text(self, url, timeout=1.5):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                return response.read().decode(charset, errors="ignore")
        except Exception as e:
            logger.debug("Probe failed: %s", e)
            return None

    def _extract_xml_name(self, xml_text, ip=None):
        if not xml_text:
            return None
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None

        candidate_tags = {
            "friendlyname",
            "user-device-name",
            "friendly-device-name",
            "devicename",
            "modelname",
        }
        for element in root.iter():
            tag_name = element.tag.split("}", 1)[-1].strip().lower()
            if tag_name not in candidate_tags:
                continue
            normalized = self._normalize_hostname(element.text, ip)
            if normalized:
                return normalized
        return None

    def get_roku_name(self, ip):
        xml_text = self._http_get_text(f"http://{ip}:8060/query/device-info", timeout=0.5)
        return self._extract_xml_name(xml_text, ip)

    def get_chromecast_name(self, ip):
        payload = self._http_get_text(f"http://{ip}:8008/setup/eureka_info?options=detail", timeout=0.5)
        if not payload:
            return None
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None

        for candidate in (
            data.get("name"),
            data.get("device_info", {}).get("name") if isinstance(data.get("device_info"), dict) else None,
            data.get("device_info", {}).get("public_device_name") if isinstance(data.get("device_info"), dict) else None,
        ):
            normalized = self._normalize_hostname(candidate, ip)
            if normalized:
                return normalized
        return None

    def _parse_ssdp_location(self, response_text):
        if not response_text:
            return None
        for line in response_text.splitlines():
            if ":" not in line:
                continue
            header, value = line.split(":", 1)
            if header.strip().lower() == "location":
                return value.strip()
        return None

    def _discover_upnp_locations(self):
        now = time.monotonic()
        if now < self._upnp_cache["expires_at"]:
            return self._upnp_cache["locations_by_ip"]

        discovery = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n"
        ).encode("ascii")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(0.35)
        locations_by_ip = {}
        try:
            try:
                sock.sendto(discovery, ("239.255.255.250", 1900))
            except Exception as e:
                logger.debug("Probe failed: %s", e)
                return {}

            while True:
                try:
                    data, address = sock.recvfrom(2048)
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug("Probe failed: %s", e)
                    return {}

                location = self._parse_ssdp_location(data.decode(errors="ignore"))
                if not location:
                    continue
                ip_locations = locations_by_ip.setdefault(address[0], [])
                if location not in ip_locations:
                    ip_locations.append(location)
        finally:
            sock.close()

        self._upnp_cache = {
            "expires_at": now + 30.0,
            "locations_by_ip": locations_by_ip,
        }
        return locations_by_ip

    def get_upnp_name(self, ip):
        locations = self._discover_upnp_locations().get(ip, [])
        for location in locations[:3]:
            xml_text = self._http_get_text(location, timeout=0.5)
            name = self._extract_xml_name(xml_text, ip)
            if name:
                return name

        return None

    def resolve_hostname(self, ip):
        for resolver in (
            self.get_dns_name,
            self.get_netbios_name,
            self.get_nbtstat_name,
            self.get_ping_name,
            self.get_roku_name,
            self.get_chromecast_name,
            self.get_upnp_name,
        ):
            name = resolver(ip)
            if name:
                return name
        return None

    def _parse_ping_hostname(self, output, ip):
        patterns = (
            rf"Pinging\s+(.+?)\s+\[{re.escape(ip)}\]",
            rf"PING\s+(.+?)\s+\({re.escape(ip)}\)",
        )
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return self._normalize_hostname(match.group(1), ip)
        return None

    def _normalize_hostname(self, hostname, ip=None):
        if not hostname:
            return None

        cleaned = str(hostname).strip().strip(".")
        if not cleaned or cleaned in {"*", "Unknown", "Unknown-Device"}:
            return None

        if ip and cleaned == ip:
            return None

        if re.fullmatch(r"\d{1,3}(?:[-.]\d{1,3}){3}", cleaned):
            return None

        if cleaned.lower().endswith(".local"):
            cleaned = cleaned[:-6]

        return cleaned or None

    def detect_device_type(self, ip):
        common_ports = {
            445: "Windows Device",
            22: "Linux/Unix Device",
            80: "Web Device",
            443: "Secure Web Device",
            7000: "Smart TV / AirPlay Device",
            8008: "Chromecast / Smart TV",
            8009: "Chromecast / Smart TV",
            8060: "Roku / Smart TV",
            9100: "Printer",
            502: "PLC / Industrial Device"
        }

        for port, device_type in common_ports.items():
            try:
                sock = socket.socket()
                sock.settimeout(0.3)
                sock.connect((ip, port))
                sock.close()
                return device_type
            except Exception as e:
                logger.debug("Exception: %s", e)
                continue

        return "Unknown Type"

    def resolve_vendor(self, mac):
        if not mac:
            return "Unknown"

        normalized = str(mac).replace("-", ":").upper()
        parts = [part for part in normalized.split(":") if part]
        if len(parts) < 3:
            return "Unknown"

        prefix = ":".join(parts[:3])
        return OUI_VENDOR_PREFIXES.get(prefix, "Unknown")

    def infer_device_type(self, ip, mac=None, hostname=None, active_probe=True):
        normalized_hostname = str(hostname or "").strip().lower()
        for marker, device_type in HOSTNAME_TYPE_HINTS.items():
            if marker in normalized_hostname:
                return device_type

        vendor = self.resolve_vendor(mac)
        vendor_lower = vendor.lower()
        if any(marker in vendor_lower for marker in MOBILE_VENDOR_MARKERS):
            return "Mobile Phone"
        if "vmware" in vendor_lower or "virtualbox" in vendor_lower or "hyper-v" in vendor_lower:
            return "Virtual Machine"
        if "raspberry" in vendor_lower:
            return "Linux/IoT Device"
        if "synology" in vendor_lower:
            return "NAS / Storage"

        if not active_probe:
            return "Unknown"

        detected = self.detect_device_type(ip)
        return "Unknown" if detected == "Unknown Type" else detected

    def identity_confidence(self, *, hostname=None, mac=None, vendor=None, device_type=None):
        score = 0
        if self._normalize_hostname(hostname):
            score += 2
        if mac and self._is_unicast_entry("192.168.0.1", str(mac).replace("-", ":")):
            score += 1
        if vendor and vendor != "Unknown":
            score += 1
        if device_type and device_type not in {"Unknown", "Unknown Type"}:
            score += 1

        if score >= 4:
            return "high"
        if score >= 2:
            return "medium"
        return "low"

    def detect_virtual_mac(self, mac):
        first_octet = int(mac.split(":")[0], 16)
        if first_octet & 2:
            return " (Locally Administered / Virtual)"
        return ""

    def full_scan(self, network=None):
        devices = [
            {"ip": ip, "mac": mac}
            for ip, mac in self.collect_arp_candidates(network).items()
        ]
        final_results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {}

            for device in devices:
                futures[executor.submit(self.resolve_device, device)] = device

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                final_results.append(result)

        return final_results

    def resolve_device(self, device):
        ip = device["ip"]
        mac = device["mac"]

        name = self.resolve_hostname(ip)
        if not name:
            name = "Unknown-Device"

        device_type = self.detect_device_type(ip)
        mac_note = self.detect_virtual_mac(mac)

        return {
            "name": name,
            "ip": ip,
            "mac": mac + mac_note,
            "type": device_type
        }


def device_compatibility_wrapper(ip: str, mac: str | None = None, hostname: str | None = None, active_probe: bool = True) -> "EngineResult":
    from engine import EngineResult, Finding, Severity
    detector = DeviceDetector()
    resolved_hostname = hostname or detector.resolve_hostname(ip) or "Unknown"
    vendor = detector.resolve_vendor(mac)
    device_type = detector.infer_device_type(ip, mac=mac, hostname=resolved_hostname, active_probe=active_probe)
    confidence_level = detector.identity_confidence(
        hostname=resolved_hostname,
        mac=mac,
        vendor=vendor,
        device_type=device_type
    )
    
    # Map confidence level ("high", "medium", "low") to a numeric float
    confidence_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
    confidence_val = confidence_map.get(confidence_level, 0.5)
    
    evidence = []
    if mac:
        evidence.append("MAC Address presence")
    if vendor != "Unknown":
        evidence.append(f"Vendor OUI match: {vendor}")
    if resolved_hostname != "Unknown":
        evidence.append(f"Hostname resolved: {resolved_hostname}")
    if device_type != "Unknown Type" and device_type != "Unknown":
        evidence.append(f"Device type inferred: {device_type}")
        
    findings = [
        Finding(
            engine="device",
            finding_type="device_profiled",
            severity=Severity.INFO,
            confidence=confidence_val,
            evidence=evidence,
            target_ip=ip,
            target_mac=mac,
            details={
                "hostname": resolved_hostname,
                "vendor": vendor,
                "device_type": device_type,
                "confidence_level": confidence_level
            }
        )
    ]
    return EngineResult(findings=findings, metadata={"device_type": device_type, "confidence": confidence_level})


if __name__ == "__main__":
    network_range = input("Enter network range (e.g., 192.168.1.0/24): ").strip()

    scanner = DeviceDetector(network_range)
    results = scanner.full_scan()

    print("\n" + "-" * 90)
    print(f"{'NAME':<25} | {'IP ADDRESS':<15} | {'MAC ADDRESS':<30} | {'TYPE'}")
    print("-" * 90)

    for dev in results:
        print(f"{dev['name']:<25} | {dev['ip']:<15} | {dev['mac']:<30} | {dev['type']}")

    print("-" * 90)
    print(f"\nTotal Devices Found: {len(results)}")
