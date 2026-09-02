import logging
import socket
from typing import Optional, Dict, Tuple

logger = logging.getLogger("netvisor.devices.enrichment")

# Comprehensive IEEE OUI Vendor Registry
IEEE_OUI_MAP: Dict[str, str] = {
    # Micro-Star International / PC Vendors
    "00:28:F8": "MSI (Micro-Star)",
    "00:14:22": "Dell Inc.",
    "18:66:DA": "Dell Inc.",
    "98:90:96": "Dell Inc.",
    "D4:BE:D9": "Dell Inc.",
    "EC:F4:BB": "Dell Inc.",
    "00:25:B3": "HP Inc.",
    "3C:D9:2B": "HP Inc.",
    "94:57:A5": "HP Inc.",
    "B4:B5:2F": "HP Inc.",
    "00:1E:67": "Intel Corporation",
    "34:02:86": "Intel Corporation",
    "70:B5:E8": "Intel Corporation",
    "A0:36:9F": "Intel Corporation",
    "F8:63:3F": "Intel Corporation",
    # Apple
    "00:03:93": "Apple Inc.",
    "00:05:02": "Apple Inc.",
    "00:0A:27": "Apple Inc.",
    "00:0D:93": "Apple Inc.",
    "00:10:FA": "Apple Inc.",
    "00:11:24": "Apple Inc.",
    "00:14:51": "Apple Inc.",
    "00:16:CB": "Apple Inc.",
    "00:17:F2": "Apple Inc.",
    "00:19:E3": "Apple Inc.",
    "00:1B:63": "Apple Inc.",
    "00:1C:B3": "Apple Inc.",
    "00:1D:4F": "Apple Inc.",
    "00:1E:52": "Apple Inc.",
    "00:1F:5B": "Apple Inc.",
    "00:1F:F3": "Apple Inc.",
    "00:21:E9": "Apple Inc.",
    "00:22:41": "Apple Inc.",
    "00:23:12": "Apple Inc.",
    "00:23:32": "Apple Inc.",
    "00:23:6C": "Apple Inc.",
    "00:23:DF": "Apple Inc.",
    "00:24:36": "Apple Inc.",
    "00:25:00": "Apple Inc.",
    "00:25:4B": "Apple Inc.",
    "00:26:08": "Apple Inc.",
    "00:26:4A": "Apple Inc.",
    "00:26:BB": "Apple Inc.",
    "3C:22:FB": "Apple Inc.",
    "84:38:35": "Apple Inc.",
    "A4:C3:F0": "Apple Inc.",
    "AC:BC:B3": "Apple Inc.",
    "BC:D2:4C": "Apple Inc.",
    "DC:A9:04": "Apple Inc.",
    "F0:18:98": "Apple Inc.",
    "F4:D4:88": "Apple Inc.",
    # Samsung
    "00:07:AB": "Samsung Electronics",
    "00:12:FB": "Samsung Electronics",
    "00:15:99": "Samsung Electronics",
    "00:18:AF": "Samsung Electronics",
    "00:1D:25": "Samsung Electronics",
    "2C:26:17": "Samsung Electronics",
    "5C:E0:C5": "Samsung Electronics",
    "84:25:DB": "Samsung Electronics",
    "EC:E0:9B": "Samsung Electronics",
    "F8:75:A4": "Samsung Electronics",
    # Google
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F8:8F:CA": "Google",
    # Virtualization
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "52:54:00": "QEMU / KVM",
    "08:00:27": "Oracle VirtualBox",
    # Network / IoT / Other
    "00:05:9A": "Cisco Systems",
    "00:1C:0E": "Cisco Systems",
    "FC:FB:FB": "Cisco Systems",
    "50:65:83": "Amazon Technologies",
    "A4:08:EA": "Amazon Technologies",
    "FC:A1:83": "Amazon Technologies",
    "50:C7:BF": "TP-Link",
    "AC:84:C6": "TP-Link",
    "E8:48:B8": "TP-Link",
    "28:6C:07": "Xiaomi",
    "54:EF:44": "Xiaomi",
    "C8:D7:B0": "Xiaomi",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:E0:4C": "Realtek Semiconductor",
    "00:08:9B": "QNAP Systems",
    "00:11:32": "Synology Inc.",
}

_DNS_CACHE: Dict[str, Optional[str]] = {}


class DeviceEnrichmentService:
    """Hardened device detection and identity enrichment service."""

    def resolve_mac_vendor(self, mac: Optional[str]) -> Tuple[Optional[str], Optional[str], bool]:
        """
        Resolves MAC vendor and device classification.
        Returns: (vendor, device_type, is_private_randomized_mac)
        """
        if not mac or mac == "-":
            return None, None, False

        clean = str(mac).replace("-", ":").upper().strip()
        parts = clean.split(":")
        if len(parts) < 3:
            return None, None, False

        try:
            first_byte = int(parts[0], 16)
        except ValueError:
            return None, None, False

        # IEEE 802 Local / Private Randomized MAC check (Bit 1 of Byte 0)
        if (first_byte & 0x02) != 0:
            return "Private / Randomized MAC", "Mobile/Private Device", True

        oui = ":".join(parts[:3])
        vendor = IEEE_OUI_MAP.get(oui)
        if vendor:
            device_type = "Managed Device" if "VMware" in vendor or "Hyper-V" in vendor or "Intel" in vendor or "Dell" in vendor or "MSI" in vendor or "HP" in vendor else "Network Endpoint"
            return vendor, device_type, False

        return "IEEE Hardware Device", "Network Asset", False

    def resolve_reverse_dns(self, ip: str) -> Optional[str]:
        """Resolves local IP reverse DNS PTR record with timeout and caching."""
        if not ip or ip == "127.0.0.1":
            return None

        if ip in _DNS_CACHE:
            return _DNS_CACHE[ip]

        hostname = None
        try:
            # Set quick socket timeout for LAN DNS lookups
            orig_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.5)
            try:
                name, _, _ = socket.gethostbyaddr(ip)
                if name and name != ip:
                    # Strip domain suffixes if present
                    hostname = name.split(".")[0].strip()
                    if hostname.lower() in {"localhost", "broadcasthost", "unknown"}:
                        hostname = None
            finally:
                socket.setdefaulttimeout(orig_timeout)
        except Exception:
            hostname = None

        _DNS_CACHE[ip] = hostname
        return hostname

    def infer_traffic_identity(self, db_conn, ip: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Inspects recent web events or flow telemetry for User-Agent, SNI domain names, or application signals.
        Returns: (inferred_hostname, os_family, device_type)
        """
        if not db_conn:
            return None, None, None

        cursor = db_conn.cursor(dictionary=True)
        try:
            # Inspect web_events for User-Agent clues
            cursor.execute(
                """
                SELECT user_agent, domain, process_name
                FROM web_events
                WHERE device_ip = %s
                ORDER BY timestamp DESC
                LIMIT 5
                """,
                (ip,),
            )
            rows = cursor.fetchall() or []
            for row in rows:
                ua = str(row.get("user_agent") or "").lower()
                domain = str(row.get("domain") or "").lower()
                if "android" in ua:
                    return None, "Android", "Mobile Device"
                if "iphone" in ua or "ipad" in ua or "cpu os" in ua:
                    return None, "iOS", "iPhone / iPad"
                if "windows nt" in ua or "win64" in ua:
                    return None, "Windows", "PC / Laptop"
                if "macintosh" in ua or "mac os x" in ua:
                    return None, "macOS", "MacBook / Mac"
                if "linux" in ua:
                    return None, "Linux", "Linux Host"

            return None, None, None
        except Exception as exc:
            logger.debug("Traffic identity inference notice for IP %s: %s", ip, exc)
            return None, None, None
        finally:
            cursor.close()

    def enrich_device(
        self,
        db_conn,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        os_family: Optional[str] = None,
    ) -> Dict[str, Optional[str]]:
        """
        Performs full identity enrichment for a device.
        """
        mac_vendor, mac_type, is_private = self.resolve_mac_vendor(mac)
        dns_hostname = self.resolve_reverse_dns(ip)
        _, traffic_os, traffic_type = self.infer_traffic_identity(db_conn, ip)

        final_hostname = hostname if hostname and hostname not in {"Unknown", "Unnamed Device", "-", ""} else dns_hostname
        final_vendor = vendor if vendor and vendor not in {"Unknown", "-"} else mac_vendor
        final_type = device_type if device_type and device_type not in {"Unknown", "Unknown Type", "-"} else (traffic_type or mac_type)
        final_os = os_family if os_family and os_family not in {"Unknown", "-"} else traffic_os

        return {
            "ip": ip,
            "mac": mac,
            "hostname": final_hostname or "Unknown",
            "vendor": final_vendor or ("Private / Randomized MAC" if is_private else "Unknown"),
            "device_type": final_type or ("Mobile/Private Device" if is_private else "Unknown"),
            "os_family": final_os or "Unknown",
            "is_private_mac": is_private,
        }

    def enrich_all_devices(self, db_conn) -> int:
        """
        Enriches all un-named or incomplete device records in MySQL database.
        """
        if not db_conn:
            return 0

        cursor = db_conn.cursor(dictionary=True)
        updated_count = 0
        try:
            cursor.execute("SELECT ip, mac, hostname, vendor, device_type, os_family FROM devices")
            devices = cursor.fetchall() or []

            update_cursor = db_conn.cursor()
            for dev in devices:
                ip = dev.get("ip")
                if not ip:
                    continue

                enriched = self.enrich_device(
                    db_conn,
                    ip=ip,
                    mac=dev.get("mac"),
                    hostname=dev.get("hostname"),
                    vendor=dev.get("vendor"),
                    device_type=dev.get("device_type"),
                    os_family=dev.get("os_family"),
                )

                h = enriched["hostname"]
                v = enriched["vendor"]
                dt = enriched["device_type"]
                os_fam = enriched["os_family"]

                if h != dev.get("hostname") or v != dev.get("vendor") or dt != dev.get("device_type") or os_fam != dev.get("os_family"):
                    update_cursor.execute(
                        """
                        UPDATE devices
                        SET hostname = %s, vendor = %s, device_type = %s, os_family = %s
                        WHERE ip = %s
                        """,
                        (h, v, dt, os_fam, ip),
                    )
                    update_cursor.execute(
                        """
                        UPDATE device_summary
                        SET hostname = %s, vendor = %s, device_type = %s, os_family = %s
                        WHERE ip = %s
                        """,
                        (h, v, dt, os_fam, ip),
                    )
                    updated_count += 1

            update_cursor.close()
            db_conn.commit()
            return updated_count
        except Exception as exc:
            db_conn.rollback()
            logger.error("Failed to enrich devices in DB: %s", exc, exc_info=True)
            return 0
        finally:
            cursor.close()


device_enrichment_service = DeviceEnrichmentService()
