"""
Network device discovery and inventory management.
"""

import ipaddress
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set

from agent.device_detector import DeviceDetector

logger = logging.getLogger(__name__)


class DeviceInventory:
    """Thread-safe device inventory with persistent storage."""
    
    def __init__(self, storage_file: Optional[Path] = None, runtime_dir: Optional[Path] = None):
        self.lock = threading.Lock()
        
        if runtime_dir:
            runtime_dir.mkdir(parents=True, exist_ok=True)
            
        self.storage_file = storage_file or (runtime_dir / "device_inventory.json" if runtime_dir else Path("device_inventory.json"))
        self.devices = {}
        self.load_inventory()
        
        # Start auto-save worker
        threading.Thread(target=self._auto_save_worker, daemon=True).start()
        
    def load_inventory(self) -> None:
        """Load device inventory from storage."""
        if self.storage_file.exists():
            try:
                with self.storage_file.open("r", encoding="utf-8") as f:
                    self.devices = json.load(f)
                    logger.info(f"Loaded {len(self.devices)} devices from inventory.")
            except Exception as e:
                logger.warning(f"Failed to load device inventory: {e}")
                
    def _auto_save_worker(self) -> None:
        """Background worker that periodically saves the inventory."""
        while True:
            time.sleep(30)
            self.save_inventory()
            
    def save_inventory(self) -> None:
        """Save device inventory to storage."""
        try:
            with self.lock:
                self.storage_file.parent.mkdir(parents=True, exist_ok=True)
                with self.storage_file.open("w", encoding="utf-8") as f:
                    json.dump(self.devices, f)
        except Exception as e:
            logger.warning(f"Failed to save device inventory: {e}")
            
    def update(self, ip: str, **kwargs) -> None:
        """Update device information for the given IP."""
        with self.lock:
            if ip not in self.devices:
                self.devices[ip] = {
                    "mac": "-",
                    "hostname": "Unknown",
                    "vendor": "Unknown",
                    "os": "Unknown",
                    "type": "Unknown",
                    "confidence": "low",
                    "last_seen": time.time()
                }
                
            # Update with new values
            for k, v in kwargs.items():
                if v and v not in ["Unknown", "-"]:
                    self.devices[ip][k] = v
                    
            self.devices[ip]["last_seen"] = time.time()
            
    def get(self, ip: str) -> Optional[Dict]:
        """Get device information for the given IP."""
        return self.devices.get(ip)
        
    def get_all_devices(self) -> Dict:
        """Get all devices."""
        with self.lock:
            return self.devices.copy()


class DiscoveryManager:
    """Manages network device discovery and synchronization."""
    
    def __init__(
        self,
        agent_id: str,
        organization_id: str,
        local_ip: str,
        device_detector: DeviceDetector,
        device_inventory: DeviceInventory,
        api_client,
        devices_url: str,
        discovery_interval: int = 60,
        max_workers: int = 5
    ):
        self.agent_id = agent_id
        self.organization_id = organization_id
        self.local_ip = local_ip
        self.device_detector = device_detector
        self.device_inventory = device_inventory
        self.api_client = api_client
        self.devices_url = devices_url
        self.discovery_interval = discovery_interval
        
        self.discovery_pool = ThreadPoolExecutor(max_workers=max_workers)
        self.is_running = True
        
        # OUI Vendor Cache
        self.vendor_cache = {
            "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", 
            "00:1C:14": "VMware", "08:00:27": "Oracle VirtualBox", 
            "00:15:5D": "Microsoft Hyper-V", "DC:A6": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi", "D8:3A:DD": "Ubiquiti", 
            "F0:9F:C2": "Ubiquiti", "00:11:32": "Synology"
        }
        
    def stop(self) -> None:
        """Stop the discovery manager."""
        self.is_running = False
        self.discovery_pool.shutdown(wait=True)
        
    def _infer_os_family(self, hostname: str, device_type: str) -> str:
        """Infer OS family from hostname and device type."""
        hostname_value = str(hostname or "").lower()
        device_type_value = str(device_type or "").lower()
        
        if "windows" in device_type_value or hostname_value.startswith(("desktop-", "laptop-", "win-", "msi-", "asus-")):
            return "Windows"
        if "linux" in device_type_value or "unix" in device_type_value:
            return "Linux"
        if "printer" in device_type_value:
            return "Embedded"
        if "synology" in hostname_value or "nas" in hostname_value:
            return "Linux"
        return "Unknown"
        
    def _resolve_vendor(self, mac: str) -> str:
        """Resolve vendor from MAC address using OUI cache."""
        if not mac or len(mac) < 8:
            return "Unknown"
        prefix = mac.upper().replace("-", ":")[:8]
        return self.vendor_cache.get(prefix, "Unknown")
        
    def _resolve_discovered_device(self, target: Tuple[str, str]) -> Tuple[Dict, str]:
        """Resolve detailed information for a discovered device (IP, MAC)."""
        ip, mac = target
        existing = self.device_inventory.get(ip) or {}
        
        # Resolve hostname if unknown
        hostname = existing.get("hostname")
        if hostname in {None, "", "Unknown", "Unknown-Device"}:
            hostname = self.device_detector.resolve_hostname(ip) or "Unknown"
            
        # Detect device type if unknown
        device_type = existing.get("type")
        if device_type in {None, "", "Unknown", "Unknown Type"}:
            device_type = self.device_detector.detect_device_type(ip)
        if device_type == "Unknown Type":
            device_type = "Unknown"
            
        vendor = self._resolve_vendor(mac)
        os_family = existing.get("os")
        if os_family in {None, "", "Unknown"}:
            os_family = self._infer_os_family(hostname, device_type)
            
        confidence = "high" if hostname != "Unknown" else "medium"
        
        payload = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": device_type,
            "os_family": os_family,
            "is_online": True,
            "organization_id": self.organization_id,
            "agent_id": self.agent_id,
        }
        
        return payload, confidence
        
    def _sync_discovered_devices(self, devices: List[Dict]) -> None:
        """Sync discovered devices to the backend server."""
        if not devices:
            return
            
        try:
            logger.debug(f"Syncing {len(devices)} discovered devices...")
            response = self.api_client.request("POST", self.devices_url, json_body=devices, timeout=10)
            if response.status_code != 200:
                logger.error(f"Device sync failed: {response.status_code} - {response.text}")
            response.raise_for_status()
            logger.debug(f"Successfully synced {len(devices)} devices")
        except Exception as exc:
            logger.warning(f"Discovered device sync failed: {exc}")
            
    def discovery_engine(self) -> None:
        """Main discovery loop running in a separate thread."""
        local_network = self.device_detector.infer_local_network(self.local_ip)
        if local_network:
            self.device_detector.set_network(local_network)
            logger.info(f"Discovery network set to {local_network}")
        else:
            logger.warning("Unable to infer local network for ARP discovery; falling back to passive ARP cache only.")
            
        while self.is_running:
            try:
                # Collect ARP candidates
                arp_data = self.device_detector.collect_arp_candidates(local_network)
                candidates = []
                
                for ip, mac in arp_data.items():
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            continue
                    except Exception:
                        continue
                    if ip == self.local_ip:
                        continue
                    candidates.append((ip, mac))
                    
                # Resolve devices in parallel
                futures = {self.discovery_pool.submit(self._resolve_discovered_device, c): c for c in candidates}
                
                for future in as_completed(futures):
                    try:
                        payload, confidence = future.result()
                        
                        # Update local inventory
                        self.device_inventory.update(
                            payload["ip"],
                            mac=payload["mac"],
                            hostname=payload["hostname"],
                            vendor=payload["vendor"],
                            type=payload["device_type"],
                            os=payload["os_family"],
                            confidence=confidence,
                        )
                        
                        # Sync to backend
                        self._sync_discovered_devices([payload])
                        
                    except Exception as exc:
                        logger.warning(f"Failed to resolve device: {exc}")
                        
            except Exception as exc:
                logger.warning(f"Discovery cycle failed: {exc}")
                
            time.sleep(self.discovery_interval)
