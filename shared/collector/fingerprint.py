import hashlib
import platform
import uuid
import psutil
from pathlib import Path

_cached_fingerprints: dict[str, str] = {}

def _get_machine_id() -> str:
    """Get stable machine ID, primarily on Linux."""
    if platform.system() == "Linux":
        try:
            return Path("/etc/machine-id").read_text(encoding="utf-8").strip()
        except Exception:
            pass
    # For Windows or fallback, use empty string.
    # We avoid reading OS serials to prevent permission issues.
    return ""

def _get_sorted_macs() -> str:
    """Get sorted list of MAC addresses."""
    macs = set()
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                mac = str(addr.address).lower().replace("-", ":")
                if len(mac) == 17 and mac.count(":") == 5:
                    if mac != "00:00:00:00:00:00" and not mac.startswith("02:42:ac"): # ignore typical docker prefixes if possible, but keep simple
                        macs.add(mac)
    except Exception:
        pass
        
    if not macs:
        # Fallback to uuid.getnode()
        try:
            node = uuid.getnode()
            mac = ":".join(f"{(node >> shift) & 0xff:02x}" for shift in range(40, -1, -8))
            macs.add(mac)
        except Exception:
            macs.add("00:00:00:00:00:00")
            
    return ",".join(sorted(list(macs)))

def compute_machine_fingerprint(org_id: str) -> str:
    """Compute a stable machine fingerprint for duplicate detection."""
    normalized_org_id = str(org_id or "").strip()
    if normalized_org_id in _cached_fingerprints:
        return _cached_fingerprints[normalized_org_id]
        
    hostname = platform.node().lower()
    macs = _get_sorted_macs()
    machine_id = _get_machine_id()
    
    # Compute SHA256(org_id + hostname + sorted_macs + machine_id)
    material = f"{normalized_org_id}|{hostname}|{macs}|{machine_id}"
    fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()
    _cached_fingerprints[normalized_org_id] = fingerprint
    
    return fingerprint
