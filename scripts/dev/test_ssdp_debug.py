import json
from backend.engines.device.pipeline import DevicePipeline

fixture_data = {
  "name": "roku_ssdp",
  "input": {
    "ip": "192.168.1.55",
    "mac": "DC:A6:32:AA:BB:CC",
    "hostname": "Unknown",
    "ssdp_services": ["urn:schemas-upnp-org:device:MediaRenderer"],
    "ssdp_friendly_name": "Living Room Roku"
  }
}

pipeline = DevicePipeline()
profile = pipeline.run(fixture_data["input"])
print("Profile Device Type:", profile.device_type)
print("Profile Vendor:", profile.vendor)
print("Profile SSDP services:", fixture_data["input"].get("ssdp_services"))
print("Profile SSDP friendly name:", fixture_data["input"].get("ssdp_friendly_name"))

# Let's test the SSDP detector directly
from backend.engines.device.ssdp_detector import SSDPDetector
detector = SSDPDetector()
res = detector.analyze(
    fixture_data["input"].get("ssdp_services"),
    fixture_data["input"].get("ssdp_friendly_name")
)
print("SSDP Detector Direct Result:", res)
