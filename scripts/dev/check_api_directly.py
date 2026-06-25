import os
from dotenv import load_dotenv
load_dotenv()

from fastapi.testclient import TestClient
from app.main import app
from app.core.dependencies import require_org_admin, get_current_user

# Get the inner FastAPI app
fastapi_app = app.other_asgi_app

client = TestClient(fastapi_app)

fastapi_app.dependency_overrides[get_current_user] = lambda: {"organization_id": "default-org-id", "role": "org_admin", "username": "admin"}
fastapi_app.dependency_overrides[require_org_admin] = lambda: {"organization_id": "default-org-id", "role": "org_admin", "username": "admin"}

print("Querying traffic-history with resolution=second:")
res = client.get("/api/v1/dashboard/traffic-history", params={"resolution": "second", "window": 60})
print(f"Status code: {res.status_code}")
data = res.json()
print("Response length:", len(data))
print("First 3 items:")
for item in data[:3]:
    print(item)
print("Last 3 items:")
for item in data[-3:]:
    print(item)
total_bytes = sum(item["byte_count"] for item in data)
print("Total bytes in 60s window:", total_bytes)

print("\nQuerying traffic-history with resolution=hour:")
res_hour = client.get("/api/v1/dashboard/traffic-history", params={"resolution": "hour", "window": 24})
print(f"Status: {res_hour.status_code}")
data_hour = res_hour.json()
print("Response length (hour):", len(data_hour))
print("Total bytes in 24h window (hour):", sum(item["byte_count"] for item in data_hour))
