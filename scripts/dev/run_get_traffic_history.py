import os
from dotenv import load_dotenv
load_dotenv()

from app.db.session import get_db_connection
from app.services.dashboard_service import dashboard_service

conn = get_db_connection()
try:
    res = dashboard_service.get_traffic_history(conn, resolution="second", window=60)
    print("Seconds resolution traffic history (last 5 items):")
    for r in res[-5:]:
        print(r)
    
    # check if any items have non-zero byte_count
    total_bytes = sum(r["byte_count"] for r in res)
    print(f"Total bytes in 60s window: {total_bytes}")
    
    # Let's check hour resolution
    res_hour = dashboard_service.get_traffic_history(conn, resolution="hour", window=24)
    print("\nHour resolution traffic history (last 5 items):")
    for r in res_hour[-5:]:
        print(r)
    total_bytes_hour = sum(r["byte_count"] for r in res_hour)
    print(f"Total bytes in 24h window: {total_bytes_hour}")
    
finally:
    conn.close()
