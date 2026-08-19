import os
from dotenv import load_dotenv
load_dotenv()

from backend.db.session import get_db_connection
import datetime

conn = get_db_connection()
cursor = conn.cursor(dictionary=True)
try:
    cursor.execute("SELECT UTC_TIMESTAMP() as db_utc, NOW() as db_now, @@global.time_zone as global_tz, @@session.time_zone as session_tz")
    db_time = cursor.fetchone()
    print("Database Time Info:")
    print(db_time)
    
    py_utc = datetime.datetime.now(datetime.timezone.utc)
    py_naive = datetime.datetime.now()
    print(f"Python UTC: {py_utc}")
    print(f"Python Naive (Local): {py_naive}")
    
    cursor.execute("SELECT COUNT(*) as cnt, MIN(last_seen) as min_seen, MAX(last_seen) as max_seen FROM flow_logs")
    flows = cursor.fetchone()
    print("Flow Logs Info:")
    print(flows)
    
    cursor.execute("SELECT last_seen, byte_count, application, domain FROM flow_logs ORDER BY last_seen DESC LIMIT 10")
    recent = cursor.fetchall()
    print("Recent 10 Flow Logs:")
    for r in recent:
        print(r)
        
finally:
    cursor.close()
    conn.close()
