import os
from dotenv import load_dotenv
load_dotenv()

from app.db.session import get_db_connection

conn = get_db_connection()
cursor = conn.cursor(dictionary=True)
try:
    cursor.execute("SELECT DISTINCT organization_id FROM flow_logs")
    orgs = cursor.fetchall()
    print("Distinct Organization IDs in flow_logs:")
    for o in orgs:
        print(o)
        
    cursor.execute("SELECT DISTINCT organization_id FROM devices")
    d_orgs = cursor.fetchall()
    print("\nDistinct Organization IDs in devices:")
    for o in d_orgs:
        print(o)
finally:
    cursor.close()
    conn.close()
