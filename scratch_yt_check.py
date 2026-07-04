import mysql.connector

conn = mysql.connector.connect(host='127.0.0.1', user='root', password='Prem@333', database='network_security')
cur = conn.cursor()

# 1. Check gvt1.com domains (Google Video Transcoder = YouTube CDN, often misclassified)
print("=== gvt1.com flows (YouTube CDN, possibly misclassified) ===")
cur.execute("""
    SELECT domain, application, COUNT(*) as cnt, SUM(byte_count) as bytes
    FROM flow_logs
    WHERE domain LIKE '%gvt1%' OR domain LIKE '%gvt2%'
    GROUP BY domain, application
    ORDER BY bytes DESC
""")
for r in cur.fetchall():
    print(f"  domain={str(r[0]):50s}  app={str(r[1]):15s}  flows={r[2]:>5}  bytes={r[3]:>12,}")

# 2. ALL QUIC traffic breakdown by domain
print("\n=== QUIC traffic breakdown by domain ===")
cur.execute("""
    SELECT COALESCE(domain, '(no domain)') as hostname, application,
           COUNT(*) as cnt, SUM(byte_count) as bytes
    FROM flow_logs
    WHERE application = 'QUIC'
    GROUP BY hostname, application
    ORDER BY bytes DESC
""")
for r in cur.fetchall():
    print(f"  host={str(r[0]):50s}  app={str(r[1]):10s}  flows={r[2]:>5}  bytes={r[3]:>12,}")

# 3. Total bytes per application
print("\n=== Total bytes per application ===")
cur.execute("""
    SELECT application, COUNT(*) as cnt, SUM(byte_count) as total_bytes,
           ROUND(SUM(byte_count)/1024/1024, 2) as mb
    FROM flow_logs
    GROUP BY application
    ORDER BY total_bytes DESC
""")
for r in cur.fetchall():
    print(f"  {str(r[0]):20s}  flows={r[1]:>6}  bytes={r[2]:>12,}  ({r[3]} MB)")

# 4. All YouTube + googlevideo + gvt1 flows combined
print("\n=== ALL YouTube-related traffic (googlevideo + gvt1 + youtube + yt) ===")
cur.execute("""
    SELECT COALESCE(domain, '(no domain)') as hostname, application,
           COUNT(*) as cnt, SUM(byte_count) as bytes
    FROM flow_logs
    WHERE domain LIKE '%youtube%'
       OR domain LIKE '%googlevideo%'
       OR domain LIKE '%gvt1%'
       OR domain LIKE '%gvt2%'
       OR domain LIKE '%ytimg%'
       OR domain LIKE '%yt3%'
       OR domain LIKE '%yt4%'
       OR application = 'YouTube'
    GROUP BY hostname, application
    ORDER BY bytes DESC
""")
total = 0
for r in cur.fetchall():
    total += r[3]
    print(f"  host={str(r[0]):50s}  app={str(r[1]):15s}  flows={r[2]:>5}  bytes={r[3]:>12,}")
print(f"\n  TOTAL YouTube-related: {total:,} bytes ({total/1024/1024:.2f} MB)")

# 5. Unresolved QUIC — no domain at all
print("\n=== Unresolved QUIC (no domain, no sni) — likely YouTube video streams ===")
cur.execute("""
    SELECT dst_ip, COUNT(*) as cnt, SUM(byte_count) as bytes
    FROM flow_logs
    WHERE application = 'QUIC'
      AND (domain IS NULL OR domain = '' OR domain = '-')
      AND (sni IS NULL OR sni = '' OR sni = '-')
    GROUP BY dst_ip
    ORDER BY bytes DESC
    LIMIT 15
""")
unresolved_total = 0
for r in cur.fetchall():
    unresolved_total += r[2]
    print(f"  dst_ip={str(r[0]):20s}  flows={r[1]:>5}  bytes={r[2]:>12,}")
print(f"\n  TOTAL unresolved QUIC: {unresolved_total:,} bytes ({unresolved_total/1024/1024:.2f} MB)")

# 6. Grand total of all captured bytes
print("\n=== Grand total of ALL captured traffic ===")
cur.execute("SELECT SUM(byte_count) FROM flow_logs")
grand = cur.fetchone()[0]
print(f"  {grand:,} bytes ({grand/1024/1024:.2f} MB)")

cur.close()
conn.close()
