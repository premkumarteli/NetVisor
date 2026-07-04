import os
import sys
import time
import asyncio
import subprocess
import httpx
from datetime import datetime, timezone

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tests.performance.synthetic_generator.generator import ReplayGenerator
from tests.performance.synthetic_generator.sender import ReplaySender
from tests.performance.synthetic_generator.collector import MetricsCollector
from tests.performance.synthetic_generator.monitor import ResourceMonitor
from tests.performance.synthetic_generator.writer import ResultWriter
from app.core.config import settings

# Test Configurations
AGENT_ID = "test-replay-agent"
KEY_VERSION = 1

def bootstrap_agent_db(sender: ReplaySender) -> str:
    print("Bootstrapping test agent in database...")
    from app.db.session import get_db_connection
    from app.services.agent_service import agent_service
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Resolve org ID
        cursor.execute("SELECT id FROM organizations LIMIT 1")
        row = cursor.fetchone()
        org_id = row[0] if row else "default-org-id"
        if not row:
            cursor.execute("INSERT INTO organizations (id, name) VALUES (%s, 'Default Organization')", (org_id,))
            
        # Clean existing test credentials and logs to avoid backpressure block
        cursor.execute("DELETE FROM agent_credentials WHERE agent_id = %s", (AGENT_ID,))
        cursor.execute("DELETE FROM agents WHERE id = %s", (AGENT_ID,))
        cursor.execute("DELETE FROM flow_ingest_batches")
        cursor.execute("DELETE FROM flow_logs")
        conn.commit()
        
        # Upsert agent
        agent_service.upsert_agent(
            conn,
            agent_id=AGENT_ID,
            organization_id=org_id,
            hostname="replay-host",
            ip_address="127.0.0.1",
            os_family="Windows",
            version="1.0.0",
            integrity_status="valid"
        )
        
        # Register credentials
        cursor.execute(
            """
            INSERT INTO agent_credentials (agent_id, key_version, secret_salt, secret_hash, status)
            VALUES (%s, %s, %s, %s, 'active')
            """,
            (AGENT_ID, KEY_VERSION, sender.secret_salt, sender.secret_hash)
        )
        conn.commit()
        print(f"Agent {AGENT_ID} successfully bootstrapped. Org: {org_id}")
        return org_id
    except Exception as e:
        conn.rollback()
        print(f"Failed agent bootstrap: {e}")
        sys.exit(1)
    finally:
        conn.close()

async def execute_generator(duration_seconds: int, flows_per_second: int, org_id: str, sender: ReplaySender, collector: MetricsCollector, monitor: ResourceMonitor):
    print(f"Starting Ingestion Load: {flows_per_second} flows/sec for {duration_seconds} seconds...")
    url = "http://127.0.0.1:8000/api/v1/collect/flow/batch"
    
    batch_size = 500
    batches_per_second = max(1, flows_per_second // batch_size)
    sleep_interval = 1.0 / batches_per_second
    
    generator = ReplayGenerator(AGENT_ID)
    start_time = time.time()
    
    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
    async with httpx.AsyncClient(limits=limits) as client:
        flow_index = 0
        total_sent = 0
        
        # Monitor sampling task
        async def background_monitoring():
            while time.time() - start_time < duration_seconds:
                monitor.sample()
                await asyncio.sleep(1.0)
                
        monitor_task = asyncio.create_task(background_monitoring())
        
        while time.time() - start_time < duration_seconds:
            loop_start = time.perf_counter()
            tasks = []
            
            for _ in range(batches_per_second):
                batch = generator.generate_flow_batch(batch_size, org_id, flow_index)
                tasks.append(sender.send_batch(client, batch, url))
                flow_index += batch_size
                total_sent += batch_size
                
            durations = await asyncio.gather(*tasks)
            for d in durations:
                collector.record_latency(d)
                
            elapsed = time.perf_counter() - loop_start
            sleep_time = max(0.0, sleep_interval - elapsed)
            await asyncio.sleep(sleep_time)
            
        await monitor_task
        return total_sent

def main():
    sender = ReplaySender(AGENT_ID, KEY_VERSION, settings.AGENT_MASTER_KEY)
    org_id = bootstrap_agent_db(sender)
    
    # 1. Start Uvicorn backend process
    print("Launching NetVisor Server in background...")
    cmd = [os.path.join(".venv", "Scripts", "python"), "-m", "uvicorn", "app.main:app", "--port", "8000"]
    env = os.environ.copy()
    env["MTLS_MODE"] = "disabled"
    env["NETVISOR_CHAOS_TESTING"] = "1"
    server_process = subprocess.Popen(cmd, env=env)
    
    # 2. Wait for server to bind port
    print("Waiting for server to become responsive...")
    time.sleep(5)
    
    collector = MetricsCollector()
    monitor = ResourceMonitor(server_process.pid)
    writer = ResultWriter("benchmarks")
    
    duration = 15
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
        
    start_time = time.time()
    try:
        total_sent = asyncio.run(execute_generator(
            duration_seconds=duration,
            flows_per_second=10000,
            org_id=org_id,
            sender=sender,
            collector=collector,
            monitor=monitor
        ))
        elapsed_seconds = time.time() - start_time
        
        # Calculate statistics
        stats = collector.compute_statistics(total_sent, elapsed_seconds)
        
        # Print summary to console
        print("\n=== Ingestion Workload Summary ===")
        print(f"Duration: {elapsed_seconds:.2f} seconds")
        print(f"Total Flows Transmitted: {stats['throughput'] * elapsed_seconds:,.0f}")
        print(f"Throughput Achieved: {stats['throughput']:.2f} flows/second")
        print(f"P50 Latency: {stats['p50_ms']:.2f} ms")
        print(f"P95 Latency: {stats['p95_ms']:.2f} ms")
        print(f"P99 Latency: {stats['p99_ms']:.2f} ms")
        print(f"Transmission Errors: {stats['error_count']}")
        
        # Save results and reports
        writer.write_time_series_csv(monitor.history)
        writer.generate_report(duration, stats, monitor.history)
        
    finally:
        print("Terminating backend server process...")
        server_process.terminate()
        server_process.wait()
        print("Server process shut down successfully.")

if __name__ == "__main__":
    main()
