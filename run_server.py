import argparse
import asyncio
import json
import os
import socket
import threading
import time

import uvicorn
from dotenv import load_dotenv
import requests


def perform_health_check() -> int:
    previous_shutdown_setting = os.getenv("NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN")
    os.environ["NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN"] = "false"
    server = None
    server_thread = None
    try:
        from backend.main import app

        probe_port = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            probe_port = int(sock.getsockname()[1])

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=probe_port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()

        base_url = f"http://127.0.0.1:{probe_port}"
        ping_response = None
        ready_response = None
        status_response = None
        deadline = time.time() + 30
        while time.time() < deadline:
            if not server_thread.is_alive():
                break
            try:
                ping_response = requests.get(f"{base_url}/ping", timeout=2)
                ready_response = requests.get(f"{base_url}/api/v1/health/ready", timeout=2)
                if ping_response.status_code == 200 and ready_response.status_code == 200:
                    break
            except Exception as e:
                print(f"Startup probe failed: {e}")
                time.sleep(1)
        if not ping_response or not ready_response:
            raise RuntimeError("Server did not become healthy in time.")

        status_response = requests.get(f"{base_url}/api/v1/health/status", timeout=10)

        payload = {
            "ping": ping_response.json() if ping_response.status_code == 200 else {"error": ping_response.text},
            "ready": ready_response.json() if ready_response.status_code == 200 else {"error": ready_response.text},
            "status": status_response.json() if status_response.status_code == 200 else {"error": status_response.text},
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        if ping_response.status_code != 200 or ready_response.status_code != 200 or status_response.status_code != 200:
            return 1
        return 0
    finally:
        if server is not None:
            server.should_exit = True
        if server_thread is not None and server_thread.is_alive():
            server_thread.join(timeout=1)
        if previous_shutdown_setting is None:
            os.environ.pop("NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN", None)
        else:
            os.environ["NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN"] = previous_shutdown_setting

def cleanup_runtime_on_process_exit():
    if os.getenv("NETVISOR_RELOAD", "false").lower() == "true":
        return

    try:
        from backend.db.session import get_db_connection
        from backend.services.system_service import system_service

        conn = get_db_connection()
        try:
            # Unconditionally dump all tables to db_dump on process exit
            system_service.export_all_tables_to_db_dump(conn)
            print("[*] Full database export to db_dump completed successfully.")

            # Clear runtime data if backup and reset on shutdown is enabled
            if os.getenv("NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN", "true").lower() == "true":
                result = system_service.backup_and_reset_runtime_data(conn, reason="process_exit")
                print(f"[*] Process-exit runtime cleanup: {result['message']}")
        finally:
            conn.close()
    except Exception as exc:
        print(f"[!] Process-exit runtime cleanup failed: {exc}")

def get_local_ip():
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        if s is not None:
            s.close()
    return IP

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetVisor Server")
    parser.add_argument("--health-check", action="store_true", help="Print a startup health snapshot and exit.")
    args, _remaining = parser.parse_known_args()
    load_dotenv()

    if args.health_check:
        raise SystemExit(perform_health_check())

    local_ip = get_local_ip()
    public_hostname = os.getenv("NETVISOR_PUBLIC_HOSTNAME") or os.getenv("PUBLIC_HOSTNAME")
    reload_enabled = os.getenv("NETVISOR_RELOAD", "false").lower() == "true"
    trust_proxy_headers = os.getenv("NETVISOR_TRUST_PROXY_HEADERS", "false").lower() == "true"
    forwarded_allow_ips = os.getenv("NETVISOR_FORWARDED_ALLOW_IPS", "127.0.0.1")
    workers_env = os.getenv("NETVISOR_WORKERS")
    workers_count = int(workers_env) if workers_env and workers_env.isdigit() else 1
    if reload_enabled:
        workers_count = 1

    limit_concurrency = int(os.getenv("NETVISOR_LIMIT_CONCURRENCY", "1000"))
    backlog = int(os.getenv("NETVISOR_SERVER_BACKLOG", "2048"))
    timeout_keep_alive = int(os.getenv("NETVISOR_TIMEOUT_KEEP_ALIVE", "30"))

    print("[*] Netvisor Server Starting...")
    print("[*] Local Access:   http://127.0.0.1:8000")
    print(f"[*] Network Access: http://{local_ip}:8000")
    print(f"[*] Auto Reload:    {'enabled' if reload_enabled else 'disabled'}")
    print(f"[*] Workers:        {workers_count}")
    if public_hostname:
        print(f"[*] Public Host:    https://{public_hostname}")
    print(f"[*] Proxy Headers:  {'enabled' if trust_proxy_headers else 'disabled'}")
    try:
        uvicorn.run(
            "backend.main:app",
            host="0.0.0.0",
            port=8000,
            reload=reload_enabled,
            workers=workers_count if not reload_enabled else None,
            proxy_headers=trust_proxy_headers,
            forwarded_allow_ips=forwarded_allow_ips,
            limit_concurrency=limit_concurrency,
            backlog=backlog,
            timeout_keep_alive=timeout_keep_alive,
            http="auto",
            loop="auto",
        )
    finally:
        cleanup_runtime_on_process_exit()
