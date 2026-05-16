import sys
import os
import mysql.connector
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from app.core.config import settings

def apply_migration():
    print("[*] Applying Phase 2 Config & Telemetry Migration...")
    try:
        conn = mysql.connector.connect(
            host=settings.DB_HOST,
            user=settings.DB_USER,
            password=settings.DB_PASSWORD,
            database=settings.DB_NAME,
        )
        cursor = conn.cursor()
        
        print("[+] Creating agent_configs table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_configs (
            agent_id VARCHAR(100) PRIMARY KEY,
            organization_id CHAR(36),
            capture_backend VARCHAR(50) DEFAULT 'auto',
            promiscuous_mode BOOLEAN DEFAULT TRUE,
            flow_flush_interval_seconds INT DEFAULT 60,
            max_buffer_mb INT DEFAULT 500,
            telemetry_enabled BOOLEAN DEFAULT TRUE,
            telemetry_interval_seconds INT DEFAULT 60,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        );
        """)
        
        print("[+] Creating telemetry_logs table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            agent_id VARCHAR(100) NOT NULL,
            organization_id CHAR(36),
            log_level VARCHAR(20) DEFAULT 'INFO',
            category VARCHAR(50) NOT NULL,
            message TEXT NOT NULL,
            metadata_json TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_telemetry_agent (agent_id, timestamp),
            INDEX idx_telemetry_org (organization_id, timestamp),
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        );
        """)

        conn.commit()
        print("[+] Migration successful!")
    except Exception as e:
        print(f"[!] Migration failed: {e}")
        if 'conn' in locals():
            conn.rollback()
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    load_dotenv()
    apply_migration()
