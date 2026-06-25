"""Idempotent migration: add mTLS certificate fields to agents + certificate_revocations table."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def _column_exists(cursor, table: str, column: str, db_name: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s AND column_name = %s
        """,
        (db_name, table, column),
    )
    return int((cursor.fetchone() or {}).get("cnt", 0)) > 0


def _table_exists(cursor, table: str, db_name: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM information_schema.tables
        WHERE table_schema = %s AND table_name = %s
        """,
        (db_name, table),
    )
    return int((cursor.fetchone() or {}).get("cnt", 0)) > 0


def main():
    db_name = os.getenv("NETVISOR_DB_NAME", "network_security")

    conn = mysql.connector.connect(
        host=os.getenv("NETVISOR_DB_HOST", "localhost"),
        user=os.getenv("NETVISOR_DB_USER", "root"),
        password=os.getenv("NETVISOR_DB_PASSWORD", ""),
        database=db_name,
    )
    cursor = conn.cursor(dictionary=True)

    try:
        # Add mTLS columns to agents table
        mtls_columns = {
            "cert_serial": "ALTER TABLE agents ADD COLUMN cert_serial VARCHAR(64) NULL",
            "cert_fingerprint": "ALTER TABLE agents ADD COLUMN cert_fingerprint CHAR(64) NULL",
            "cert_issued_at": "ALTER TABLE agents ADD COLUMN cert_issued_at DATETIME NULL",
            "cert_expires_at": "ALTER TABLE agents ADD COLUMN cert_expires_at DATETIME NULL",
            "cert_status": "ALTER TABLE agents ADD COLUMN cert_status VARCHAR(20) DEFAULT 'none'",
        }

        for col_name, alter_sql in mtls_columns.items():
            if not _column_exists(cursor, "agents", col_name, db_name):
                print(f"[+] Adding agents.{col_name}")
                cursor.execute(alter_sql)
            else:
                print(f"[=] agents.{col_name} already exists")

        # Create certificate_revocations table
        if not _table_exists(cursor, "certificate_revocations", db_name):
            print("[+] Creating certificate_revocations table")
            cursor.execute(
                """
                CREATE TABLE certificate_revocations (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    serial_number VARCHAR(64) NOT NULL,
                    agent_id VARCHAR(100) NULL,
                    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    revoked_by VARCHAR(100) NULL,
                    reason VARCHAR(255) NULL,
                    UNIQUE KEY uq_cert_revocation_serial (serial_number),
                    INDEX idx_cert_revocation_agent (agent_id)
                )
                """
            )
        else:
            print("[=] certificate_revocations table already exists")

        conn.commit()
        print("[✓] mTLS schema migration complete.")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
