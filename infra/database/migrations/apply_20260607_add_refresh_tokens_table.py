from __future__ import annotations

import sys
from pathlib import Path

from mysql.connector import Error

def _find_project_root(script_path: Path) -> Path:
    for parent in script_path.resolve().parents:
        if (parent / "app").exists() and (parent / "shared").exists():
            return parent
    return script_path.resolve().parents[2]


PROJECT_ROOT = _find_project_root(Path(__file__))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.session import get_db_connection


def table_exists(cursor, table_name: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        LIMIT 1
        """,
        (table_name,),
    )
    return cursor.fetchone() is not None


def main() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    applied = False

    try:
        table_name = "user_refresh_tokens"
        if not table_exists(cursor, table_name):
            sql = """
            CREATE TABLE IF NOT EXISTS user_refresh_tokens (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(100) NOT NULL,
                token_hash CHAR(64) NOT NULL,
                family_id VARCHAR(255) NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME NULL,
                revoked TINYINT NOT NULL DEFAULT 0,
                revoked_reason VARCHAR(50) NULL,
                ip_address VARCHAR(45) NULL,
                user_agent VARCHAR(255) NULL,
                UNIQUE KEY uq_token_hash (token_hash),
                INDEX idx_user_refresh_tokens_family (family_id),
                INDEX idx_user_refresh_tokens_user (user_id)
            )
            """
            cursor.execute(sql)
            applied = True

        conn.commit()
        if applied:
            print(f"Applied table migration: created {table_name}.")
        else:
            print(f"Table {table_name} already exists. No migration applied.")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
