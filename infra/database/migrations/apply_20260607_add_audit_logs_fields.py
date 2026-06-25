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


DUPLICATE_COLUMN_ERROR = 1060


def column_exists(cursor, table_name: str, column_name: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        LIMIT 1
        """,
        (table_name, column_name),
    )
    return cursor.fetchone() is not None


def main() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    applied: list[str] = []

    def _execute(sql: str, label: str, *, ignore_errnos: tuple[int, ...] = ()) -> None:
        try:
            cursor.execute(sql)
            applied.append(label)
        except Error as exc:
            if exc.errno in ignore_errnos:
                return
            raise

    try:
        columns = {
            "ip_address": "ALTER TABLE audit_logs ADD COLUMN ip_address VARCHAR(45) NULL AFTER action",
            "resource": "ALTER TABLE audit_logs ADD COLUMN resource VARCHAR(100) NULL AFTER ip_address",
        }
        for column_name, sql in columns.items():
            if not column_exists(cursor, "audit_logs", column_name):
                _execute(sql, f"audit_logs.{column_name}", ignore_errnos=(DUPLICATE_COLUMN_ERROR,))

        conn.commit()
        print("Applied audit logs fields migration.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
