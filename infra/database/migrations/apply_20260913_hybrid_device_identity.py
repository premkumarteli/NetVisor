from __future__ import annotations

import sys
from pathlib import Path

def _find_project_root(script_path: Path) -> Path:
    for parent in script_path.resolve().parents:
        if (parent / "app").exists() and (parent / "shared").exists():
            return parent
    return script_path.resolve().parents[2]


PROJECT_ROOT = _find_project_root(Path(__file__))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.db.session import get_db_connection


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
    try:
        # Check if migration is already fully applied
        has_uuid_col = column_exists(cursor, "devices", "device_uuid")
        has_mac_table = table_exists(cursor, "device_mac_addresses")
        has_conflict_table = table_exists(cursor, "device_identity_conflicts")

        if has_uuid_col and has_mac_table and has_conflict_table:
            print("Migration '20260913_hybrid_device_identity' is already applied.")
            return

        sql_file = Path(__file__).parent / "20260913_hybrid_device_identity.sql"
        if not sql_file.exists():
            raise FileNotFoundError(f"SQL file not found at {sql_file}")

        sql_content = sql_file.read_text(encoding="utf-8")

        statements = []
        current_stmt = []
        for line in sql_content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("--"):
                continue
            current_stmt.append(line)
            if stripped.endswith(";"):
                statements.append("\n".join(current_stmt))
                current_stmt = []

        print("Executing migration statements...")
        for stmt in statements:
            stmt_clean = stmt.strip()
            if not stmt_clean:
                continue
            # Handle partial execution idempotency: skip table create if already exists, etc.
            if "ADD COLUMN device_uuid" in stmt_clean and has_uuid_col:
                continue
            if "ADD UNIQUE KEY uq_device_uuid_org" in stmt_clean and has_uuid_col:
                continue
            if "CREATE TABLE IF NOT EXISTS device_mac_addresses" in stmt_clean and has_mac_table:
                continue
            if "CREATE TABLE IF NOT EXISTS device_identity_conflicts" in stmt_clean and has_conflict_table:
                continue

            print(f"Executing:\n{stmt_clean}\n")
            cursor.execute(stmt_clean)

        conn.commit()
        print("Successfully applied hybrid device identity migration.")
    except Exception as exc:
        conn.rollback()
        print(f"Error applying migration: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
