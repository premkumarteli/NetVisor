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


def main() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if organization_id is already present to make it idempotent
        if column_exists(cursor, "device_risks", "organization_id"):
            print("Migration 'device_risks tenant isolation' is already applied (organization_id column exists).")
            return

        # Read SQL statements from sql file
        sql_file = Path(__file__).parent / "20260628_device_risks_tenant_isolation.sql"
        if not sql_file.exists():
            raise FileNotFoundError(f"SQL file not found at {sql_file}")

        sql_content = sql_file.read_text(encoding="utf-8")
        
        # Split sql file into separate statements
        # Split by ';' while ignoring comments or empty parts
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
            print(f"Executing:\n{stmt_clean}\n")
            cursor.execute(stmt_clean)

        conn.commit()
        print("Successfully applied device_risks tenant isolation migration.")
    except Exception as exc:
        conn.rollback()
        print(f"Error applying migration: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
