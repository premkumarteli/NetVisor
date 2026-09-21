from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import mysql.connector


def _iter_sql_statements(sql: str):
    buffer: list[str] = []
    for raw_line in sql.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("--"):
            continue
        buffer.append(raw_line)
        if line.endswith(";"):
            statement = "\n".join(buffer).strip().rstrip(";").strip()
            buffer = []
            if statement:
                yield statement
    trailing = "\n".join(buffer).strip()
    if trailing:
        yield trailing


def _connect_with_retry():
    config = {
        "host": os.environ.get("NETVISOR_DB_HOST", "127.0.0.1"),
        "user": os.environ.get("NETVISOR_DB_USER", "root"),
        "password": os.environ.get("NETVISOR_DB_PASSWORD", ""),
        "connection_timeout": 5,
        "autocommit": False,
    }
    last_error: Exception | None = None
    for _ in range(60):
        try:
            return mysql.connector.connect(**config)
        except mysql.connector.Error as exc:
            last_error = exc
            time.sleep(2)
    raise RuntimeError(f"MySQL did not become available for CI initialization: {last_error}")


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    sql_path = project_root / "infra" / "database" / "init.sql"
    if not sql_path.exists():
        sql_path = project_root / "database" / "init.sql"
    statements = list(_iter_sql_statements(sql_path.read_text(encoding="utf-8")))

    conn = _connect_with_retry()
    cursor = conn.cursor()
    try:
        for statement in statements:
            cursor.execute(statement)
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    # Apply all migration scripts
    migrations_dir = project_root / "infra" / "database" / "migrations"
    if migrations_dir.exists():
        migration_files = sorted(migrations_dir.glob("apply_*.py"))
        for mig_file in migration_files:
            spec = importlib.util.spec_from_file_location(mig_file.stem, mig_file)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "main"):
                    print(f"Running migration {mig_file.name}...")
                    mod.main()

    from backend.db.session import (
        ensure_bootstrap_state,
        ensure_security_schema,
        get_db_connection,
        require_runtime_schema,
    )

    verify_conn = get_db_connection()
    try:
        ensure_security_schema(verify_conn)
        ensure_bootstrap_state()
        status = require_runtime_schema(verify_conn, force=True)
        print("Database initialized and runtime schema verified successfully:", status)
    finally:
        verify_conn.close()


if __name__ == "__main__":
    main()
