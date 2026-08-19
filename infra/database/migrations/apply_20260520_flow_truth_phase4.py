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


DUPLICATE_COLUMN_ERROR = 1060
DUPLICATE_KEY_ERROR = 1061


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


def index_exists(cursor, table_name: str, index_name: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND index_name = %s
        LIMIT 1
        """,
        (table_name, index_name),
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
            "flow_direction": (
                "ALTER TABLE flow_logs "
                "ADD COLUMN flow_direction VARCHAR(20) NOT NULL DEFAULT 'unknown' AFTER network_scope"
            ),
            "analysis_source": (
                "ALTER TABLE flow_logs "
                "ADD COLUMN analysis_source VARCHAR(64) NOT NULL DEFAULT 'transport_fallback' AFTER agent_id"
            ),
            "analysis_confidence": (
                "ALTER TABLE flow_logs "
                "ADD COLUMN analysis_confidence FLOAT NOT NULL DEFAULT 0.0 AFTER analysis_source"
            ),
            "analysis_signals_json": (
                "ALTER TABLE flow_logs "
                "ADD COLUMN analysis_signals_json TEXT NULL AFTER analysis_confidence"
            ),
            "ingest_hash": (
                "ALTER TABLE flow_logs "
                "ADD COLUMN ingest_hash CHAR(40) NULL AFTER analysis_signals_json"
            ),
        }
        for column_name, sql in columns.items():
            if not column_exists(cursor, "flow_logs", column_name):
                _execute(sql, f"flow_logs.{column_name}", ignore_errnos=(DUPLICATE_COLUMN_ERROR,))

        indexes = {
            "idx_flow_logs_direction_last_seen": (
                "CREATE INDEX idx_flow_logs_direction_last_seen ON flow_logs (flow_direction, last_seen)"
            ),
            "idx_flow_logs_confidence_last_seen": (
                "CREATE INDEX idx_flow_logs_confidence_last_seen ON flow_logs (analysis_confidence, last_seen)"
            ),
            "uq_flow_logs_ingest_hash": (
                "CREATE UNIQUE INDEX uq_flow_logs_ingest_hash ON flow_logs (ingest_hash)"
            ),
        }
        for index_name, sql in indexes.items():
            if not index_exists(cursor, "flow_logs", index_name):
                _execute(sql, f"flow_logs.{index_name}", ignore_errnos=(DUPLICATE_KEY_ERROR,))

        conn.commit()
        print("Applied flow truth phase 4 migration.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
