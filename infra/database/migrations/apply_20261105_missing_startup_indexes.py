from __future__ import annotations

import sys
from pathlib import Path

from mysql.connector import Error

def _find_project_root(script_path: Path) -> Path:
    for parent in script_path.resolve().parents:
        if (parent / "backend").exists() and (parent / "agent").exists():
            return parent
    return script_path.resolve().parents[3]


PROJECT_ROOT = _find_project_root(Path(__file__))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.db.session import get_db_connection


DUPLICATE_KEY_ERROR = 1061


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
    indexes = (
        (
            "alerts",
            "idx_alerts_org_resolved_time_sev",
            "CREATE INDEX idx_alerts_org_resolved_time_sev ON alerts (organization_id, resolved, timestamp, severity)",
        ),
        (
            "web_events",
            "idx_web_events_org_last_seen_id",
            "CREATE INDEX idx_web_events_org_last_seen_id ON web_events (organization_id, last_seen, id)",
        ),
    )

    try:
        for table_name, index_name, sql in indexes:
            if index_exists(cursor, table_name, index_name):
                continue
            try:
                cursor.execute(sql)
                applied.append(f"{table_name}.{index_name}")
            except Error as exc:
                if exc.errno != DUPLICATE_KEY_ERROR:
                    raise
        conn.commit()
        print("Applied missing startup indexes required by backend/db/session.py.")
        for item in applied:
            print(f" - {item}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
