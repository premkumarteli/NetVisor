import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger("netvisor.db.partition")

class PartitionManager:
    """
    Manages MySQL range partitioning for high-volume telemetry tables like `flow_logs`.
    Supports automated partition maintenance, future partition generation, and retention cleanup.
    """

    @staticmethod
    def is_table_partitioned(cursor, db_name: str, table_name: str) -> bool:
        cursor.execute(
            """
            SELECT partition_name 
            FROM information_schema.partitions 
            WHERE table_schema = %s AND table_name = %s AND partition_name IS NOT NULL
            LIMIT 1
            """,
            (db_name, table_name),
        )
        return cursor.fetchone() is not None

    @staticmethod
    def get_existing_partitions(cursor, db_name: str, table_name: str) -> List[Dict[str, Any]]:
        cursor.execute(
            """
            SELECT partition_name, partition_description, table_rows
            FROM information_schema.partitions
            WHERE table_schema = %s AND table_name = %s AND partition_name IS NOT NULL
            ORDER BY partition_ordinal_position ASC
            """,
            (db_name, table_name),
        )
        return cursor.fetchall() or []

    @staticmethod
    def generate_monthly_partition_ddl(
        table_name: str = "flow_logs",
        column_name: str = "start_time",
        start_year: int = 2026,
        months_ahead: int = 6,
    ) -> str:
        """
        Generates MySQL RANGE partitioning DDL using TO_DAYS(column_name).
        """
        partitions = []
        now = datetime.now()
        for i in range(months_ahead + 1):
            target_date = (now.replace(day=1) + timedelta(days=32 * i)).replace(day=1)
            p_name = f"p_{target_date.strftime('%Y_%m')}"
            # Next month's first day
            next_month = (target_date + timedelta(days=32)).replace(day=1)
            days_val = f"TO_DAYS('{next_month.strftime('%Y-%m-%d')}')"
            partitions.append(f"    PARTITION {p_name} VALUES LESS THAN ({days_val})")

        partitions.append("    PARTITION p_future VALUES LESS THAN MAXVALUE")
        partition_body = ",\n".join(partitions)

        return f"""ALTER TABLE {table_name}
PARTITION BY RANGE (TO_DAYS({column_name})) (
{partition_body}
);"""

    @staticmethod
    def drop_expired_partitions(
        cursor,
        db_name: str,
        table_name: str,
        retention_days: int = 90,
    ) -> List[str]:
        """
        Identifies and drops partitions whose upper bounds are older than the retention threshold.
        """
        dropped = []
        cursor.execute(
            """
            SELECT partition_name, partition_description
            FROM information_schema.partitions
            WHERE table_schema = %s AND table_name = %s AND partition_name IS NOT NULL
            """,
            (db_name, table_name),
        )
        rows = cursor.fetchall()
        cutoff_days = (datetime.now() - timedelta(days=retention_days)).toordinal()

        for row in rows:
            p_name = row.get("partition_name")
            desc = row.get("partition_description")
            if not p_name or p_name == "p_future":
                continue
            try:
                if desc and desc.isdigit() and int(desc) < cutoff_days:
                    cursor.execute(f"ALTER TABLE {table_name} DROP PARTITION {p_name}")
                    dropped.append(p_name)
                    logger.info("Dropped expired partition %s from %s (retention: %dd)", p_name, table_name, retention_days)
            except Exception as exc:
                logger.warning("Failed to evaluate/drop partition %s: %s", p_name, exc)

        return dropped

partition_manager = PartitionManager()
