import clickhouse_connect
import logging
from pathlib import Path
from backend.core.config import settings

logger = logging.getLogger("netvisor.db.clickhouse")

_clickhouse_client = None

def get_clickhouse_client():
    """Returns the shared ClickHouse client instance, initializing it and applying DDL on first call."""
    global _clickhouse_client
    if _clickhouse_client is None:
        logger.info(
            "Initializing ClickHouse connection: %s:%s (DB: %s)",
            settings.CLICKHOUSE_HOST,
            settings.CLICKHOUSE_PORT,
            settings.CLICKHOUSE_DB
        )
        try:
            _clickhouse_client = clickhouse_connect.get_client(
                host=settings.CLICKHOUSE_HOST,
                port=settings.CLICKHOUSE_PORT,
                username=settings.CLICKHOUSE_USER,
                password=settings.CLICKHOUSE_PASSWORD,
                database=settings.CLICKHOUSE_DB,
                connect_timeout=1,
            )
            # Apply initial schema DDL
            init_clickhouse_schema(_clickhouse_client)
        except Exception as e:
            logger.error("Failed to connect or initialize ClickHouse: %s", e)
            raise e
    return _clickhouse_client

def init_clickhouse_schema(client) -> None:
    """Applies ClickHouse DDL schemas from the sql files in infra/clickhouse/."""
    schema_path = Path(__file__).parents[2] / "infra" / "clickhouse" / "schema.sql"
    if not schema_path.exists():
        logger.warning("ClickHouse schema file not found at %s", schema_path)
        return
        
    logger.info("Applying ClickHouse schema DDL from %s", schema_path)
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            ddl_queries = f.read().split(";")
            
        for query in ddl_queries:
            query = query.strip()
            if query:
                client.command(query)
        logger.info("ClickHouse schema DDL applied successfully.")
    except Exception as e:
        logger.error("Failed to apply ClickHouse schema DDL: %s", e)
        raise e
