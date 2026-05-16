"""
Data access boundary layer for database operations.
Provides abstraction between services and database, enabling multi-database support.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar
import json
import logging
import uuid

logger = logging.getLogger("netvisor.repository")

T = TypeVar('T')


class DatabaseConnection(ABC):
    """Abstract database connection interface."""
    
    @abstractmethod
    def execute(self, query: str, params: tuple = ()) -> Any:
        """Execute a query with parameters."""
        pass
        
    @abstractmethod
    def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict]:
        """Fetch a single record."""
        pass
        
    @abstractmethod
    def fetch_all(self, query: str, params: tuple = ()) -> List[Dict]:
        """Fetch multiple records."""
        pass
        
    @abstractmethod
    def fetch_dict(self, query: str, key_field: str, params: tuple = ()) -> Dict[str, Dict]:
        """Fetch records as dictionary keyed by specified field."""
        pass
        
    @abstractmethod
    def insert(self, query: str, params: tuple = ()) -> str:
        """Insert a record and return the ID."""
        pass
        
    @abstractmethod
    def update(self, query: str, params: tuple = ()) -> int:
        """Update records and return affected count."""
        pass
        
    @abstractmethod
    def delete(self, query: str, params: tuple = ()) -> int:
        """Delete records and return affected count."""
        pass
        
    @abstractmethod
    def commit(self) -> None:
        """Commit transaction."""
        pass
        
    @abstractmethod
    def rollback(self) -> None:
        """Rollback transaction."""
        pass
        
    @abstractmethod
    def close(self) -> None:
        """Close connection."""
        pass


class MySQLConnection(DatabaseConnection):
    """MySQL implementation of database connection."""
    
    def __init__(self, connection):
        self._conn = connection
        
    def execute(self, query: str, params: tuple = ()) -> Any:
        cursor = self._conn.cursor(dictionary=True)
        try:
            cursor.execute(query, params)
            return cursor
        except Exception as e:
            logger.error(f"MySQL execute error: {e}")
            raise
            
    def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict]:
        cursor = self._conn.cursor(dictionary=True)
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except Exception as e:
            logger.error(f"MySQL fetch_one error: {e}")
            return None
            
    def fetch_all(self, query: str, params: tuple = ()) -> List[Dict]:
        cursor = self._conn.cursor(dictionary=True)
        try:
            cursor.execute(query, params)
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"MySQL fetch_all error: {e}")
            return []
            
    def fetch_dict(self, query: str, key_field: str, params: tuple = ()) -> Dict[str, Dict]:
        cursor = self._conn.cursor(dictionary=True)
        try:
            cursor.execute(query, params)
            return {row[key_field]: row for row in cursor.fetchall()}
        except Exception as e:
            logger.error(f"MySQL fetch_dict error: {e}")
            return {}
            
    def insert(self, query: str, params: tuple = ()) -> str:
        cursor = self._conn.cursor()
        try:
            cursor.execute(query, params)
            self._conn.commit()
            return cursor.lastrowid if cursor.lastrowid else str(uuid.uuid4())
        except Exception as e:
            logger.error(f"MySQL insert error: {e}")
            self._conn.rollback()
            raise
            
    def update(self, query: str, params: tuple = ()) -> int:
        cursor = self._conn.cursor()
        try:
            cursor.execute(query, params)
            affected = cursor.rowcount
            self._conn.commit()
            return affected
        except Exception as e:
            logger.error(f"MySQL update error: {e}")
            self._conn.rollback()
            raise
            
    def delete(self, query: str, params: tuple = ()) -> int:
        cursor = self._conn.cursor()
        try:
            cursor.execute(query, params)
            affected = cursor.rowcount
            self._conn.commit()
            return affected
        except Exception as e:
            logger.error(f"MySQL delete error: {e}")
            self._conn.rollback()
            raise
            
    def commit(self) -> None:
        self._conn.commit()
        
    def rollback(self) -> None:
        self._conn.rollback()
        
    def close(self) -> None:
        self._conn.close()


class Repository(ABC, Generic[T]):
    """Abstract repository base class."""
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
        
    @abstractmethod
    def get_by_id(self, id: str) -> Optional[T]:
        """Get entity by ID."""
        pass
        
    @abstractmethod
    def get_all(self, **filters) -> List[T]:
        """Get all entities with optional filters."""
        pass
        
    @abstractmethod
    def create(self, entity: T) -> str:
        """Create new entity."""
        pass
        
    @abstractmethod
    def update(self, id: str, updates: Dict[str, Any]) -> bool:
        """Update entity by ID."""
        pass
        
    @abstractmethod
    def delete(self, id: str) -> bool:
        """Delete entity by ID."""
        pass
        
    @abstractmethod
    def count(self, **filters) -> int:
        """Count entities with optional filters."""
        pass


class FlowRepository(Repository[Dict]):
    """Repository for flow data access."""
    
    def get_by_id(self, flow_id: str) -> Optional[Dict]:
        query = "SELECT * FROM flows WHERE flow_id = %s"
        result = self.db.fetch_one(query, (flow_id,))
        return result
        
    def get_all(self, **filters) -> List[Dict]:
        conditions = []
        params = []
        
        if 'agent_id' in filters:
            conditions.append("agent_id = %s")
            params.append(filters['agent_id'])
            
        if 'organization_id' in filters:
            conditions.append("organization_id = %s")
            params.append(filters['organization_id'])
            
        if 'start_time' in filters:
            conditions.append("created_at >= %s")
            params.append(filters['start_time'])
            
        if 'end_time' in filters:
            conditions.append("created_at <= %s")
            params.append(filters['end_time'])
            
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM flows WHERE {where_clause} ORDER BY created_at DESC"
        
        return self.db.fetch_all(query, tuple(params))
        
    def create(self, flow_data: Dict) -> str:
        query = """
            INSERT INTO flows (
                flow_id, agent_id, organization_id, src_ip, dst_ip, src_port, dst_port,
                protocol, bytes_sent, bytes_received, packets_sent, packets_received,
                start_time, end_time, duration_ms, flow_metadata, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        params = (
            flow_data.get('flow_id'),
            flow_data.get('agent_id'),
            flow_data.get('organization_id'),
            flow_data.get('src_ip'),
            flow_data.get('dst_ip'),
            flow_data.get('src_port'),
            flow_data.get('dst_port'),
            flow_data.get('protocol'),
            flow_data.get('bytes_sent', 0),
            flow_data.get('bytes_received', 0),
            flow_data.get('packets_sent', 0),
            flow_data.get('packets_received', 0),
            flow_data.get('start_time'),
            flow_data.get('end_time'),
            flow_data.get('duration_ms'),
            json.dumps(flow_data.get('flow_metadata', {})),
            datetime.now(timezone.utc).isoformat()
        )
        
        return self.db.insert(query, params)
        
    def update(self, flow_id: str, updates: Dict[str, Any]) -> bool:
        set_clauses = []
        params = []
        
        for field, value in updates.items():
            set_clauses.append(f"{field} = %s")
            params.append(value)
            
        query = f"UPDATE flows SET {', '.join(set_clauses)} WHERE flow_id = %s"
        params.append(flow_id)
        
        try:
            affected = self.db.update(query, tuple(params))
            return affected > 0
        except Exception as e:
            logger.error(f"Failed to update flow {flow_id}: {e}")
            return False
            
    def delete(self, flow_id: str) -> bool:
        query = "DELETE FROM flows WHERE flow_id = %s"
        try:
            affected = self.db.delete(query, (flow_id,))
            return affected > 0
        except Exception as e:
            logger.error(f"Failed to delete flow {flow_id}: {e}")
            return False
            
    def count(self, **filters) -> int:
        conditions = []
        params = []
        
        if 'agent_id' in filters:
            conditions.append("agent_id = %s")
            params.append(filters['agent_id'])
            
        if 'organization_id' in filters:
            conditions.append("organization_id = %s")
            params.append(filters['organization_id'])
            
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT COUNT(*) FROM flows WHERE {where_clause}"
        
        result = self.db.fetch_one(query, tuple(params))
        return result['COUNT(*)'] if result else 0


class AgentRepository(Repository[Dict]):
    """Repository for agent data access."""
    
    def get_by_id(self, agent_id: str) -> Optional[Dict]:
        query = "SELECT * FROM agents WHERE agent_id = %s"
        result = self.db.fetch_one(query, (agent_id,))
        return result
        
    def get_all(self, **filters) -> List[Dict]:
        conditions = []
        params = []
        
        if 'organization_id' in filters:
            conditions.append("organization_id = %s")
            params.append(filters['organization_id'])
            
        if 'status' in filters:
            conditions.append("status = %s")
            params.append(filters['status'])
            
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM agents WHERE {where_clause} ORDER BY last_seen DESC"
        
        return self.db.fetch_all(query, tuple(params))
        
    def create(self, agent_data: Dict) -> str:
        query = """
            INSERT INTO agents (
                agent_id, hostname, os_family, version, device_ip, device_mac,
                status, last_seen, organization_id, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        params = (
            agent_data.get('agent_id'),
            agent_data.get('hostname'),
            agent_data.get('os_family'),
            agent_data.get('version'),
            agent_data.get('device_ip'),
            agent_data.get('device_mac'),
            agent_data.get('status'),
            agent_data.get('last_seen'),
            agent_data.get('organization_id'),
            datetime.now(timezone.utc).isoformat(),
            datetime.now(timezone.utc).isoformat()
        )
        
        return self.db.insert(query, params)
        
    def update(self, agent_id: str, updates: Dict[str, Any]) -> bool:
        set_clauses = []
        params = []
        
        for field, value in updates.items():
            set_clauses.append(f"{field} = %s")
            params.append(value)
            
        query = f"UPDATE agents SET {', '.join(set_clauses)} WHERE agent_id = %s"
        params.append(agent_id)
        
        try:
            affected = self.db.update(query, tuple(params))
            return affected > 0
        except Exception as e:
            logger.error(f"Failed to update agent {agent_id}: {e}")
            return False
            
    def delete(self, agent_id: str) -> bool:
        query = "DELETE FROM agents WHERE agent_id = %s"
        try:
            affected = self.db.delete(query, (agent_id,))
            return affected > 0
        except Exception as e:
            logger.error(f"Failed to delete agent {agent_id}: {e}")
            return False
            
    def count(self, **filters) -> int:
        conditions = []
        params = []
        
        if 'organization_id' in filters:
            conditions.append("organization_id = %s")
            params.append(filters['organization_id'])
            
        if 'status' in filters:
            conditions.append("status = %s")
            params.append(filters['status'])
            
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT COUNT(*) FROM agents WHERE {where_clause}"
        
        result = self.db.fetch_one(query, tuple(params))
        return result['COUNT(*)'] if result else 0


def create_repository(db_connection: DatabaseConnection, repository_type: Type[Repository]) -> Repository:
    """Factory function to create repository instances."""
    return repository_type(db_connection)
