"""
Flow repository service using the new repository pattern.
Provides clean data access boundary for flow operations.
"""

from __future__ import annotations

from typing import Dict, List, Optional
import logging

from .repository_service import create_repository, DatabaseConnection, FlowRepository

logger = logging.getLogger("netvisor.flow_repository")


class FlowRepositoryService:
    """Service layer for flow data operations using repository pattern."""
    
    def __init__(self, db_connection: DatabaseConnection):
        self._db = create_repository(db_connection, FlowRepository)
        
    def get_flow(self, flow_id: str) -> Optional[Dict]:
        """Get flow by ID."""
        return self._db.get_by_id(flow_id)
        
    def get_flows_by_agent(self, agent_id: str, organization_id: str, **filters) -> List[Dict]:
        """Get all flows for an agent, with optional filters."""
        filter_params = {"agent_id": agent_id, "organization_id": organization_id}
        filter_params.update(filters)
        return self._db.get_all(**filter_params)
        
    def create_flow(self, flow_data: Dict) -> str:
        """Create a new flow record."""
        return self._db.create(flow_data)
        
    def update_flow(self, flow_id: str, updates: Dict) -> bool:
        """Update flow by ID."""
        return self._db.update(flow_id, updates)
        
    def delete_flow(self, flow_id: str) -> bool:
        """Delete flow by ID."""
        return self._db.delete(flow_id)
        
    def count_flows(self, agent_id: str, organization_id: str, **filters) -> int:
        """Count flows for an agent, with optional filters."""
        filter_params = {"agent_id": agent_id, "organization_id": organization_id}
        filter_params.update(filters)
        return self._db.count(**filter_params)
        
    def get_recent_flows(self, organization_id: str, limit: int = 100) -> List[Dict]:
        """Get recent flows for an organization."""
        return self._db.get_all(
            organization_id=organization_id,
            start_time=None  # This would need to be implemented in the repository
        )[:limit]
