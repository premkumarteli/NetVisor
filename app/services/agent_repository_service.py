"""
Agent repository service using the new repository pattern.
Provides clean data access boundary for agent operations.
"""

from __future__ import annotations

from typing import Dict, List, Optional
import logging

from .repository_service import create_repository, Repository, DatabaseConnection

logger = logging.getLogger("netvisor.agent_repository")


class AgentRepositoryService:
    """Service layer for agent data operations using repository pattern."""
    
    def __init__(self, db_connection: DatabaseConnection):
        self._db = self.create_repository(db_connection, AgentRepository)
        
    @staticmethod
    def create_repository(db_connection: DatabaseConnection, repository_type: Type[Repository]) -> Repository:
        """Factory function to create repository instances."""
        return repository_type(db_connection)
        
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent by ID."""
        return self._db.get_by_id(agent_id)
        
    def get_agents_by_organization(self, organization_id: str, status: Optional[str] = None) -> List[Dict]:
        """Get all agents for an organization, optionally filtered by status."""
        filters = {"organization_id": organization_id}
        if status:
            filters["status"] = status
        return self._db.get_all(**filters)
        
    def create_agent(self, agent_data: Dict) -> str:
        """Create a new agent record."""
        return self._db.create(agent_data)
        
    def update_agent(self, agent_id: str, updates: Dict) -> bool:
        """Update agent by ID."""
        return self._db.update(agent_id, updates)
        
    def delete_agent(self, agent_id: str) -> bool:
        """Delete agent by ID."""
        return self._db.delete(agent_id)
        
    def count_agents(self, organization_id: str, status: Optional[str] = None) -> int:
        """Count agents for an organization, optionally filtered by status."""
        filters = {"organization_id": organization_id}
        if status:
            filters["status"] = status
        return self._db.count(**filters)
        
    def get_active_agents(self, organization_id: str) -> List[Dict]:
        """Get only active (online) agents."""
        return self.get_agents_by_organization(organization_id, status="online")
        
    def get_pending_agents(self, organization_id: str) -> List[Dict]:
        """Get only pending agents."""
        return self.get_agents_by_organization(organization_id, status="pending")
        
    def update_agent_status(self, agent_id: str, status: str, last_seen: Optional[str] = None) -> bool:
        """Update agent status and last seen timestamp."""
        updates = {"status": status}
        if last_seen:
            updates["last_seen"] = last_seen
        return self.update_agent(agent_id, updates)
