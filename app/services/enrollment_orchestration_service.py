"""
Enrollment orchestration service for predictable agent/gateway enrollment flows.
Provides better visibility and recovery mechanisms.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
import json
import logging
import uuid

from ..core.config import settings
from .agent_enrollment_service import agent_enrollment_service
from .agent_auth_service import agent_auth_service
from .audit_service import audit_service

logger = logging.getLogger("netvisor.enrollment_orchestration")


class EnrollmentOrchestrationService:
    """Manages enrollment lifecycle with predictable flows and better visibility."""
    
    def __init__(self):
        self._schema_ready = False
        
    def ensure_schema(self, db_conn) -> None:
        """Ensure orchestration tracking tables exist."""
        if self._schema_ready:
            return
            
        cursor = db_conn.cursor()
        try:
            # Enrollment state tracking for better visibility
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS enrollment_state_tracking (
                    tracking_id CHAR(36) PRIMARY KEY,
                    agent_id VARCHAR(100) NOT NULL,
                    organization_id CHAR(36),
                    current_state VARCHAR(32) NOT NULL DEFAULT 'initializing',
                    previous_state VARCHAR(32),
                    state_entered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    state_expires_at DATETIME NULL,
                    retry_count INT DEFAULT 0,
                    max_retries INT DEFAULT 10,
                    next_retry_at DATETIME NULL,
                    last_error_message TEXT,
                    recovery_attempts INT DEFAULT 0,
                    UNIQUE KEY uq_enrollment_state_agent (agent_id),
                    INDEX idx_enrollment_state_org (organization_id),
                    INDEX idx_enrollment_state_retry (next_retry_at),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
                )
            """)
            
            # Enrollment events for audit trail
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS enrollment_events (
                    event_id CHAR(36) PRIMARY KEY,
                    agent_id VARCHAR(100) NOT NULL,
                    organization_id CHAR(36),
                    event_type VARCHAR(32) NOT NULL,
                    previous_state VARCHAR(32),
                    new_state VARCHAR(32),
                    event_data JSON,
                    source_ip VARCHAR(50),
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_enrollment_events_agent (agent_id),
                    INDEX idx_enrollment_events_org (organization_id),
                    INDEX idx_enrollment_events_timestamp (timestamp),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
                )
            """)
            
            db_conn.commit()
            self._schema_ready = True
            logger.info("Enrollment orchestration schema initialized")
        finally:
            cursor.close()
            
    def get_enrollment_state(self, db_conn, *, agent_id: str) -> Optional[Dict]:
        """Get current enrollment state with metadata."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT * FROM enrollment_state_tracking 
                WHERE agent_id = %s 
                LIMIT 1
            """, (agent_id,))
            return cursor.fetchone()
        finally:
            cursor.close()
            
    def transition_state(
        self, 
        db_conn, 
        *, 
        agent_id: str, 
        organization_id: str,
        new_state: str,
        event_data: Optional[Dict] = None,
        error_message: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> Dict:
        """Transition enrollment state with full audit trail."""
        
        current_state = self.get_enrollment_state(db_conn, agent_id=agent_id)
        previous_state = current_state.get("current_state") if current_state else None
        
        tracking_id = current_state.get("tracking_id") if current_state else str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        cursor = db_conn.cursor()
        try:
            # Update or insert state tracking
            if current_state:
                cursor.execute("""
                    UPDATE enrollment_state_tracking 
                    SET previous_state = %s,
                        current_state = %s,
                        state_entered_at = %s,
                        last_error_message = %s,
                        retry_count = CASE 
                            WHEN %s IN ('failed', 'error', 'rejected') THEN retry_count + 1
                            ELSE retry_count
                        END
                    WHERE tracking_id = %s
                """, (
                    previous_state, new_state, now, error_message, new_state, tracking_id
                ))
            else:
                cursor.execute("""
                    INSERT INTO enrollment_state_tracking 
                    (tracking_id, agent_id, organization_id, current_state, state_entered_at)
                    VALUES (%s, %s, %s, %s, %s)
                """, (tracking_id, agent_id, organization_id, new_state, now))
            
            # Record state transition event
            cursor.execute("""
                INSERT INTO enrollment_events 
                (event_id, agent_id, organization_id, event_type, previous_state, new_state, event_data, source_ip, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                str(uuid.uuid4()), agent_id, organization_id, "state_transition",
                previous_state, new_state, 
                json.dumps(event_data) if event_data else None,
                source_ip, now
            ))
            
            db_conn.commit()
            
            # Return updated state
            updated_state = self.get_enrollment_state(db_conn, agent_id=agent_id)
            logger.info(f"Agent {agent_id} transitioned from {previous_state} to {new_state}")
            
            return updated_state
            
        except Exception as e:
            db_conn.rollback()
            logger.error(f"Failed to transition state for agent {agent_id}: {e}")
            raise
        finally:
            cursor.close()
            
    def schedule_retry(
        self, 
        db_conn, 
        *, 
        agent_id: str,
        retry_delay_seconds: int = None,
        max_retries: int = 10
    ) -> bool:
        """Schedule enrollment retry with exponential backoff."""
        
        state = self.get_enrollment_state(db_conn, agent_id=agent_id)
        if not state:
            return False
            
        retry_count = state.get("retry_count", 0)
        if retry_count >= max_retries:
            self.transition_state(
                db_conn,
                agent_id=agent_id,
                organization_id=state["organization_id"],
                new_state="permanently_failed",
                error_message=f"Max retries ({max_retries}) exceeded"
            )
            return False
            
        # Calculate exponential backoff with jitter
        base_delay = retry_delay_seconds or settings.AGENT_ENROLLMENT_RETRY_SECONDS
        delay = min(base_delay * (2 ** retry_count), 300)  # Cap at 5 minutes
        jitter = delay * 0.1  # 10% jitter
        final_delay = delay + jitter
        
        next_retry = datetime.now(timezone.utc) + timedelta(seconds=final_delay)
        
        cursor = db_conn.cursor()
        try:
            cursor.execute("""
                UPDATE enrollment_state_tracking 
                SET next_retry_at = %s,
                    state_expires_at = %s,
                    current_state = 'retry_scheduled'
                WHERE tracking_id = %s
            """, (next_retry, next_retry, state["tracking_id"]))
            
            db_conn.commit()
            logger.info(f"Scheduled retry for agent {agent_id} at {next_retry}")
            return True
            
        except Exception as e:
            db_conn.rollback()
            logger.error(f"Failed to schedule retry for agent {agent_id}: {e}")
            return False
        finally:
            cursor.close()
            
    def get_pending_retries(self, db_conn, organization_id: str) -> List[Dict]:
        """Get agents scheduled for retry."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT est.*, aer.hostname, aer.device_ip
                FROM enrollment_state_tracking est
                LEFT JOIN agent_enrollment_requests aer ON est.agent_id = aer.agent_id
                WHERE est.organization_id = %s 
                    AND est.current_state = 'retry_scheduled'
                    AND est.next_retry_at <= NOW()
                ORDER BY est.next_retry_at ASC
            """, (organization_id,))
            return cursor.fetchall()
        finally:
            cursor.close()
            
    def get_enrollment_summary(self, db_conn, organization_id: str) -> Dict:
        """Get comprehensive enrollment status summary."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            # State distribution
            cursor.execute("""
                SELECT current_state, COUNT(*) as count
                FROM enrollment_state_tracking
                WHERE organization_id = %s
                GROUP BY current_state
            """, (organization_id,))
            state_distribution = {row["current_state"]: row["count"] for row in cursor.fetchall()}
            
            # Recent activity
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM enrollment_events
                WHERE organization_id = %s 
                    AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                GROUP BY event_type
            """, (organization_id,))
            recent_activity = {row["event_type"]: row["count"] for row in cursor.fetchall()}
            
            # Failed enrollments needing attention
            cursor.execute("""
                SELECT est.*, aer.hostname, aer.device_ip, aer.last_seen
                FROM enrollment_state_tracking est
                LEFT JOIN agent_enrollment_requests aer ON est.agent_id = aer.agent_id
                WHERE est.organization_id = %s 
                    AND est.current_state IN ('failed', 'permanently_failed', 'error')
                ORDER BY est.state_entered_at DESC
                LIMIT 10
            """, (organization_id,))
            failed_enrollments = cursor.fetchall()
            
            return {
                "state_distribution": state_distribution,
                "recent_activity": recent_activity,
                "failed_enrollments": failed_enrollments,
                "summary_timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        finally:
            cursor.close()


# Global instance
enrollment_orchestration_service = EnrollmentOrchestrationService()
