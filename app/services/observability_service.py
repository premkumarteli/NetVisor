"""
Enhanced observability service for startup timing, health checks, and metrics.
Provides comprehensive operational visibility.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional
import logging
import time
import threading
from collections import defaultdict, deque

logger = logging.getLogger("netvisor.observability")


class ObservabilityService:
    """Enhanced observability service for operational monitoring."""
    
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._startup_events: List[Dict] = []
        self._health_checks: Dict[str, Dict] = {}
        self._performance_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._component_status: Dict[str, Dict] = {}
        self._startup_start_time = None
        self._startup_complete_time = None
        
    def record_startup_event(self, component: str, event_type: str, details: Optional[Dict] = None) -> None:
        """Record startup event with timing."""
        with self._lock:
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": component,
                "event_type": event_type,
                "details": details or {},
                "relative_time": time.time() - (self._startup_start_time or time.time())
            }
            self._startup_events.append(event)
            
        if event_type == "startup_start":
            self._startup_start_time = time.time()
        elif event_type == "startup_complete":
            self._startup_complete_time = time.time()
            
        logger.info(f"Startup event: {component} - {event_type}")
        
    def record_health_check(
        self, 
        component: str, 
        check_type: str, 
        status: str, 
        details: Optional[Dict] = None,
        duration_ms: Optional[float] = None
    ) -> None:
        """Record health check result."""
        with self._lock:
            if component not in self._health_checks:
                self._health_checks[component] = {}
                
            self._health_checks[component][check_type] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": status,
                "details": details or {},
                "duration_ms": duration_ms,
            }
            
        logger.info(f"Health check: {component} - {check_type} - {status}")
        
    def record_performance_metric(
        self, 
        component: str, 
        metric_name: str, 
        value: float, 
        unit: str = "ms",
        labels: Optional[Dict] = None
    ) -> None:
        """Record performance metric for trend analysis."""
        with self._lock:
            metric_key = f"{component}.{metric_name}"
            self._performance_metrics[metric_key].append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "value": value,
                "unit": unit,
                "labels": labels or {},
            })
            
        # Keep only last 1000 entries per metric
        if len(self._performance_metrics[metric_key]) > 1000:
            self._performance_metrics[metric_key] = deque(
                list(self._performance_metrics[metric_key])[-1000:], 
                maxlen=1000
            )
            
        logger.debug(f"Performance metric: {component} - {metric_name} = {value} {unit}")
        
    def update_component_status(self, component: str, status: str, details: Optional[Dict] = None) -> None:
        """Update component operational status."""
        with self._lock:
            self._component_status[component] = {
                "status": status,
                "details": details or {},
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            
        logger.info(f"Component status: {component} - {status}")
        
    def get_startup_summary(self) -> Dict:
        """Get comprehensive startup timing summary."""
        with self._lock:
            if not self._startup_events:
                return {"status": "not_started"}
                
            start_time = self._startup_start_time
            complete_time = self._startup_complete_time
            
            if not complete_time:
                return {
                    "status": "in_progress",
                    "start_time": datetime.fromtimestamp(start_time, timezone.utc).isoformat() if start_time else None,
                    "duration_seconds": time.time() - start_time if start_time else None,
                    "events": self._startup_events,
                }
                
            total_duration = complete_time - start_time if start_time else 0
            
            # Calculate component startup times
            component_times = {}
            for event in self._startup_events:
                if event["event_type"] == "startup_complete":
                    component_times[event["component"]] = event.get("relative_time", 0)
                    
            return {
                "status": "completed",
                "start_time": datetime.fromtimestamp(start_time, timezone.utc).isoformat() if start_time else None,
                "complete_time": datetime.fromtimestamp(complete_time, timezone.utc).isoformat() if complete_time else None,
                "total_duration_seconds": total_duration,
                "component_startup_times": component_times,
                "events": self._startup_events,
            }
            
    def get_health_summary(self) -> Dict:
        """Get comprehensive health check summary."""
        with self._lock:
            summary = {
                "overall_status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "components": {},
                "failed_checks": [],
            }
            
            # Evaluate overall health
            for component, checks in self._health_checks.items():
                component_health = "healthy"
                failed_checks = []
                
                for check_type, check_data in checks.items():
                    if check_data["status"] != "healthy":
                        component_health = "unhealthy"
                        failed_checks.append({
                            "component": component,
                            "check_type": check_type,
                            "status": check_data["status"],
                            "details": check_data["details"],
                            "timestamp": check_data["timestamp"],
                        })
                        
                summary["components"][component] = {
                    "status": component_health,
                    "checks": checks,
                    "failed_check_count": len(failed_checks),
                }
                
                if component_health != "healthy":
                    summary["overall_status"] = "degraded"
                    summary["failed_checks"].extend(failed_checks)
                    
            return summary
            
    def get_performance_summary(self) -> Dict:
        """Get performance metrics summary with trends."""
        with self._lock:
            summary = {"metrics": {}}
            
            for metric_key, values in self._performance_metrics.items():
                if not values:
                    continue
                    
                component, metric_name = metric_key.split(".", 1)
                
                # Calculate statistics
                numeric_values = [v["value"] for v in values if isinstance(v["value"], (int, float))]
                if not numeric_values:
                    continue
                    
                recent_values = numeric_values[-100:]  # Last 100 values
                avg_value = sum(recent_values) / len(recent_values) if recent_values else 0
                min_value = min(recent_values) if recent_values else 0
                max_value = max(recent_values) if recent_values else 0
                
                # Trend calculation (simple linear trend)
                trend = "stable"
                if len(recent_values) >= 10:
                    first_half = recent_values[:len(recent_values)//2]
                    second_half = recent_values[len(recent_values)//2:]
                    first_avg = sum(first_half) / len(first_half)
                    second_avg = sum(second_half) / len(second_half)
                    if second_avg > first_avg * 1.1:
                        trend = "increasing"
                    elif second_avg < first_avg * 0.9:
                        trend = "decreasing"
                        
                summary["metrics"][metric_key] = {
                    "component": component,
                    "metric": metric_name,
                    "current": numeric_values[-1] if numeric_values else 0,
                    "average": avg_value,
                    "min": min_value,
                    "max": max_value,
                    "unit": values[-1]["unit"],
                    "trend": trend,
                    "sample_count": len(values),
                    "last_updated": values[-1]["timestamp"],
                }
                
            return summary
            
    def get_component_status(self) -> Dict:
        """Get current component status overview."""
        with self._lock:
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "components": self._component_status.copy(),
            }


# Global instance
observability_service = ObservabilityService()
