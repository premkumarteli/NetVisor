"""
Packet capture coordination and processing.
"""

import logging
from typing import Callable, Optional, Dict, Any

from colorama import Fore
from shared.collector import (
    DomainHintCache,
    FlowManager,
    PacketObservation,
    build_capture_backend,
)

logger = logging.getLogger(__name__)


class CaptureManager:
    """Manages packet capture backend and processing."""
    
    def __init__(
        self,
        agent_id: str,
        organization_id: str,
        flow_manager: FlowManager,
        domain_cache: DomainHintCache,
        interface: Optional[str] = None,
        backend_name: str = "auto",
        verbose: bool = False
    ):
        self.agent_id = agent_id
        self.organization_id = organization_id
        self.flow_manager = flow_manager
        self.domain_cache = domain_cache
        self.interface = interface
        self.backend_name = backend_name
        self.verbose = verbose
        
        self.capture_backend = build_capture_backend(
            role="agent",
            interface=interface,
            requested_backend=backend_name,
        )
        
    def process_packet(self, packet) -> bool:
        """Process a single packet through the flow manager."""
        try:
            observation = PacketObservation.from_packet(
                packet,
                source_type="agent",
                metadata_only=False,
                domain_cache=self.domain_cache,
            )
            if observation is None:
                return False
                
            if observation.domain and self.verbose:
                print(f"{Fore.CYAN}[APP]{Fore.RESET} {observation.src_ip} -> {observation.domain}")
                
            self.flow_manager.update_from_observation(observation)
            return True
            
        except Exception as e:
            logger.error(f"Packet processing error: {e}")
            return False
            
    def start(self, packet_handler: Optional[Callable] = None, timeout: Optional[int] = None) -> tuple[bool, Optional[str]]:
        """Start packet capture with optional timeout."""
        handler = packet_handler or self.process_packet
        return self.capture_backend.start(handler, timeout=timeout)
        
    def stop(self) -> None:
        """Stop packet capture."""
        self.capture_backend.stop()
        
    def fallback_to_scapy(self) -> tuple[bool, Optional[str]]:
        """Fallback to Scapy backend if primary backend fails."""
        logger.warning("Primary capture backend failed. Falling back to Scapy.")
        self.capture_backend.stop()
        self.capture_backend = build_capture_backend(
            role="agent",
            interface=self.interface,
            requested_backend="scapy",
        )
        return self.capture_backend.start(self.process_packet)
        
    def status_snapshot(self) -> Dict[str, Any]:
        """Get status snapshot of capture backend."""
        return self.capture_backend.status_snapshot()
