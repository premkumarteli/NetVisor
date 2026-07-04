from datetime import datetime, timezone

class ReplayGenerator:
    """Generates realistic multi-dataset synthetic network flow records."""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def generate_flow_batch(self, batch_size: int, org_id: str, start_index: int) -> list:
        import random
        flows = []
        t_base = datetime.now(timezone.utc)
        # Random second offset to avoid collision with previous test run logs
        run_salt = random.randint(1, 100000)
        
        for i in range(batch_size):
            idx = start_index + i
            dataset_type = idx % 4
            
            # Generate high-resolution microsecond timestamp unique to this flow
            t_flow = t_base.replace(microsecond=(i * 1000 + run_salt) % 1000000).isoformat()
            
            # Base Flow Template
            flow = {
                "src_ip": f"192.168.1.{10 + (idx % 240)}",
                "dst_ip": f"10.0.0.{5 + (idx % 250)}",
                "src_port": 1024 + (idx % 60000),
                "dst_port": 80,
                "protocol": "TCP",
                "packet_count": 10 + (idx % 100),
                "byte_count": 500 + (idx % 10000),
                "duration": 0.5 + (idx % 50) / 10.0,
                "agent_id": self.agent_id,
                "organization_id": org_id,
                "start_time": t_flow,
                "last_seen": t_flow,
                "average_packet_size": 150.0,
                "source_type": "agent",
                "metadata_only": False,
                "event_type": "FLOW_UPDATE"
            }
            
            # Mimic Specific Datasets
            if dataset_type == 0:
                # CTU-13 Botnet (Beacons)
                flow["dst_ip"] = "203.0.113.50"
                flow["dst_port"] = 8080
                flow["packet_count"] = 5
                flow["byte_count"] = 250
                flow["duration"] = 0.1
                flow["analysis_signals"] = ["periodic_beaconing"]
            elif dataset_type == 1:
                # CIC-IDS2017 Port Scan
                flow["src_ip"] = "192.168.1.150"
                flow["dst_ip"] = "192.168.1.1"
                flow["dst_port"] = idx % 1000
                flow["analysis_signals"] = ["port_scanning"]
            elif dataset_type == 2:
                # MAWI high speed traffic (mostly random IP space)
                flow["src_ip"] = f"{idx % 223}.{idx % 255}.{idx % 255}.1"
                flow["dst_ip"] = "8.8.8.8"
                flow["dst_port"] = 53
                flow["protocol"] = "UDP"
            else:
                # Synthetic Enterprise Web Requests
                flow["domain"] = "example-enterprise.com"
                flow["sni"] = "example-enterprise.com"
                flow["dst_port"] = 443
                
            flows.append(flow)
        return flows
