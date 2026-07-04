import time
import sys
import gc

class Node:
    def __init__(self, node_id: str, node_type: str):
        self.id = node_id
        self.type = node_type
        self.neighbors = set()

class Edge:
    def __init__(self, u: str, v: str, expires_at: float):
        self.u = u
        self.v = v
        self.expires_at = expires_at

class TimeWheel:
    def __init__(self, num_slots: int = 3600):
        self.num_slots = num_slots
        self.slots = [set() for _ in range(num_slots)]
        self.current_slot = 0
        self.edge_to_slot = {}

    def add_edge(self, edge: Edge, current_time: float):
        ticks = int(max(0.0, edge.expires_at - current_time))
        target_slot = (self.current_slot + ticks) % self.num_slots
        self.slots[target_slot].add((edge.u, edge.v))
        self.edge_to_slot[(edge.u, edge.v)] = target_slot

    def tick(self) -> list:
        expired = self.slots[self.current_slot]
        self.slots[self.current_slot] = set()
        self.current_slot = (self.current_slot + 1) % self.num_slots
        
        # Clean from mapping
        for edge_key in expired:
            self.edge_to_slot.pop(edge_key, None)
            
        return list(expired)

class PythonCorrelationEngine:
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        self.time_wheel = TimeWheel()

    def add_node(self, node_id: str, node_type: str):
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(node_id, node_type)

    def add_edge(self, u_id: str, u_type: str, v_id: str, v_type: str, ttl: float, current_time: float):
        self.add_node(u_id, u_type)
        self.add_node(v_id, v_type)
        
        edge_key = (u_id, v_id)
        expires_at = current_time + ttl
        
        edge = Edge(u_id, v_id, expires_at)
        self.edges[edge_key] = edge
        self.nodes[u_id].neighbors.add(v_id)
        self.nodes[v_id].neighbors.add(u_id)
        
        self.time_wheel.add_edge(edge, current_time)

    def traverse(self, start_id: str) -> set:
        """BFS traversal to find all connected nodes (Incident extraction)."""
        visited = set()
        if start_id not in self.nodes:
            return visited
            
        queue = [start_id]
        visited.add(start_id)
        
        while queue:
            curr = queue.pop(0)
            for neighbor in self.nodes[curr].neighbors:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        return visited

    def expire_edges(self, current_time: float) -> int:
        expired_edges = self.time_wheel.tick()
        count = 0
        for u, v in expired_edges:
            edge_key = (u, v)
            if edge_key in self.edges:
                del self.edges[edge_key]
                count += 1
                # Remove neighbor links
                if u in self.nodes:
                    self.nodes[u].neighbors.discard(v)
                if v in self.nodes:
                    self.nodes[v].neighbors.discard(u)
        
        # Clean up isolated nodes
        isolated = [node_id for node_id, node in self.nodes.items() if not node.neighbors]
        for node_id in isolated:
            del self.nodes[node_id]
            
        return count

def run_workload():
    engine = PythonCorrelationEngine()
    
    # 1. Benchmark Insertion
    t_start = time.perf_counter()
    num_ops = 100000
    for i in range(num_ops):
        # Alternate connecting IPs, MACs, Domains, and Alerts
        ip = f"ip_{i % 5000}"
        mac = f"mac_{i % 3000}"
        domain = f"domain_{i % 2000}"
        alert = f"alert_{i}"
        
        engine.add_edge(ip, "IP", mac, "MAC", ttl=100.0, current_time=0.0)
        engine.add_edge(mac, "MAC", domain, "DOMAIN", ttl=100.0, current_time=0.0)
        engine.add_edge(ip, "IP", alert, "ALERT", ttl=2.0, current_time=0.0)
        
    insert_duration = time.perf_counter() - t_start
    insert_throughput = (num_ops * 3) / insert_duration # 3 edges per iteration
    
    # Measure memory size
    gc.collect()
    # Estimate size in MB (using system's internal check or python object count approximation)
    mem_size = sys.getsizeof(engine.nodes) + sys.getsizeof(engine.edges)
    # Estimate real process RSS if possible
    try:
        import psutil
        process = psutil.Process()
        mem_rss = process.memory_info().rss / (1024 * 1024)
    except ImportError:
        mem_rss = mem_size / (1024 * 1024)
        
    # 2. Benchmark Traversal
    num_traversals = 10000
    traversal_times = []
    for i in range(num_traversals):
        start_node = f"ip_{i % 5000}"
        t0 = time.perf_counter()
        engine.traverse(start_node)
        traversal_times.append(time.perf_counter() - t0)
        
    traversal_times.sort()
    p50_traversal_ms = traversal_times[int(num_traversals * 0.50)] * 1000
    p95_traversal_ms = traversal_times[int(num_traversals * 0.95)] * 1000
    p99_traversal_ms = traversal_times[int(num_traversals * 0.99)] * 1000
    
    # 3. Benchmark Expiration Clean-up
    # Advance time to expire alerts (ttl was 2.0)
    t_start = time.perf_counter()
    expired_count = engine.expire_edges(current_time=3.0)
    cleanup_duration = time.perf_counter() - t_start
    
    import json
    results = {
        "language": "Python",
        "insert_throughput_eps": insert_throughput,
        "p50_traversal_ms": p50_traversal_ms,
        "p95_traversal_ms": p95_traversal_ms,
        "p99_traversal_ms": p99_traversal_ms,
        "cleanup_duration_ms": cleanup_duration * 1000,
        "expired_count": expired_count,
        "rss_mb": mem_rss
    }
    print(json.dumps(results))

if __name__ == "__main__":
    run_workload()
