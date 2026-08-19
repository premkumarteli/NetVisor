use petgraph::graph::{NodeIndex, UnGraph};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

#[derive(Serialize)]
struct BenchmarkResults {
    language: String,
    insert_throughput_eps: f64,
    p50_traversal_ms: f64,
    p95_traversal_ms: f64,
    p99_traversal_ms: f64,
    cleanup_duration_ms: f64,
    expired_count: usize,
    rss_mb: f64,
}

struct Node {
    id: String,
    node_type: String,
}

struct Edge {
    u: String,
    v: String,
    expires_at: f64,
}

struct TimeWheel {
    num_slots: usize,
    slots: Vec<HashSet<(String, String)>>,
    current_slot: usize,
    edge_to_slot: HashMap<(String, String), usize>,
}

impl TimeWheel {
    fn new(num_slots: usize) -> Self {
        Self {
            num_slots,
            slots: vec![HashSet::new(); num_slots],
            current_slot: 0,
            edge_to_slot: HashMap::new(),
        }
    }

    fn add_edge(&mut self, u: &str, v: &str, expires_at: f64, current_time: f64) {
        let ticks = ((expires_at - current_time).max(0.0) as usize);
        let target_slot = (self.current_slot + ticks) % self.num_slots;
        let edge_key = (u.to_string(), v.to_string());
        self.slots[target_slot].insert(edge_key.clone());
        self.edge_to_slot.insert(edge_key, target_slot);
    }

    fn tick(&mut self) -> Vec<(String, String)> {
        let expired = std::mem::take(&mut self.slots[self.current_slot]);
        self.current_slot = (self.current_slot + 1) % self.num_slots;

        for edge_key in &expired {
            self.edge_to_slot.remove(edge_key);
        }

        expired.into_iter().collect()
    }
}

struct RustCorrelationEngine {
    graph: UnGraph<Node, ()>,
    id_to_index: HashMap<String, NodeIndex>,
    edges: HashMap<(String, String), Edge>,
    time_wheel: TimeWheel,
}

impl RustCorrelationEngine {
    fn new() -> Self {
        Self {
            graph: UnGraph::new_undirected(),
            id_to_index: HashMap::new(),
            edges: HashMap::new(),
            time_wheel: TimeWheel::new(3600),
        }
    }

    fn get_or_create_node(&mut self, id: &str, node_type: &str) -> NodeIndex {
        if let Some(&idx) = self.id_to_index.get(id) {
            idx
        } else {
            let idx = self.graph.add_node(Node {
                id: id.to_string(),
                node_type: node_type.to_string(),
            });
            self.id_to_index.insert(id.to_string(), idx);
            idx
        }
    }

    fn add_edge(&mut self, u_id: &str, u_type: &str, v_id: &str, v_type: &str, ttl: f64, current_time: f64) {
        let u_idx = self.get_or_create_node(u_id, u_type);
        let v_idx = self.get_or_create_node(v_id, v_type);

        let edge_key = (u_id.to_string(), v_id.to_string());
        let expires_at = current_time + ttl;

        // Check if edge already exists in petgraph
        if !self.edges.contains_key(&edge_key) {
            self.graph.add_edge(u_idx, v_idx, ());
        }

        self.edges.insert(
            edge_key.clone(),
            Edge {
                u: u_id.to_string(),
                v: v_id.to_string(),
                expires_at,
            },
        );

        self.time_wheel.add_edge(u_id, v_id, expires_at, current_time);
    }

    fn traverse(&self, start_id: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let start_idx = match self.id_to_index.get(start_id) {
            Some(&idx) => idx,
            None => return visited,
        };

        let mut queue = VecDeque::new();
        queue.push_back(start_idx);
        visited.insert(start_id.to_string());

        while let Some(curr_idx) = queue.pop_front() {
            for neighbor_idx in self.graph.neighbors(curr_idx) {
                let neighbor_id = &self.graph[neighbor_idx].id;
                if !visited.contains(neighbor_id) {
                    visited.insert(neighbor_id.clone());
                    queue.push_back(neighbor_idx);
                }
            }
        }

        visited
    }

    fn expire_edges(&mut self, current_time: f64) -> usize {
        let expired_edges = self.time_wheel.tick();
        let mut expired_count = 0;

        for (u, v) in expired_edges {
            let edge_key = (u.clone(), v.clone());
            if self.edges.remove(&edge_key).is_some() {
                expired_count += 1;

                // In petgraph, remove the edge
                if let (Some(&u_idx), Some(&v_idx)) = (self.id_to_index.get(&u), self.id_to_index.get(&v)) {
                    if let Some(edge_idx) = self.graph.find_edge(u_idx, v_idx) {
                        self.graph.remove_edge(edge_idx);
                    }
                }
            }
        }

        // Clean up isolated nodes
        let mut isolated_ids = Vec::new();
        for (id, &idx) in &self.id_to_index {
            if self.graph.neighbors(idx).count() == 0 {
                isolated_ids.push(id.clone());
            }
        }

        for id in isolated_ids {
            if let Some(idx) = self.id_to_index.remove(&id) {
                self.graph.remove_node(idx);
            }
        }

        expired_count
    }
}

#[tokio::main]
async fn main() {
    let mut engine = RustCorrelationEngine::new();
    let num_ops = 100000;

    // 1. Benchmark Insertion
    let t_start = Instant::now();
    for i in 0..num_ops {
        let ip = format!("ip_{}", i % 5000);
        let mac = format!("mac_{}", i % 3000);
        let domain = format!("domain_{}", i % 2000);
        let alert = format!("alert_{}", i);

        engine.add_edge(&ip, "IP", &mac, "MAC", 100.0, 0.0);
        engine.add_edge(&mac, "MAC", &domain, "DOMAIN", 100.0, 0.0);
        engine.add_edge(&ip, "IP", &alert, "ALERT", 2.0, 0.0);
    }
    let insert_duration = t_start.elapsed().as_secs_f64();
    let insert_throughput = (num_ops as f64 * 3.0) / insert_duration;

    // Measure memory (using system RSS on platforms support it, or zero/approx)
    // Measure memory (using system RSS on platforms support it, or zero/approx)
    let rss_mb = get_rss_mb();

    // 2. Benchmark Traversal
    let num_traversals = 10000;
    let mut traversal_times = Vec::with_capacity(num_traversals);
    for i in 0..num_traversals {
        let start_node = format!("ip_{}", i % 5000);
        let t0 = Instant::now();
        engine.traverse(&start_node);
        traversal_times.push(t0.elapsed().as_secs_f64());
    }
    traversal_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50_traversal_ms = traversal_times[(num_traversals as f64 * 0.50) as usize] * 1000.0;
    let p95_traversal_ms = traversal_times[(num_traversals as f64 * 0.95) as usize] * 1000.0;
    let p99_traversal_ms = traversal_times[(num_traversals as f64 * 0.99) as usize] * 1000.0;

    // 3. Benchmark Expiration Clean-up
    let t_start = Instant::now();
    let expired_count = engine.expire_edges(3.0);
    let cleanup_duration = t_start.elapsed().as_secs_f64();

    let results = BenchmarkResults {
        language: "Rust".to_string(),
        insert_throughput_eps: insert_throughput,
        p50_traversal_ms,
        p95_traversal_ms,
        p99_traversal_ms,
        cleanup_duration_ms: cleanup_duration * 1000.0,
        expired_count,
        rss_mb,
    };

    println!("{}", serde_json::to_string(&results).unwrap());
}

#[cfg(target_os = "windows")]
fn get_rss_mb() -> f64 {
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    let handle = unsafe { GetCurrentProcess() };
    let success = unsafe {
        GetProcessMemoryInfo(
            handle,
            &mut pmc,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if success != 0 {
        (pmc.WorkingSetSize as f64) / (1024.0 * 1024.0)
    } else {
        0.0
    }
}

#[cfg(not(target_os = "windows"))]
fn get_rss_mb() -> f64 {
    if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = statm.split_whitespace().collect();
        if let Some(rss_pages_str) = parts.get(1) {
            if let Ok(rss_pages) = rss_pages_str.parse::<usize>() {
                return (rss_pages * 4096) as f64 / (1024.0 * 1024.0);
            }
        }
    }
    0.0
}
