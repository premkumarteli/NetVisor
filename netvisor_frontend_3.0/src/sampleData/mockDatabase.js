// Mock dataset extracted and parsed from NetVisor DB Dumps (db_dump/2026-08-31_22-58-59)
// Provides realistic telemetry, device assets, traffic flows, security threats, web inspection evidence, agents & logs.

export const MOCK_SUMMARY_STATS = {
  active_devices: 14,
  total_devices: 18,
  flows_24h: 148920,
  high_threats: 3,
  medium_threats: 7,
  active_agents: 4,
  bandwidth_bytes_sec: 1420500, // ~1.4 MB/s
  bandwidth_formatted: "1.42 MB/s",
  active_vpn_tunnels: 2,
  inspection_status: "Active (Transparent Redaction Enabled)",
  gateway_status: "Online (Hotspot 192.168.137.1)"
};

export const MOCK_DEVICES = [
  {
    id: "DEV-1001",
    hostname: "DESKTOP-39F4JFO",
    ip: "192.168.137.230",
    mac: "C8:8D:83:2A:90:E1",
    vendor: "Dell Inc.",
    device_type: "Managed Workstation",
    os_family: "Windows 11 Pro",
    status: "Online",
    management_mode: "managed",
    risk_score: 82,
    risk_level: "HIGH",
    confidence: "Strong identity (Agent Verified)",
    top_application: "Chrome (Claude AI)",
    last_seen: "Just now",
    bytes_transferred: "4.8 GB",
    agent_id: "AGENT-B9A05094"
  },
  {
    id: "DEV-1002",
    hostname: "DESKTOP-IFIA9GL",
    ip: "10.4.3.47",
    mac: "00:15:5D:8A:12:4F",
    vendor: "Microsoft Corporation",
    device_type: "Hyper-V Guest",
    os_family: "Windows Server 2022",
    status: "Online",
    management_mode: "managed",
    risk_score: 24,
    risk_level: "LOW",
    confidence: "Strong identity (Agent Verified)",
    top_application: "Windows Update",
    last_seen: "2 mins ago",
    bytes_transferred: "12.4 GB",
    agent_id: "AGENT-D455C7A1"
  },
  {
    id: "DEV-1003",
    hostname: "iPhone-15-Pro-Prem",
    ip: "192.168.137.105",
    mac: "3E:A2:11:88:99:BC",
    vendor: "Apple Inc.",
    device_type: "Mobile Phone (BYOD)",
    os_family: "iOS 17.5",
    status: "Online",
    management_mode: "gateway_only",
    risk_score: 65,
    risk_level: "MEDIUM",
    confidence: "Usable identity (ARP + OUI)",
    top_application: "Safari (Instagram/Web)",
    last_seen: "Just now",
    bytes_transferred: "840 MB",
    agent_id: null
  },
  {
    id: "DEV-1004",
    hostname: "MacBookAir-M2-Prem",
    ip: "192.168.137.142",
    mac: "F4:D4:88:90:AA:12",
    vendor: "Apple Inc.",
    device_type: "BYOD Laptop",
    os_family: "macOS Sonoma",
    status: "Online",
    management_mode: "gateway_only",
    risk_score: 15,
    risk_level: "LOW",
    confidence: "Usable identity (DHCP Fingerprint)",
    top_application: "VS Code / GitHub",
    last_seen: "5 mins ago",
    bytes_transferred: "2.1 GB",
    agent_id: null
  },
  {
    id: "DEV-1005",
    hostname: "Unknown-IoT-Cam-01",
    ip: "192.168.137.201",
    mac: "50:EC:50:11:22:33",
    vendor: "Hikvision",
    device_type: "IP Security Camera",
    os_family: "Embedded Linux",
    status: "Idle",
    management_mode: "gateway_only",
    risk_score: 91,
    risk_level: "CRITICAL",
    confidence: "Needs Confirmation (MAC Vendor Only)",
    top_application: "RTSP / Outbound IP Connection",
    last_seen: "12 mins ago",
    bytes_transferred: "18.9 GB",
    agent_id: null
  }
];

export const MOCK_TRAFFIC_FLOWS = [
  {
    id: "FLOW-9901",
    src_ip: "192.168.137.230",
    src_device: "DESKTOP-39F4JFO",
    dst_ip: "160.79.104.10",
    domain: "platform.claude.com",
    application: "Claude AI Platform",
    category: "AI & LLM Services",
    protocol: "HTTPS (443)",
    byte_count: 4850200,
    formatted_volume: "4.62 MB",
    severity: "LOW",
    confidence: "0.95 (SNI + DPI Verified)",
    direction: "Outbound",
    timestamp: "2026-08-31T23:44:10Z"
  },
  {
    id: "FLOW-9902",
    src_ip: "192.168.137.201",
    src_device: "Unknown-IoT-Cam-01",
    dst_ip: "185.220.101.5",
    domain: "check.torproject.org",
    application: "Tor Anonymizer Exit Node",
    category: "Anonymizer / Proxy",
    protocol: "TCP (9001)",
    byte_count: 89400200,
    formatted_volume: "85.25 MB",
    severity: "CRITICAL",
    confidence: "0.99 (Threat Intelligence Match)",
    direction: "Outbound",
    timestamp: "2026-08-31T23:43:55Z"
  },
  {
    id: "FLOW-9903",
    src_ip: "10.4.3.47",
    src_device: "DESKTOP-IFIA9GL",
    dst_ip: "13.107.42.16",
    domain: "download.windowsupdate.com",
    application: "Windows Update",
    category: "OS & System Patching",
    protocol: "HTTPS (443)",
    byte_count: 240500100,
    formatted_volume: "229.35 MB",
    severity: "LOW",
    confidence: "0.90 (Domain Heuristic)",
    direction: "Outbound",
    timestamp: "2026-08-31T23:42:18Z"
  },
  {
    id: "FLOW-9904",
    src_ip: "192.168.137.105",
    src_device: "iPhone-15-Pro-Prem",
    dst_ip: "157.240.22.35",
    domain: "graph.instagram.com",
    application: "Instagram CDN",
    category: "Social Media",
    protocol: "QUIC (UDP 443)",
    byte_count: 14200500,
    formatted_volume: "13.54 MB",
    severity: "MEDIUM",
    confidence: "0.85 (Gateway Flow SNI)",
    direction: "Outbound",
    timestamp: "2026-08-31T23:40:02Z"
  },
  {
    id: "FLOW-9905",
    src_ip: "192.168.137.230",
    src_device: "DESKTOP-39F4JFO",
    dst_ip: "185.199.108.153",
    domain: "raw.githubusercontent.com",
    application: "GitHub Repository Data",
    category: "Developer Tools",
    protocol: "HTTPS (443)",
    byte_count: 1250400,
    formatted_volume: "1.19 MB",
    severity: "LOW",
    confidence: "0.95 (Agent TLS Handshake)",
    direction: "Outbound",
    timestamp: "2026-08-31T23:38:40Z"
  }
];

export const MOCK_APPLICATIONS = [
  {
    id: "APP-01",
    name: "Claude AI Platform",
    domain: "platform.claude.com",
    category: "Artificial Intelligence",
    risk_level: "LOW",
    confidence: 0.95,
    devices_using: 3,
    total_volume: "1.2 GB",
    policy_status: "Allowed",
    source_layer: "DPI + SNI"
  },
  {
    id: "APP-02",
    name: "Tor Project Anonymizer",
    domain: "check.torproject.org",
    category: "Anonymization & Proxy",
    risk_level: "CRITICAL",
    confidence: 0.99,
    devices_using: 1,
    total_volume: "450 MB",
    policy_status: "Blocked / Quarantined",
    source_layer: "Threat Intel Baseline"
  },
  {
    id: "APP-03",
    name: "Windows Update Service",
    domain: "download.windowsupdate.com",
    category: "System Infrastructure",
    risk_level: "LOW",
    confidence: 0.90,
    devices_using: 8,
    total_volume: "42.8 GB",
    policy_status: "Whitelisted",
    source_layer: "SLD Heuristics"
  },
  {
    id: "APP-04",
    name: "Dell Support Assist",
    domain: "csgdtm-svc-agent.dell.com",
    category: "Device Telemetry",
    risk_level: "LOW",
    confidence: 0.85,
    devices_using: 2,
    total_volume: "88 MB",
    policy_status: "Allowed",
    source_layer: "SLD Heuristics"
  },
  {
    id: "APP-05",
    name: "Starfield Certificate Authority",
    domain: "crl.starfieldtech.com",
    category: "PKI & Trust Verification",
    risk_level: "LOW",
    confidence: 0.85,
    devices_using: 12,
    total_volume: "14 MB",
    policy_status: "Allowed",
    source_layer: "SLD Heuristics"
  }
];

export const MOCK_THREATS = [
  {
    id: "THREAT-801",
    title: "Unauthorized Tor Exit Node Communication",
    severity: "CRITICAL",
    score: 95,
    device: "Unknown-IoT-Cam-01 (192.168.137.201)",
    engine: "ThreatIntelEngine / AnonymizerDetector",
    status: "Active Alert",
    summary: "Device 192.168.137.201 established persistent outbound TCP connection to verified Tor relay node 185.220.101.5.",
    timestamp: "10 mins ago",
    recommendation: "Isolate IP 192.168.137.201 at gateway router and inspect device firmware."
  },
  {
    id: "THREAT-802",
    title: "Unencrypted Sensitive Keyword Transmission",
    severity: "HIGH",
    score: 78,
    device: "DESKTOP-39F4JFO (192.168.137.230)",
    engine: "DpiInspectionEngine / SensitiveRedactor",
    status: "Mitigated (Redacted)",
    summary: "Form payload contained unencrypted string pattern 'api_secret_key=***REDACTED***' over plain HTTP session.",
    timestamp: "28 mins ago",
    recommendation: "Transparent proxy automatically redacted sensitive payload. Upgrade host configuration to HTTPS."
  },
  {
    id: "THREAT-803",
    title: "Suspicious High-Volume UDP Burst",
    severity: "MEDIUM",
    score: 62,
    device: "iPhone-15-Pro-Prem (192.168.137.105)",
    engine: "AnomalyEngine / FlowBurstDetector",
    status: "Under Observation",
    summary: "Mobile device initiated >4,000 UDP packets within 15 seconds targeting non-standard port 4433.",
    timestamp: "1 hour ago",
    recommendation: "Monitor session for potential QUIC fallback or tunnel encapsulation."
  }
];

export const MOCK_DPI_EVIDENCE = [
  {
    id: "DPI-5001",
    domain: "platform.claude.com",
    path: "/api/v1/chat/completions",
    process: "chrome.exe",
    device: "DESKTOP-39F4JFO (192.168.137.230)",
    http_method: "POST",
    status_code: 200,
    content_type: "application/json",
    snippet: '{"prompt": "Refactor React frontend components...", "model": "claude-3-5-sonnet"}',
    redaction_status: "Clean (No PII Detected)",
    confidence: "0.98",
    timestamp: "2 mins ago"
  },
  {
    id: "DPI-5002",
    domain: "downloads.example.org",
    path: "/payload.bin?user_token=REDACTED_AUTH_TOKEN",
    process: "msedge.exe",
    device: "DESKTOP-39F4JFO (192.168.137.230)",
    http_method: "GET",
    status_code: 302,
    content_type: "application/octet-stream",
    snippet: "Binary executable download payload header [MZ...]",
    redaction_status: "Sensitive Auth Token Auto-Redacted",
    confidence: "0.94",
    timestamp: "15 mins ago"
  }
];

export const MOCK_AGENTS = [
  {
    id: "AGENT-B9A05094",
    hostname: "DESKTOP-39F4JFO",
    ip: "192.168.137.230",
    os: "Windows 11 Pro",
    version: "v3.0-hybrid",
    status: "Online",
    cpu_usage: "24.2%",
    ram_usage: "85.3%",
    mtls_cert: "Valid (Expires 2027-04-30)",
    browsers: "Chrome, Edge",
    privacy_guard: "Enabled"
  },
  {
    id: "AGENT-D455C7A1",
    hostname: "DESKTOP-IFIA9GL",
    ip: "10.4.3.47",
    os: "Windows Server 2022",
    version: "v3.0-hybrid",
    status: "Online",
    cpu_usage: "56.0%",
    ram_usage: "75.4%",
    mtls_cert: "Valid (Expires 2027-08-31)",
    browsers: "Chrome, Edge, Firefox, Brave",
    privacy_guard: "Enabled"
  }
];

export const MOCK_LOGS = [
  {
    id: "LOG-3001",
    level: "INFO",
    module: "gateway.sensor_ingest",
    message: "Pooled flow log batch #4928 ingested successfully. 1,420 flows processed in 14ms.",
    timestamp: "2026-08-31 23:44:02"
  },
  {
    id: "LOG-3002",
    level: "WARN",
    module: "security.mtls_verifier",
    message: "CRL Revocation check cache miss for agent AGENT-B9A05094. Non-blocking verification passed.",
    timestamp: "2026-08-31 23:41:15"
  },
  {
    id: "LOG-3003",
    level: "CRITICAL",
    module: "engine.threat_intel",
    message: "ALERT: Threat signature MATCH (Rule #801) - Tor exit node connection from 192.168.137.201.",
    timestamp: "2026-08-31 23:35:10"
  }
];

export const MOCK_USERS = [
  {
    id: "USR-01",
    username: "admin",
    role: "System Administrator",
    email: "admin@netvisor.internal",
    status: "Active",
    last_login: "Just now",
    mfa_enabled: true
  },
  {
    id: "USR-02",
    username: "operator",
    role: "SOC Analyst",
    email: "operator@netvisor.internal",
    status: "Active",
    last_login: "3 hours ago",
    mfa_enabled: true
  }
];

export const MOCK_VPN_TUNNELS = [
  {
    id: "VPN-101",
    user: "admin",
    client_ip: "192.168.137.230",
    assigned_vpn_ip: "10.8.0.2",
    protocol: "WireGuard",
    cipher: "ChaCha20-Poly1305",
    bytes_in: "1.4 GB",
    bytes_out: "4.2 GB",
    connected_at: "2 hours ago",
    status: "Active Tunnel"
  }
];
