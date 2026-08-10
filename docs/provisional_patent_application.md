# PATENT APPLICATION SPECIFICATION

**DOCKET NO.:** NV-PAT-2026-001  
**CONFIDENTIAL DOCUMENT — PREPARED FOR PATENT FILING**

---

# TITLE OF THE INVENTION
**PRIVACY-PRESERVING MULTI-SOURCE NETWORK THREAT ASSESSMENT USING RECURSIVE CORRELATION AND NON-DILUTIVE RISK AGGREGATION**

---

## APPLICATION METADATA & COVER

* **Title of Invention:** Privacy-Preserving Multi-Source Network Threat Assessment Using Recursive Correlation and Non-Dilutive Risk Aggregation
* **Primary Inventor:** Prem Kumar Teli et al.
* **Filing Date:** July 31, 2026
* **Classification:** 
  * **USPC:** 726/22, 726/23, 726/25, 709/224
  * **CPC:** H04L63/1408, H04L63/1416, H04L63/1425, H04L63/1433, G06F21/552
* **Notice of Confidentiality:** The information contained in this patent application specification contains proprietary, trade-secret, and confidential technical material owned by the inventors and assignees. Unauthorized distribution, copying, or reverse engineering is strictly prohibited.

---

## TABLE OF CONTENTS
1. **Technical Field**
2. **Background of the Invention**
3. **Problems Solved by the Invention**
4. **Summary of the Invention**
5. **Brief Description of the Drawings (Figures 1–15)**
6. **Detailed Description of Preferred Embodiments**
   * *Chapter 1: Dual Telemetry Architecture & Payload Isolation*
   * *Chapter 2: Multi-Source Evidence Confidence Engine*
   * *Chapter 3: Threat Detection Pipeline & Analytics*
   * *Chapter 4: Encrypted Traffic & VPN Detection Engine*
   * *Chapter 5: Structured Finding Object & Inter-Engine Data Model*
   * *Chapter 6: Risk History Store, Half-Life Decay, and TTL Pruning*
   * *Chapter 7: Recursive Correlation Engine & Synthetic Finding Injection*
   * *Chapter 8: Non-Dilutive Risk Aggregation Engine*
   * *Chapter 9: Decoupled Suppression Store & State Retention*
   * *Chapter 10: AI Explanatory Engine & Remediation Mapping*
7. **Experimental Evaluation & Performance Benchmarks**
8. **Industrial Applications**
9. **Technical Advantages of the Invention**
10. **Patent Claims Set**
    * *Independent Claims 1–3*
    * *Dependent Claims 4–23*
11. **Abstract of the Disclosure**
12. **Novelty & Codebase Evidence Support Mapping**

---

## 1. TECHNICAL FIELD

The present invention relates generally to computer network security, Network Detection and Response (NDR), Endpoint Detection and Response (EDR), Security Information and Event Management (SIEM), and privacy-preserving telemetry processing. More particularly, the invention relates to computer-implemented systems and methods for fusing heterogeneous telemetry sources from managed endpoints and unmanaged Bring-Your-Own-Device (BYOD) network gateways into a unified risk assessment framework using multi-source evidence confidence tracking, recursive threat correlation, continuous exponential half-life time decay, and non-dilutive composite risk score aggregation.

---

## 2. BACKGROUND OF THE INVENTION

Modern enterprise computing environments are increasingly complex, characterized by a mix of enterprise-managed devices (e.g., corporate laptops and servers) and unmanaged, heterogeneous Bring-Your-Own-Device (BYOD) endpoints (e.g., personal smartphones, tablets, IoT appliances). Securing these hybrid networks presents severe technical challenges that existing network security tools fail to address adequately.

Traditional network monitoring systems rely on one of two paradigms:
1. **Agent-Based Endpoint Inspection (EDR/SIEM):** Endpoint software agents are installed on devices to inspect local memory, processes, and network sockets. While effective for managed endpoints, EDR solutions raise severe user privacy concerns because they frequently extract and transmit raw application payloads, credentials, and private communication snippets to centralized cloud servers. Furthermore, EDR agents cannot be installed on unmanaged BYOD devices, personal smartphones, or third-party vendor hardware, leaving critical blind spots in the enterprise perimeter.
2. **Gateway-Based Deep Packet Inspection (NDR/NGFW):** Network gateways inspect traffic in-flight. However, deep packet inspection (DPI) at the gateway requires resource-intensive SSL/TLS decryption (TLS man-in-the-middle inspection), which breaks end-to-end encryption, degrades network throughput, and violates compliance regulations (e.g., GDPR, HIPAA) by decrypting private user payloads.

Furthermore, conventional Security Information and Event Management (SIEM) risk scoring engines suffer from fundamental mathematical flaws:
* **Alert Dilution in Weighted Averaging:** Most conventional scoring engines compute risk by taking a weighted average of active alerts. When a single critical exploit alert (e.g., Risk Score = 90) is averaged with multiple low-severity background telemetry events (e.g., 9 events of Risk Score = 10), the calculated average drops to 18 (LOW risk). The critical security alert is "diluted" and hidden from security analysts under routine operational noise.
* **Blindness to Compound Attacks in Max-Only Scoring:** Alternative systems attempt to prevent dilution by returning only the maximum alert score ($\max(S_i)$). However, max-only scoring treats a device with a single minor anomaly (Score = 40) identically to a device simultaneously undergoing multi-stage reconnaissance, VPN tunneling, brute-force login attempts, and command-and-control (C2) beaconing (each Score = 40). Max-only scoring fails to reflect the exponential increase in compromise probability when multiple independent attack vectors co-occur.
* **Alert Flooding in Pure Summation:** Systems that sum alert scores ($\sum S_i$) suffer from immediate ceiling saturation, pushing risk scores to maximum (100) from minor background noise and inducing severe analyst alarm fatigue.
* **Rigid Event Deletion:** Traditional SIEMs manage alert history using rigid time boundaries (e.g., deleting events older than 24 hours). This creates artificial boundary drops where threat risk instantly resets to zero, ignoring the continuous mathematical decay of threat relevance over time.

Consequently, there is an urgent need in the art for an intelligent, privacy-preserving network security framework that bridges the visibility gap between managed endpoints and unmanaged BYOD devices without transmitting raw application payloads, while mathematically eliminating alert dilution, preventing false-positive ceiling saturation, and continuously evaluating compound threat risk.

---

## 3. PROBLEMS SOLVED BY THE INVENTION

The present invention solves the aforementioned technical problems through a novel system architecture and processing pipeline:

1. **Elimination of Alert Dilution:** Implements an anchor-plus-dampened-sum risk aggregation algorithm ($\text{MaxScore} + 0.1 \times \sum \text{Others}$) that anchors the baseline risk to the single most severe active threat, guaranteeing that low-severity operational noise can never dilute or mask a critical security alert.
2. **Quantification of Compound Multi-Vector Attacks:** Incorporates a controlled $10\%$ corroboration multiplier ($0.1 \times \text{Others}$) for secondary active findings, ensuring that co-occurring threats across independent engines elevate the overall composite risk score without causing false-positive score saturation.
3. **Privacy-Preserving Telemetry Separation:** Establishes a dual-monitoring model that isolates raw packet payload inspection strictly within local agent memory on managed endpoints (transmitting only sanitized evidence snippets and metadata), while unmanaged BYOD endpoints are monitored at the gateway exclusively via non-payload metadata flows (IPs, ports, protocols, flow durations, TLS SNI, JA4 fingerprints, DNS metadata).
4. **Recursive Evidence Correlation:** Implements a correlation engine that evaluates active, decayed findings across sliding temporal windows and, upon matching multi-stage attack rules (e.g., VPN usage + Port Scanning), generates a *synthetic correlation finding* with its own base score ($80.0$). This synthetic finding is recursively re-injected into the active finding history store, instantaneously updating the device risk score.
5. **Decoupled Suppression & State Retention:** Decouples notification suppression (hiding duplicate alert UI notifications within a 60-second window) from internal risk state calculation, ensuring that suppressed notifications retain their full mathematical contribution to the target device's composite risk score.
6. **Continuous Half-Life Evidence Decay:** Replaces binary alert expiration with continuous exponential half-life time decay ($S(t) = S_0 \times 0.5^{t / T_{1/2}}$), modeling the natural decay of threat relevance over time while pruning expired records via Time-To-Live (TTL) boundaries.
7. **Heterogeneous Passive Device Identification:** Calculates device confidence scores using a weighted linear combination of passive discovery evidence (DHCPOption 55/60, mDNS, SSDP, OUI, Hostname), triggering active port probing as a safety fallback strictly when passive confidence falls below a low-confidence threshold ($< 0.50$).

---

## 4. SUMMARY OF THE INVENTION

The present invention discloses a computer-implemented system, method, and computer-readable medium for privacy-preserving network security monitoring, threat detection, and composite risk assessment.

In a preferred embodiment, the system includes a dual telemetry intake module comprising:
* **Managed Endpoint Software Agents:** Operating on managed computing devices, executing local packet inspection within local memory, redacting sensitive credentials and application payloads, and transmitting only structured metadata and evidence findings to a central backend.
* **Gateway Monitoring Probes:** Operating on network gateways, capturing non-payload flow telemetry (IP addresses, network ports, protocols, flow durations, packet counts, DNS metadata, and TLS client fingerprints) for unmanaged Bring-Your-Own-Device (BYOD) endpoints without storing or inspecting application payloads.

The backend pipeline includes a centralized **Engine Registry** that executes an ordered sequence of detection and evaluation engines:
1. **Device Identification Engine:** Accumulates passive evidence from DHCP fingerprints, mDNS service announcements, SSDP UPnP advertisements, IEEE OUI vendor lookups, and hostnames into an `EvidenceTracker`. Calculates a continuous total confidence score:
   $$\text{TotalConfidence} = \min\left(1.0, \sum_{i} w_i \times c_i\right)$$
   If passive confidence falls below $0.50$, the system conditionally executes an active TCP port prober across a restricted set of common service ports to refine device classification.
2. **Encrypted Traffic & VPN Engine:** Analyzes TLS Client Hello characteristics, JA4 fingerprints, Autonomous System Number (ASN) ownership, and flow timing to generate weighted VPN detection findings.
3. **Threat Engine:** Executes specialized detectors for Port Scanning (sliding window port count), Brute Force attacks (rapid short-duration login attempts), C2 Beaconing (Coefficient of Variation $\text{COV} \le 0.10$ on packet inter-arrival times), and DNS Tunneling (Shannon entropy $H(X) > 3.8$ on subdomain labels and sliding TTL Bloom filter unique subdomain counts).
4. **Risk History Store:** Stores active findings per target IP in a thread-safe, in-memory history dictionary (`defaultdict(list)`). When an incoming finding arrives, existing active findings of the same `(engine, finding_type)` are replaced to renew timestamps and prevent duplication.
5. **Continuous Exponential Decay:** Applies exponential half-life time decay to all active findings:
   $$S(t) = \text{BaseScore} \times 0.5^{\left(\frac{\text{AgeSeconds}}{T_{1/2}}\right)}$$
   where $T_{1/2} = 300.0$ seconds (5 minutes). Findings exceeding their TTL (default 300s to 3600s) are automatically pruned.
6. **Recursive Correlation Engine:** Evaluates active decayed findings against a rule graph (e.g., VPN Detection + Port Scan $\rightarrow$ Credential Attack; Beaconing + DNS Tunneling $\rightarrow$ Active C2). Upon matching a rule, the engine creates a synthetic correlation finding (Base Score = 80.0) and recursively re-injects it into the target IP's active history store.
7. **Non-Dilutive Risk Aggregation Engine:** Sorts all active decayed scores and correlation scores for a target IP in descending order ($S_1 \ge S_2 \ge \dots \ge S_N$) and computes the composite risk score:
   $$\text{RiskScore} = \min\left(100, \text{round}\left(S_1 + 0.1 \times \sum_{i=2}^{N} S_i\right)\right)$$
8. **Decoupled Suppression Store:** Filters dashboard alert notifications within a sliding suppression window (60s) to prevent UI alert spam, while maintaining the underlying findings within the risk history store so they retain their full mathematical contribution to the target device's composite risk score.
9. **AI Explanatory Engine:** Reads the finalized risk score and findings, generating natural language executive summaries, top-priority remediation steps, and MITRE ATT&CK technique mappings ($T1110, T1071, T1048$) for analyst presentation.

---

## 5. BRIEF DESCRIPTION OF THE DRAWINGS

The patent application includes 15 formal drawings illustrating the system architecture, component interactions, mathematical workflows, and UI presentations:

* **FIGURE 1** is a high-level system block diagram illustrating the privacy-preserving dual telemetry intake architecture (managed endpoint agents and gateway BYOD probes) connected to the backend engine registry and analyst console.
* **FIGURE 2** is a software architecture flow diagram illustrating the ordered execution sequence of the Engine Registry (`Device` $\rightarrow$ `Threat` $\rightarrow$ `Application` $\rightarrow$ `VPN` $\rightarrow$ `Risk` $\rightarrow$ `AI`).
* **FIGURE 3** is a data flow diagram illustrating the local packet inspection, credential redaction, and payload-isolation workflow executed by the managed endpoint agent.
* **FIGURE 4** is a data flow diagram illustrating non-payload gateway flow logging for unmanaged BYOD endpoints.
* **FIGURE 5** is a detailed block diagram of the Device Identification Engine, illustrating passive evidence collection, the `EvidenceTracker`, and the low-confidence active probing fallback loop.
* **FIGURE 6** is a flowchart illustrating the multi-tier device classification logic (mDNS/SSDP $\rightarrow$ Hostname $\rightarrow$ DHCP OS $\rightarrow$ OUI $\rightarrow$ Active Probe).
* **FIGURE 7** is a component diagram of the Threat Engine, showing the parallel execution of Port Scan, Brute Force, C2 Beaconing, and DNS Tunneling detectors.
* **FIGURE 8** is a mathematical flowchart illustrating the C2 Beaconing detection algorithm using inter-arrival time Mean ($\mu$), Standard Deviation ($\sigma$), and Coefficient of Variation ($COV$).
* **FIGURE 9** is a mathematical flowchart illustrating the DNS Tunneling detection algorithm using Shannon Entropy calculation and sliding TTL Bloom filter unique subdomain tracking.
* **FIGURE 10** is a data structure diagram of the structured `Finding` object, illustrating all fields, metadata dictionaries, and MITRE ATT&CK mappings.
* **FIGURE 11** is a process flowchart illustrating the Risk History Store management, including finding replacement, thread-safe RLock synchronization, and memory-leak key pruning.
* **FIGURE 12** is a graph illustrating the continuous exponential half-life decay function ($T_{1/2} = 300\text{s}$) contrasted with rigid step-function alert deletion.
* **FIGURE 13** is a sequence diagram illustrating the Recursive Correlation Engine workflow, showing rule evaluation, synthetic correlation finding generation, and re-injection into the active finding history.
* **FIGURE 14** is a comparative mathematical graph illustrating the Non-Dilutive Risk Aggregation formula ($\text{MaxScore} + 0.1 \sum \text{Others}$) compared to Weighted Averaging, Max-Only, and Pure Summation models under single-threat, noisy, and compound attack scenarios.
* **FIGURE 15** is a block diagram of the Decoupled Suppression Store, illustrating the operational separation between notification emission filtering (UI layer) and internal risk score state retention (engine layer).

---

## 6. DETAILED DESCRIPTION OF PREFERRED EMBODIMENTS

### CHAPTER 1: Dual Telemetry Architecture & Payload Isolation

Referring to **FIGURE 1** and **FIGURE 3**, the system implements a privacy-preserving dual monitoring architecture that provides full visibility across an enterprise network containing both managed enterprise devices and unmanaged Bring-Your-Own-Device (BYOD) endpoints.

#### Managed Endpoint Telemetry Isolation (FIGURE 3)
For managed devices where a software agent is installed (`agent/`), the agent executes local packet capture via raw sockets or PCAP drivers. The agent inspects full packet headers and application payloads locally within device memory. To preserve user privacy and prevent data exfiltration, the agent passes raw payload snippets through a redaction pipeline (`agent/dpi/redaction.py`) that strips sensitive OAuth tokens, API keys, passwords, credit card numbers, and personal identifiable information (PII). Only structured event summaries (`confidence_score`, `domain`, `app_name`, redacted evidence snippets) are transmitted over TLS to the backend API (`/api/v1/dpi/events`). Raw payloads never leave local endpoint memory.

#### Gateway BYOD Telemetry Capture (FIGURE 4)
For unmanaged BYOD devices, personal mobile phones, and IoT hardware where software agents cannot be deployed, gateway monitoring probes (`gateway/`) capture network flow telemetry at network chokepoints (firewalls, TAP ports, router mirrors). The gateway captures non-payload metadata including source/destination IP addresses, Layer 4 ports, IP protocols, packet counts, byte counts, flow durations, DNS query hostnames, and TLS Client Hello SNI/JA4 fingerprints. The gateway explicitly discards all application layer payloads without storage or transmission.

---

### CHAPTER 2: Multi-Source Evidence Confidence Engine

Referring to **FIGURE 5** and **FIGURE 6**, the Device Identification Engine (`app/engines/device/`) assesses device identity and assigns a continuous confidence score without relying on invasive scanning.

#### Evidence Tracking Data Structure
The engine instantiates an `EvidenceTracker` (`app/engines/common/evidence.py`) configured with protocol-specific weight parameters:

```python
# Configuration Weights (app/engines/common/config.py)
self.device_weights = {
    "dhcp": 0.40,         # Kernel Option 55/60 request list signature
    "mdns": 0.20,         # Consumer service announcements (_airplay, _googlecast)
    "ssdp": 0.15,         # UPnP friendly name / device description
    "oui": 0.15,          # IEEE MAC vendor prefix
    "hostname": 0.10,     # DNS/NetBIOS hostname
    "active_probe": 0.15  # Fallback TCP service port probe
}
```

As network traffic is observed, passive detectors extract protocol attributes and append `Evidence` objects to `tracker.evidence_sources`. Total confidence is evaluated as:

$$\text{TotalConfidence} = \min\left(1.0, \text{round}\left(\sum_{i} \text{weight}_i \times \text{confidence}_i, 2\right)\right)$$

Confidence levels are categorized as:
* `TotalConfidence >= 0.85` $\rightarrow$ `"high"`
* `0.50 <= TotalConfidence < 0.85` $\rightarrow$ `"medium"`
* `TotalConfidence < 0.50` $\rightarrow$ `"low"`

#### Tiered Classification Pipeline (FIGURE 6)
Device type classification follows a strict priority hierarchy:
1. **Tier A (mDNS / SSDP Specific Models):** Explicit service announcements (e.g., Apple TV, Roku, Chromecast) override generic classifications.
2. **Tier B (Hostname Heuristics):** Pattern matching on cleaned hostnames (e.g., `*-iPad` $\rightarrow$ Tablet).
3. **Tier C (DHCP OS Family & OUI Refinement):** Maps Option 55 fingerprints to OS families (Windows, Apple OS, Linux). Linux devices with Synology OUIs are refined to `NAS / Storage`; Raspberry Pi OUIs are refined to `Linux/IoT Device`.
4. **Tier D (Active Probing Fallback):** If `device_type` remains `"Unknown"` AND `TotalConfidence < 0.50` AND active probing is permitted, `ActiveProber` (`app/engines/device/active_prober.py`) executes non-blocking TCP socket probes (timeout = 0.3s) across ports `445` (Windows/SMB), `22` (SSH), `80/443` (HTTP/S), `7000` (AirPlay), `8008/8009` (Cast), `8060` (Roku), `9100` (Printer), `502` (Modbus PLC), and `3000` (Dev Port). If a port connects, the corresponding evidence is appended to `EvidenceTracker`, refining classification and boosting confidence.

---

### CHAPTER 3: Threat Detection Pipeline & Analytics

Referring to **FIGURE 7**, **FIGURE 8**, and **FIGURE 9**, the Threat Engine (`app/engines/threat/`) executes modular detectors operating on sliding window memory stores (`SlidingWindowStore`).

#### A. Port Scanning Detector
Monitors unique destination ports targeted by a source IP within a 10-second sliding window (`port_scan_window`):
$$\text{If } |\text{UniquePorts}_{10\text{s}}| \ge 10 \longrightarrow \text{Emit Finding (Type: } \texttt{port\_scan}\text{, Severity: HIGH, BaseScore: } 70\text{)}$$

#### B. Brute Force Detector
Monitors rapid, short-duration connection attempts to authentication ports (`22, 3389, 445, 80, 443`) where duration $< 1.0\text{s}$ and total byte count $< 500$ bytes:
$$\text{If } |\text{FailedAttempts}_{60\text{s}}| \ge 15 \longrightarrow \text{Emit Finding (Type: } \texttt{brute\_force}\text{, Severity: CRITICAL, BaseScore: } 85\text{)}$$

#### C. Command & Control (C2) Beaconing Detector (FIGURE 8)
Analyzes flow inter-arrival times for an IP tuple `(src_ip, dst_ip, dst_port)` within an 1800-second (30-minute) window. Requires at least 5 flow events. Calculates inter-arrival intervals $\Delta t_i = t_i - t_{i-1}$, interval mean $\mu$, and population standard deviation $\sigma$:

$$COV = \frac{\sigma}{\mu}$$

$$\text{If } 5\text{s} \le \mu \le 600\text{s} \text{ AND } (COV \le 0.10 \text{ OR } \sigma \le 1.0\text{s}) \longrightarrow \text{Emit Finding (Type: } \texttt{beaconing}\text{, Severity: HIGH, BaseScore: } 70\text{)}$$

The Coefficient of Variation ($COV$) normalizes variance relative to interval length, isolating regular automated cardiac C2 beacons from irregular human browsing.

#### D. DNS Tunneling Detector (FIGURE 9)
Evaluates DNS query hostnames using two independent mathematical criteria:
1. **Shannon Entropy Check:** Computes Shannon entropy on the lowest-level subdomain label:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   where $P(x_i) = \frac{\text{count}(x_i)}{\text{len}(\text{subdomain})}$. If $\text{len}(\text{subdomain}) > 15$ AND $H(X) > 3.8$, the engine emits a CRITICAL `dns_tunneling` finding (BaseScore = 80).
2. **Sliding TTL Subdomain Volume Check:** Tracks unique subdomains queried per `(src_ip, parent_domain)` within a 3600-second (1-hour) TTL window. If $|\text{UniqueSubdomains}_{3600\text{s}}| > 50$, the engine emits a CRITICAL `dns_tunneling` finding (BaseScore = 80).

---

### CHAPTER 4: Encrypted Traffic & VPN Detection Engine

The VPN Engine (`app/engines/vpn/`) identifies encrypted proxy and VPN tunnels without decrypting traffic payloads.

#### Weighted Indicator Evaluation
The engine checks flow metadata against an `EngineConfig` weight dictionary:

```python
self.vpn_weights = {
    "tor": 0.80,         # Tor exit node IP or TLS certificate match
    "openvpn": 0.50,     # OpenVPN protocol headers / static ports (1194)
    "asn": 0.40,         # Commercial VPN provider Autonomous System Number
    "wireguard": 0.35,   # WireGuard UDP handshake patterns
    "tls": 0.20          # Obfuscated TLS Client Hello / JA4 fingerprint
}
```

The engine sums active indicator weights. If $\sum \text{weight}_i \ge 0.50$, the engine emits a `vpn_detected` finding (`Severity: MEDIUM`, `BaseScore: 35`).

---

### CHAPTER 5: Structured Finding Object & Inter-Engine Data Model

Referring to **FIGURE 10**, all engines communicate using a standardized, immutable data structure called `Finding` (`shared/engine/findings.py`).

```python
@dataclass(frozen=True)
class Finding:
    engine: str                          # Engine name ("threat", "vpn", "risk", "device", "ai")
    finding_type: str                    # Unique finding identifier (e.g. "port_scan")
    severity: Severity                   # Enum: INFO(0), LOW(15), MEDIUM(40), HIGH(70), CRITICAL(90)
    confidence: float                    # Floating point confidence (0.0 to 1.0)
    evidence: List[str]                  # Human-readable evidence strings
    timestamp: datetime                  # Naive or UTC timestamp of observation
    ttl: int = 300                       # Time-To-Live in seconds (default 300s)
    target_ip: Optional[str] = None      # Target device IP address
    target_mac: Optional[str] = None     # Target device MAC address
    mitre_attack_id: Optional[str] = None # MITRE ATT&CK Technique ID (e.g., "T1110")
    details: Dict[str, Any]              # Arbitrary key-value metadata dictionary
```

This uniform contract allows findings from any engine to be serialized, passed through middleware, stored in memory, and ingested by the `RiskEngine`.

---

### CHAPTER 6: Risk History Store, Half-Life Decay, and TTL Pruning

Referring to **FIGURE 11** and **FIGURE 12**, the Risk Engine (`app/engines/risk/engine.py`) maintains a thread-safe finding history store:

```python
self._history = defaultdict(list)  # Target_IP -> List[Finding]
self._lock = threading.RLock()
```

#### Finding Ingestion & Deduplication
When new findings arrive for a target IP, the engine iterates through existing history. If an active finding with the exact same `(engine, finding_type)` already exists, the old finding is removed and replaced by the new finding:

```python
existing_finding = None
for hist_finding in self._history[target_ip]:
    if (hist_finding.engine == finding.engine and
        hist_finding.finding_type == finding.finding_type):
        existing_finding = hist_finding
        break

if existing_finding is not None:
    self._history[target_ip].remove(existing_finding)

self._history[target_ip].append(finding)
```
This renews the finding's timestamp and prevents duplicate score accumulation from the same ongoing event.

#### Continuous Exponential Half-Life Decay (FIGURE 12)
Rather than deleting alerts abruptly, the system applies continuous exponential decay (`app/engines/risk/decay.py`) to every active finding based on its age relative to current observation time ($\text{age\_seconds} = \text{observed\_at} - \text{finding.timestamp}$):

$$\text{DecayedScore} = \text{BaseScore} \times 0.5^{\left(\frac{\text{age\_seconds}}{\text{half\_life}}\right)}$$

where $\text{half\_life} = 300.0$ seconds (5 minutes).

#### Time-To-Live (TTL) Pruning
If $\text{age\_seconds} \ge \text{finding.ttl}$, the finding is permanently pruned from `_history`. If `_history[target_ip]` becomes empty, `self._history.pop(target_ip, None)` is called immediately to prevent memory leaks.

---

### CHAPTER 7: Recursive Correlation Engine & Synthetic Finding Injection

Referring to **FIGURE 13**, the `Correlator` (`app/engines/risk/correlation.py`) evaluates active decayed findings against a graph of `CorrelationRule` objects:

```python
DEFAULT_RULES = [
    CorrelationRule(
        name="credential_attack",
        required_findings=["vpn_detected", "port_scan"],
        resulting_finding_type="credential_attack",
        severity=Severity.HIGH,
        mitre_attack_id="T1110",
        description="Credential Attack: VPN usage correlated with port scanning."
    ),
    CorrelationRule(
        name="active_c2",
        required_findings=["beaconing", "dns_tunneling"],
        resulting_finding_type="active_c2",
        severity=Severity.CRITICAL,
        mitre_attack_id="T1071",
        description="Active Command & Control: periodic beaconing coupled with DNS tunneling."
    ),
    CorrelationRule(
        name="suspicious_exfiltration",
        required_findings=["large_upload", "beaconing"],
        resulting_finding_type="suspicious_exfiltration",
        severity=Severity.HIGH,
        mitre_attack_id="T1048",
        description="Suspicious Exfiltration: large upload correlated with beaconing."
    ),
    CorrelationRule(
        name="credential_stuffing",
        required_findings=["brute_force", "vpn_detected"],
        resulting_finding_type="credential_stuffing",
        severity=Severity.CRITICAL,
        mitre_attack_id="T1110",
        description="Credential Stuffing: brute force attempts originating from a VPN."
    )
]
```

#### Recursive Evidence Feedback Loop
When `Correlator.evaluate_rules()` detects that all `required_findings` for a rule are present in `_history[target_ip]` with positive decayed scores:
1. It constructs a **Synthetic Correlation Finding** with `engine="risk"`, `finding_type=rule.resulting_finding_type`, `severity=rule.severity`, and base score = $80.0$ (or $90.0$).
2. This synthetic finding is **recursively re-injected** into the active score aggregation pool (`scores.append(80.0)`).
3. The synthetic finding is passed downstream to the Risk Aggregation Engine, instantaneously driving up the device composite risk score.

---

### CHAPTER 8: Non-Dilutive Risk Aggregation Engine

Referring to **FIGURE 14**, the Risk Engine aggregates all active decayed scores and synthetic correlation scores for a target IP.

#### The Mathematical Aggregation Algorithm
Let $S = \{S_1, S_2, \dots, S_N\}$ be the array of all active decayed finding scores and triggered correlation scores for a target device, sorted in descending order ($S_1 \ge S_2 \ge \dots \ge S_N$).

The composite risk score $\text{RiskScore}$ is calculated as:

$$\text{RiskScore} = \min\left(100, \text{round}\left(S_1 + 0.1 \times \sum_{i=2}^{N} S_i\right)\right)$$

#### Severity Level Resolution
The resulting integer score is mapped to a discrete severity level:
* $\text{RiskScore} \ge 80 \longrightarrow \text{CRITICAL}$
* $60 \le \text{RiskScore} < 80 \longrightarrow \text{HIGH}$
* $30 \le \text{RiskScore} < 60 \longrightarrow \text{MEDIUM}$
* $0 < \text{RiskScore} < 30 \longrightarrow \text{LOW}$
* $\text{RiskScore} = 0 \longrightarrow \text{INFO}$

---

### CHAPTER 9: Decoupled Suppression Store & State Retention

Referring to **FIGURE 15**, the system incorporates a `SuppressionStore` (`app/engines/risk/suppression.py`) that decouples dashboard alert notifications from internal risk scoring.

#### Operational Workflow
1. When a correlation finding is generated, the system queries `SuppressionStore.should_suppress(target_ip, rule_name, observed_at, suppression_window=60.0)`.
2. **If Suppressed:** The system omits emitting a duplicate alert notification to the frontend dashboard, preventing analyst alert fatigue.
3. **State Retention:** The underlying finding **remains active** in `_history[target_ip]`, and its base score ($80.0$) remains in the risk aggregation pool ($\text{scores}$). The device's composite risk score remains elevated at its true mathematical level ($90$) even while UI alert spam is suppressed.

---

### CHAPTER 10: AI Explanatory Engine & Remediation Mapping

The AI Engine (`app/engines/ai/`) operates as the final stage in the Engine Registry sequence (`[device, threat, application, vpn] -> risk -> ai`).

#### Functionality
* Takes the aggregated `AnalysisModel` containing `risk_score`, `severity`, and raw findings.
* Generates natural language executive summaries (e.g., *"Overall device risk score is evaluated as 91 (CRITICAL) due to active C2 beaconing and DNS tunneling."*).
* Maps findings to top-priority remediation steps and MITRE ATT&CK technique IDs ($T1110, T1071, T1048$).
* Emits an `ai_analysis` summary finding (`confidence=1.0`) for UI rendering. The AI engine does not alter risk scores or modify underlying detection findings.

---

## 7. EXPERIMENTAL EVALUATION & PERFORMANCE BENCHMARKS

The system was evaluated under standardized benchmark specifications (Specification Version `1.0.0`) using synthetic workload generators and live network traffic profiling.

### A. Comparative Scoring Model Evaluation

The implemented anchor-plus-dampened-sum formula ($\text{Max} + 0.1 \sum \text{Others}$) was benchmarked against alternative scoring models across representative operational scenarios:

| Scenario | Attack & Background Telemetry Description | Weighted Average ($\frac{\sum S_i}{N}$) | Max Only ($\max S_i$) | NetVisor ($\text{Max} + 0.1\sum\text{Others}$) | Operational Security Evaluation |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **1. Single Critical Exploit** | 1 Critical C2 Exploit ($S=90$), 0 background events | **90.0** (Critical) | **90.0** (Critical) | **90.0** (Critical) | All models identify isolated severe threats. |
| **2. Exploit + Telemetry Noise** | 1 Critical C2 Exploit ($S=90$), 9 benign telemetry logs ($S=10$ each) | **18.0** (Low) ❌ *(Diluted)* | **90.0** (Critical) | **90.9** (Critical) | **NetVisor & Max eliminate Alert Dilution.** Weighted Average fails by masking the attack as `LOW`. |
| **3. Compound Multi-Vector Attack**| VPN Anomaly ($S=40$), Port Scan ($S=70$), Brute Force ($S=85$), Correlation ($S=80$) | **68.8** (High) | **85.0** (Critical) | **98.5** (Critical) | **NetVisor reflects compound risk accumulation.** Max Only treats it same as single brute force. |
| **4. Background Operational Noise**| 5 Low-severity policy/DHCP events ($S=15$ each) | **15.0** (Low) | **15.0** (Low) | **21.0** (Low) | **NetVisor prevents False Positive Saturation.** Pure sum would incorrectly inflate score to `75` (`HIGH`). |
| **5. Sustained Attack with Half-Life**| Critical Exploit ($S=90$) at $T=0$, evaluated at $T=5\text{ min}$ ($T_{1/2}$) | **45.0** (Medium) | **45.0** (Medium) | **45.0** (Medium) | Demonstrates smooth exponential decay ($90 \times 0.5^1 = 45$). |
| **6. Correlated Reconnaissance** | VPN ($S=35$) + Port Scan ($S=70$) triggering Credential Attack Correlation ($S=80$) | **61.7** (High) | **80.0** (Critical) | **87.5** (Critical) | **NetVisor's recursive correlation elevates threat level** above individual events. |

### B. System Throughput & Latency Profiling

Ingestion performance was benchmarked on a baseline single-worker Uvicorn/FastAPI server:
* **Ingestion Throughput:** **9,704.91 flows/second** (97% of 10,000 flows/sec target).
* **Latency Profile:**
  * **P50 Latency:** **12.39 ms**
  * **P95 Latency:** **105.81 ms**
  * **P99 Latency:** **165.73 ms**
* **Resource Utilization:** CPU load average **46.3%**, RAM footprint **123.1 MB**.

---

## 8. INDUSTRIAL APPLICATIONS

The present invention is applicable across numerous commercial and industrial sectors:

1. **Enterprise NDR & EDR Deployments:** Provides unified security monitoring across corporate networks containing both managed laptops and employee BYOD smartphones.
2. **Healthcare & HIPAA Compliance:** Enables threat monitoring on medical IoT equipment (e.g., patient monitors, imaging systems) via gateway metadata collection without decrypting private health records (PHI).
3. **Financial Services & Banking:** Detects credential stuffing and exfiltration across remote worker VPN connections while enforcing zero-payload logging for compliance.
4. **Higher Education & Campus Networks:** Monitors massive, highly dynamic student BYOD populations across university Wi-Fi networks using non-intrusive passive device fingerprinting.
5. **Managed Security Service Providers (MSSPs):** Allows multi-tenant security monitoring with low false-positive rates, enabling SOC analysts to focus on high-fidelity correlated incidents.

---

## 9. TECHNICAL ADVANTAGES OF THE INVENTION

1. **Zero Payload Transmission for Privacy:** Eliminates regulatory compliance risks by retaining raw application payloads within local agent memory.
2. **Immunity to Alert Dilution:** Anchors risk to the maximum threat score, ensuring critical exploits are never masked by background operational noise.
3. **Compound Risk Sensitivity:** Incorporates secondary active findings via a 10% dampening multiplier, accurately reflecting multi-vector attack chains.
4. **Saturation-Resistant Aggregation:** Bounds composite risk at 100, preventing false-positive score inflation from low-severity background events.
5. **Continuous Mathematical Decay:** Replaces abrupt step-function alert deletion with smooth exponential half-life decay ($T_{1/2} = 300\text{s}$).
6. **Real-Time Recursive Correlation:** Re-injects synthetic correlation findings ($S = 80$) into active history to instantaneously update device risk scores upon attack chain discovery.
7. **UI Suppression Without State Loss:** Decouples notification emission from risk scoring, preventing dashboard alert spam while maintaining true risk state accuracy.
8. **Line-Rate Computational Efficiency:** Executes risk aggregation in $O(N \log N)$ time, achieving 9,700+ flows/sec throughput on a single server worker.

---

## 10. PATENT CLAIMS SET

### INDEPENDENT CLAIMS

**What is claimed is:**

**1. A computer-implemented method for privacy-preserving network security monitoring and dynamic threat risk assessment, comprising:**
* receiving, by a computing system, telemetry from a plurality of network endpoints comprising managed devices and unmanaged Bring-Your-Own-Device (BYOD) endpoints, wherein for managed devices telemetry is captured by endpoint agents executing local packet inspection without transmitting raw payloads, and for unmanaged BYOD endpoints telemetry is captured by a network gateway collecting non-payload metadata flows;
* executing, by an engine registry, a plurality of detection engines to generate structured finding objects, each finding object comprising an engine identifier, a finding type, a severity level, a base score, an evidence array, and an observation timestamp;
* storing active finding objects associated with a target device in a thread-safe history memory store, wherein an incoming finding object matching an existing active finding object's engine identifier and finding type replaces the existing active finding object in the history memory store;
* calculating a decayed score for each active finding object in the history memory store using an exponential half-life decay function based on elapsed time between the observation timestamp and a current observation time;
* evaluating the active finding objects against a plurality of correlation rules, wherein matching a correlation rule generates a synthetic correlation finding object having a correlation base score, and recursively re-injecting the synthetic correlation finding object into the active finding history store; and
* calculating a composite risk score for the target device by sorting all active decayed scores and correlation base scores in descending order to identify a maximum score ($S_1$) and secondary scores ($S_2 \dots S_N$), and computing the composite risk score according to:
  $$\text{RiskScore} = \min\left(100, \text{round}\left(S_1 + \alpha \sum_{i=2}^{N} S_i\right)\right)$$
  wherein $\alpha$ is a pre-determined dampening coefficient.

**2. A privacy-preserving network threat assessment system, comprising:**
* a gateway probe configured to capture non-payload network flow metadata for unmanaged endpoints, the metadata comprising IP addresses, Layer 4 ports, protocols, flow durations, packet counts, Domain Name System (DNS) queries, and Transport Layer Security (TLS) client fingerprints;
* one or more endpoint agents installed on managed endpoints, each agent configured to inspect packet payloads locally within endpoint memory, redact sensitive application credentials and payloads, and transmit redacted telemetry summaries;
* a memory storing an active finding history dictionary for target devices; and
* a processor operatively coupled to the memory, configured to:
  * ingest findings from a plurality of detection engines into the active finding history dictionary;
  * apply an exponential half-life decay function to calculate a decayed score for each active finding in the history dictionary;
  * evaluate active findings against a correlation rule graph to generate a synthetic correlation finding upon matching a multi-stage attack pattern, and recursively ingest the synthetic correlation finding into the active finding history dictionary; and
  * calculate a composite risk score for a target device by adding a scaled sum of secondary active decayed scores to a maximum active score, wherein the scaled sum uses a dampening factor $\alpha = 0.10$.

**3. A non-transitory computer-readable storage medium storing instructions that, when executed by at least one processor, cause the at least one processor to perform operations comprising:**
* accumulating passive network discovery evidence comprising DHCP option fingerprints, mDNS service announcements, SSDP UPnP advertisements, IEEE OUI vendor lookups, and hostnames into an evidence tracker for a target device;
* calculating a continuous device identity confidence score by evaluating a weighted linear sum of the accumulated passive evidence sources:
  $$\text{TotalConfidence} = \min\left(1.0, \sum_{i} w_i \times c_i\right)$$
  wherein $w_i$ represents a protocol-specific weight;
* conditionally executing an active TCP port probe against the target device strictly when the calculated device identity confidence score falls below a low-confidence threshold;
* storing threat findings generated for the target device in an active history store and calculating decayed scores using an exponential half-life equation; and
* calculating a non-dilutive composite device risk score by summing a maximum active decayed score with ten percent of all secondary active decayed scores, capped at one hundred.

---

### DEPENDENT CLAIMS

**4. The method of claim 1,** wherein the dampening coefficient $\alpha$ is $0.10$.

**5. The method of claim 1,** wherein the exponential half-life decay function evaluates:
$$S(t) = \text{BaseScore} \times 0.5^{\left(\frac{\text{AgeSeconds}}{T_{1/2}}\right)}$$
wherein $T_{1/2}$ is $300.0$ seconds.

**6. The method of claim 1,** further comprising pruning an active finding object from the history memory store when the elapsed time exceeds a Time-To-Live (TTL) parameter associated with the finding object.

**7. The method of claim 6,** further comprising removing a target device key from the history memory store when all active finding objects for the target device have been pruned, thereby preventing memory leaks.

**8. The method of claim 1,** further comprising passing active correlation findings through a decoupled suppression store, wherein matching a suppression window suppresses emission of duplicate alert notifications to a user interface while retaining the correlation finding within the history memory store to maintain composite risk score accuracy.

**9. The method of claim 8,** wherein the suppression window is $60.0$ seconds.

**10. The method of claim 1,** wherein the plurality of detection engines executed by the engine registry comprises a C2 beaconing detector configured to calculate a Coefficient of Variation ($COV = \sigma / \mu$) on packet inter-arrival times across a sliding window, and trigger a beaconing finding when $COV \le 0.10$.

**11. The method of claim 1,** wherein the plurality of detection engines comprises a DNS tunneling detector configured to compute Shannon entropy on subdomain labels, and trigger a DNS tunneling finding when subdomain label length exceeds 15 characters and Shannon entropy exceeds 3.8.

**12. The method of claim 1,** wherein the plurality of detection engines comprises a DNS tunneling detector configured to track unique subdomains queried per parent domain in a sliding Bloom filter store, and trigger a DNS tunneling finding when unique subdomain count exceeds 50 within a 3600-second TTL window.

**13. The method of claim 1,** wherein the plurality of detection engines comprises a VPN engine configured to evaluate a weighted sum of TOR exit nodes, OpenVPN headers, commercial VPN ASNs, WireGuard handshakes, and TLS client fingerprints, and emit a VPN finding when the weighted sum exceeds $0.50$.

**14. The system of claim 2,** wherein the processor executes the detection engines in an ordered sequence comprising: Device Engine, Threat Engine, Application Engine, VPN Engine, Risk Engine, and AI Explanatory Engine.

**15. The system of claim 14,** wherein findings generated by the Device, Threat, Application, and VPN engines are injected into a context findings array and passed to the Risk Engine.

**16. The system of claim 14,** wherein the AI Explanatory Engine reads the composite risk score and findings generated by the Risk Engine and generates natural language executive summaries and MITRE ATT&CK technique mappings without altering the composite risk score.

**17. The medium of claim 3,** wherein the protocol-specific weights ($w_i$) in the evidence tracker comprise: $0.40$ for DHCP, $0.20$ for mDNS, $0.15$ for SSDP, $0.15$ for OUI, and $0.10$ for Hostname.

**18. The medium of claim 3,** wherein the low-confidence threshold for triggering active TCP port probing is $0.50$.

**19. The medium of claim 3,** wherein active TCP port probing connects to a restricted set of service ports comprising TCP ports 445, 22, 80, 443, 7000, 8008, 8009, 8060, 9100, 502, and 3000.

**20. The method of claim 1,** wherein the synthetic correlation finding generated by matching a correlation rule carries a base score of $80.0$.

**21. The method of claim 1,** wherein a correlation rule matches when a VPN finding and a port scan finding are simultaneously active for the same target device.

**22. The method of claim 1,** wherein a correlation rule matches when a C2 beaconing finding and a DNS tunneling finding are simultaneously active for the same target device.

**23. The method of claim 1,** wherein the calculated composite risk score is mapped to a discrete severity level comprising: CRITICAL ($\ge 80$), HIGH ($60\text{–}79$), MEDIUM ($30\text{–}59$), LOW ($1\text{–}29$), and INFO ($0$).

---

## 11. ABSTRACT OF THE DISCLOSURE

A computer-implemented system, method, and non-transitory computer-readable storage medium for privacy-preserving network security monitoring and dynamic threat assessment. The system establishes a dual telemetry model comprising managed endpoint agents that perform local packet inspection and payload redaction within endpoint memory, and gateway probes that collect non-payload metadata flows for unmanaged Bring-Your-Own-Device (BYOD) endpoints. An engine registry executes detection engines to generate structured finding objects. Active findings are stored in a thread-safe history dictionary per target device and decayed continuously using an exponential half-life function ($T_{1/2} = 300\text{s}$). A correlation engine evaluates active decayed findings against rule graphs, generating synthetic correlation findings that are recursively re-injected into the history store. A risk aggregation engine calculates a composite device risk score by adding ten percent of secondary active decayed scores to a maximum active score ($\text{Max} + 0.1 \sum \text{Others}$), capping the result at 100. This non-dilutive formula preserves dominant threat severity while incorporating corroborating evidence without false-positive score saturation.

---

## 12. NOVELTY & CODEBASE EVIDENCE SUPPORT MAPPING

The table below maps each patent claim element directly to its supporting implementation file and lines within the `NetVisor` codebase:

| Claim Element | Codebase Implementation File | Code Symbol / Method / Lines |
| :--- | :--- | :--- |
| **Dual Telemetry Architecture** | `README.md`, `agent/`, `gateway/` | `agent/dpi/event_buffer.py` (Local DPI), `gateway/` (Metadata intake) |
| **EvidenceTracker & Weights** | `app/engines/common/evidence.py` | `EvidenceTracker.add_evidence()`, `total_confidence` |
| **Evidence Weight Config** | `app/engines/common/config.py` | `self.device_weights` (DHCP: 0.40, mDNS: 0.20, OUI: 0.15, etc.) |
| **Active Probing Fallback** | `app/engines/device/pipeline.py` | Lines 129–135 (`tracker.total_confidence < 0.50`) |
| **Active Prober Ports** | `app/engines/device/active_prober.py` | `COMMON_PORTS` (445, 22, 80, 443, 8008, 9100, 502, etc.) |
| **Beaconing COV Detector** | `app/engines/threat/beaconing.py` | Lines 46–51 (`cov = std / mean`, `cov <= 0.10`) |
| **DNS Tunneling Entropy** | `app/engines/threat/dns_tunneling.py` | Lines 17–28 (`_calculate_entropy`, $H(X) > 3.8$) |
| **DNS Tunneling Bloom TTL** | `app/engines/threat/dns_tunneling.py` | Lines 62–81 (`dns_subdomain_counts`, `unique_count > 50`) |
| **VPN Weighted Engine** | `app/engines/vpn/engine.py` | `self.vpn_weights` (TOR: 0.80, OpenVPN: 0.50, ASN: 0.40) |
| **Finding Dataclass Model** | `shared/engine/findings.py` | `Finding` dataclass (engine, type, severity, confidence, ttl, details) |
| **Risk History Storage & Lock** | `app/engines/risk/engine.py` | `self._history = defaultdict(list)`, `self._lock = RLock()` |
| **History Deduplication** | `app/engines/risk/engine.py` | Lines 116–126 (removes matching `(engine, finding_type)` before append) |
| **Exponential Half-Life Decay**| `app/engines/risk/decay.py` | `calculate_decay()` ($S_0 \times 0.5^{\text{age}/300}$) |
| **TTL Key Pruning** | `app/engines/risk/engine.py` | Lines 160–164 (`self._history.pop(target_ip, None)`) |
| **Correlation Rule Graph** | `app/engines/risk/models.py` | `DEFAULT_RULES` (`vpn_detected` + `port_scan` $\rightarrow$ `credential_attack`) |
| **Recursive Synthetic Finding**| `app/engines/risk/engine.py` | Lines 167–171, 201–202 (`scores.append(80.0)`) |
| **Risk Aggregation Formula** | `app/engines/risk/engine.py` | Lines 206–214 (`max_score + sum(s * 0.1 for s in sorted_scores[1:])`) |
| **Decoupled Suppression** | `app/engines/risk/suppression.py` | `SuppressionStore.should_suppress()` (60s UI window filtering) |
| **AI Explanatory Engine** | `app/engines/ai/engine.py` | `AIEngine.analyze()`, `AISummaryEngine`, `AIRecommendationEngine` |
| **Ordered Registry Sequence** | `app/engines/registry.py` | Lines 60–67 (`selected_names.append("risk")`, `selected_names.append("ai")`) |
