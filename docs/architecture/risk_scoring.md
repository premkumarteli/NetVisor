# Risk Scoring & Correlation Specification

The Risk Engine consumes structural findings from all other engines and computes a normalized host risk score. This document specifies the scoring algorithm, correlation patterns, and decay lifecycle.

## 1. Score Calculation Algorithm

The risk score ranges from `0` (Safe) to `100` (Critical):

$$\text{Final Risk Score} = \text{Min}\left(100, \text{Base Risk} + \text{Correlation Boost} + \sum \text{Decayed Detections}\right)$$

### Base Risk Components
*   **Flow Score**: Connection volume / anomaly rating.
*   **DNS Score**: Malicious domain classification.
*   **Baseline Score**: Statistical deviations from historic metrics.
*   **ML Score**: Anomaly forest probability output.
*   **VPN Score**: Weighting of anonymous traffic.

---

## 2. Risk Correlation Rules

Correlation matches multiple engine findings to identify structured multi-stage attacks:

*   **Rule 1: Tunneling + Reconnaissance**
    *   *Triggers*: `VPNEngine (vpn_detected)` + `ThreatEngine (port_scan)`
    *   *Action*: Elevate Severity to `HIGH`, apply +20 correlation boost.
*   **Rule 2: Access Intrusion + Exfiltration**
    *   *Triggers*: `ThreatEngine (potential_brute_force)` + `ThreatEngine (suspected_data_exfiltration)`
    *   *Action*: Elevate Severity to `CRITICAL`, force score to `90` minimum.

---

## 3. Decay & Time-To-Live (TTL)

To prevent transient events from permanently blacklisting a device, findings decay exponentially:

$$Score(t) = Score_0 \times e^{-\lambda t}$$

Where:
*   $\lambda$ is the decay constant based on the finding's `ttl`.
*   Once a finding's TTL expires, it is removed from the active risk evaluation cache.
*   **Suppression**: Repeated alerts for the same signature are suppressed (grouped) to prevent alert fatigue.
