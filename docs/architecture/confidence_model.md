# Confidence & Evidence Model Specification

To verify device identity assertions, NetVisor utilizes an evidence-weighted confidence model. This document defines the metrics and scoring math for device profiling.

## 1. Evidence Weight Matrix

Different discovery channels carry varying reliability weights:

| Evidence Type | Source | Weight | Description |
| --- | --- | --- | --- |
| **DHCP Fingerprint** | Passive DHCP Parser | `0.40` | Highly reliable OS parameter list signature. |
| **mDNS Advertisement** | Multicast Listeners | `0.20` | Dynamic device names/services (Apple, Chromecast). |
| **SSDP UPnP** | UPnP discovery | `0.15` | Smart TVs, routers, and IoT models. |
| **MAC Vendor (OUI)** | IEEE Database | `0.15` | NIC manufacturer registry prefix. |
| **Resolved Hostname** | DNS / NetBIOS / Ping | `0.10` | Static domain / NetBIOS resolution. |

---

## 2. Confidence Calculation

The final confidence score $C$ is the sum of all observed, normalized evidence weights:

$$C = \sum_{i \in E} W_i$$

Where:
*   $E$ is the set of observed evidence channels.
*   $W_i$ is the weight of channel $i$.
*   Maximum confidence is $1.0$.

### Categorization Mapping:
*   $C \ge 0.85$ ➔ **High Confidence**
*   $0.50 \le C < 0.85$ ➔ **Medium Confidence**
*   $C < 0.50$ ➔ **Low Confidence**
