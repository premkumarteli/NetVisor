# NetVisor Production-Ready Roadmap

## Operating Rule

- A phase is complete only when it is implemented, tested, verified in a real environment, and ready to deploy.
- Do not move to the next phase until the current phase has no blocking bugs or unresolved deployment gaps.
- "Feature added" is not enough. Each phase must be stable under real use.

## Phase 1: Agent and Gateway Hardening

### Goal

Make capture, enrollment, upload, buffering, and recovery reliable on another machine.

### Checklist

- [ ] Stable agent and gateway identity
- [ ] Preflight checks before startup
- [ ] Capture health reporting
- [ ] Upload health reporting
- [ ] Disk-backed buffering for offline resilience
- [ ] Enrollment recovery and duplicate detection
- [ ] Retry/backoff behavior for failed uploads
- [ ] Fleet UI visibility for health, queue depth, and offline reason
- [ ] Deploy bundle hygiene and secret exclusion

### Verification

- [ ] Agent starts on a second machine
- [ ] Backend outage does not lose data
- [ ] Reconnect drains buffered data correctly
- [ ] Re-enrollment works after credential recovery
- [ ] No traceback spam on disconnect or timeouts
- [ ] Lint passes
- [ ] Build passes
- [ ] Manual LAN test completes successfully

### Exit Criteria

- [ ] Agent and gateway are deployable on another host
- [ ] Capture and upload failures are diagnosable
- [ ] No blocking runtime errors remain

## Phase 2: Device, Application, and DPI Intelligence

### Goal

Make traffic understandable at analyst level, not raw packet level.

### Checklist

- [ ] Application-level grouping
- [ ] Browser/session grouping
- [ ] Google, ChatGPT, YouTube, and similar app pages
- [ ] Cleaned DPI noise filtering
- [ ] Search/query/context evidence summaries
- [ ] Raw packet views demoted to drill-down mode
- [ ] Better app identity stability across reloads
- [ ] Consistent labels for app, browser, domain, and search context

### Verification

- [ ] App pages show meaningful grouped evidence
- [ ] Search pages show queries and related pages
- [ ] ChatGPT pages show conversation-related browsing context
- [ ] YouTube pages show session and watch context
- [ ] Raw DPI is secondary, not the default path
- [ ] No duplicate or noisy evidence flood in normal use

### Exit Criteria

- [ ] Analysts can understand current application activity without reading raw packets first
- [ ] App grouping is stable and useful
- [ ] UI is coherent across device and app views

## Phase 3: VPN and Threat Detection Hardening

### Goal

Make threat detection meaningful, explainable, and low-noise.

### Checklist

- [ ] VPN/proxy detection
- [ ] Suspicious behavior signal refinement
- [ ] Severity mapping consistency
- [ ] False-positive reduction
- [ ] Better alert explanation text
- [ ] Clear signal source and confidence handling

### Verification

- [ ] Known VPN/proxy cases are detected consistently
- [ ] Alerts are explainable to an analyst
- [ ] Severity levels are stable across repeated runs
- [ ] Noise is lower than useful signal

### Exit Criteria

- [ ] Detection is reliable enough for review and triage
- [ ] Alerts are understandable without backend inspection

## Phase 4: DPI Capture and Flow Truth Hardening

### Goal

Improve correctness of packet, flow, session, and direction truth.

### Checklist

- [x] Flow deduplication rules
- [x] Direction inference
- [x] Packet loss handling
- [x] Confidence scoring
- [ ] Capture resilience under load
- [x] Better session merge behavior

### Verification

- [ ] Flow counts are stable under sustained real traffic
- [x] Duplicate sessions are reduced
- [x] Direction metadata is correct
- [x] Dropped-packet scenarios are handled gracefully

### Exit Criteria

- [x] Flow truth is consistent enough for analysis
- [x] Capture health is visible and actionable

## Phase 5: Security Platform Hardening

### Goal

Make the system safer to operate, maintain, and deploy.

### Checklist

- [ ] Stronger auth and transport controls
- [ ] Safer secrets handling
- [ ] Tighter enrollment and revocation
- [ ] Safer database and write paths
- [ ] Auditability for sensitive actions
- [ ] Removal of embedded secrets and runtime artifacts

### Verification

- [ ] No secrets are committed
- [ ] Sensitive actions are logged
- [ ] Access boundaries are enforced
- [ ] Deployment does not require manual cleanup

### Exit Criteria

- [ ] The platform is safe to deploy in a real environment
- [ ] Security-sensitive flows are auditable

## Phase 6: UI Maturity and Analyst Workflow

### Goal

Make the product feel finished, readable, and fast to operate.

### Checklist

- [ ] Cleaner analyst flows
- [ ] Polished application pages
- [ ] Better detail drawers
- [ ] Responsive layout
- [ ] Consistent visual language
- [ ] Clear separation between summary and drill-down

### Verification

- [ ] Main analyst paths are obvious
- [ ] Desktop and mobile both work
- [ ] No critical layout breakage
- [ ] UI is stable under real data

### Exit Criteria

- [ ] The product looks and behaves like a finished platform
- [ ] The UI supports analyst work without friction

## Recommended Execution Order

1. Phase 1
2. Phase 2
3. Phase 3
4. Phase 4
5. Phase 5
6. Phase 6

## Definition of Done for Every Phase

- [ ] Feature implemented
- [ ] Tests or checks run
- [ ] Real-world behavior verified
- [ ] Deployment readiness confirmed
- [ ] No blocking bugs remain
