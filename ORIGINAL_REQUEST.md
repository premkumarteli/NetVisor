# Original User Request

## 2026-08-17T13:51:12Z

<USER_REQUEST>
Debug the NetVisor project by executing all tests, resolving flaky test failures (such as settings/cleanup issues in test_refresh_token.py), and ensuring the backend server, agent, and gateway start cleanly.

Working directory: c:/Users/prem/Network
Integrity mode: development

## Requirements

### R1. Test Suite Stabilization
Run the complete pytest suite, analyze any failures, and resolve them. Ensure that tests do not fail due to shared mock pollution, concurrent file writes, or missing temporary directories (e.g. JWT cert path issues in `test_refresh_token.py`).

### R2. System Startup and Health Verification
Verify that the `backend` server (FastAPI), the local `agent` telemetry collector, and the `gateway` BYOD processor boot up and pass basic configuration/health checks without errors.

## Acceptance Criteria

### Test Verification
- [ ] Running `.venv\Scripts\pytest` succeeds with 100% test cases passing.
- [ ] No regression is introduced in the core detection engines (Device, Application, VPN, Threat, Risk, AI).

### Startup Verification
- [ ] Running `python run_server.py --health-check` reports status as healthy.
- [ ] Running `python run_agent.py --health-check` reports status as healthy.
- [ ] Running `python run_gateway.py --health-check` reports status as healthy.
</USER_REQUEST>
