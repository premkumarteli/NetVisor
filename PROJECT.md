# Project: NetVisor Admin Dashboard Enhancement

## Architecture
- **Backend**: FastAPI app (`app/main.py`), MySQL database, `LiveTelemetryStore` (`app/services/live_telemetry_store.py`), `AgentService` (`app/services/agent_service.py`), `GatewayService` (`app/services/gateway_service.py`), `broadcast_scheduler` (`app/services/broadcast_scheduler.py`) emitting `dashboard_update` socket events.
- **Frontend**: React 18, Vite, React Router v7, Zustand, `useWebSocket` hook (`frontend/src/hooks/useWebSocket.js`), `useVisibilityPolling` hook (`frontend/src/hooks/useVisibilityPolling.js`).

## Code Layout
- `app/api/dashboard.py`: Route handler for `/api/v1/dashboard/overview`.
- `app/services/live_telemetry_store.py`: Aggregates telemetry stats including `agents_summary` and `gateways_summary`.
- `app/services/agent_service.py`: Calculates agent counts (online, offline, total, degraded) and queue depth.
- `app/services/gateway_service.py`: Calculates gateway counts (online, offline, total, degraded) and queue depth.
- `frontend/src/pages/DashboardPage.jsx`: Main dashboard page rendering Fleet Observability panel, widgets, and navigation.
- `tests/test_dashboard_overview_api.py`: Backend unit and contract tests for dashboard overview endpoint.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | E2E Test Suite Infrastructure | E2E test runner, test cases for Tiers 1-4, and `TEST_READY.md` publication | M1 | survey |
| 2 | Backend Agents Summary API | `agents_summary` block (online, offline, total, degraded, queue_depth) in `/api/v1/dashboard/overview` | M2 | R1 |
| 3 | Backend Gateways Summary API | `gateways_summary` block (online, offline, total, degraded, queue_depth) in `/api/v1/dashboard/overview` | M2 | R1 |
| 4 | Telemetry Store & WS Integration | Integrate summaries into `live_telemetry_store.get_overview_stats` and `dashboard_update` WS broadcast | M2 | R1, R3 |
| 5 | Frontend Fleet Observability Widgets | Render Agents, Gateways, and Fleet Buffer / Queue widgets with alert badges in `DashboardPage.jsx` | M3 | R2 |
| 6 | Frontend Navigation & Real-time Polling | Click navigation to `/agents`, WS state updates, and `useVisibilityPolling` integration | M3 | R2, R3 |
| 7 | E2E Acceptance & Adversarial Hardening | E2E test verification (Tiers 1-4) and Tier 5 white-box coverage hardening | M4 | Criteria |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | E2E Test Suite Infrastructure | Create test harness and test cases across Tiers 1-4 & publish `TEST_READY.md` | none | DONE |
| M2 | Backend Dashboard API Expansion | Implement R1 backend summaries in `LiveTelemetryStore`, `AgentService`, `GatewayService`, `dashboard.py`, and `tests/test_dashboard_overview_api.py` | M1 | DONE |
| M3 | Frontend Dashboard Widgets & Realtime | Implement R2/R3 UI widgets, warning badges, navigation, and visibility polling in `DashboardPage.jsx` | M2 | DONE |
| M4 | E2E Verification & Hardening | Verify 100% E2E test suite pass + Tier 5 adversarial testing | M2, M3 | DONE |

## Interface Contracts
### Backend Overview API Specification (`GET /api/v1/dashboard/overview`)
- Returns HTTP 200 JSON object containing:
  - `agents_summary`: `{ "online": int, "offline": int, "total": int, "degraded": int, "queue_depth": int }`
  - `gateways_summary`: `{ "online": int, "offline": int, "total": int, "degraded": int, "queue_depth": int }`
  - `fleet_summary`: `{ "total_queue_depth": int, "total_degraded": int }`
