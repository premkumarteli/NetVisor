# NetVisor Project Structure

This repository is organized around runtime roles. Source code stays in role-specific folders; generated packages, runtime state, and temporary files stay out of git.

## Source Layout

| Path | Purpose |
| --- | --- |
| `app/` | FastAPI backend, API routers, service layer, enrollment, observability, analytics, and persistence orchestration. |
| `agent/` | Managed endpoint collector: capture, discovery, enrollment, heartbeat, upload worker, and DPI launch/control paths. |
| `gateway/` | Metadata-only network gateway collector for BYOD and unmanaged traffic visibility. |
| `shared/` | Runtime code intentionally shared by `agent/`, `gateway/`, and backend services. Do not delete this folder; it is not a generated share-agent bundle. |
| `frontend/` | React/Vite analyst console, immersion engine, dashboard pages, API client, and UI styles. |
| `database/` | Database bootstrap and schema assets. |
| `deployment/` | Role-specific deployment bundle templates, setup helpers, and deployment documentation. |
| `scripts/` | Developer and release automation: package install, bundle build, connectivity checks, and environment setup. |
| `tests/` | Backend, security, ingestion, classification, and operational regression tests. |
| `docs/` | Human-facing architecture, runbooks, setup guides, and project conventions. |
| `config/` | Tracked baseline configuration templates for local roles. |

## Root Files

| File | Purpose |
| --- | --- |
| `run_server.py` | Local backend entrypoint. |
| `run_agent.py` | Local managed-agent entrypoint. |
| `run_gateway.py` | Local gateway entrypoint. |
| `run_flow_worker.py` | Local flow worker entrypoint. |
| `build_share_agent.py` | Convenience wrapper for creating deployable agent bundles. |
| `pyproject.toml` | Python package metadata for editable installs and standard imports. |
| `.env.example` | Tracked configuration template. |
| `.env` | Local secrets and machine-specific configuration; ignored by git. |

## Generated And Local-Only Paths

These paths should remain ignored and can be rebuilt or regenerated:

| Path | Reason |
| --- | --- |
| `runtime/` | Local encrypted transport state, credentials, backup/runtime data. |
| `build/` | Generated deployable server, agent, and gateway bundles. |
| `tmp/` | Scratch transport and test directories. Stop running services before deleting it. |
| `.venv/`, `.venv-1/`, `venv/` | Local Python virtual environments. |
| `frontend/node_modules/`, `frontend/dist/`, `frontend/.vite/` | Frontend dependencies and generated build output. |
| `share_agent/`, `share_agent.zip` | Generated agent bundle output for copying to another system. |
| `scratch/`, `all_fd.txt`, `generate_all_fd.py` | Local investigation/code-dump artifacts. |

## Engineering Rules

- Keep role code inside the matching role folder unless it is genuinely shared.
- Put reusable cross-role runtime utilities in `shared/`.
- Put backend business logic in `app/services/`, not directly inside API routers.
- Put frontend environmental rendering under `frontend/src/immersion/`; keep page components focused on data and layout.
- Do not commit `.env`, local runtime state, deployable ZIPs, generated bundles, logs, or code-dump files.
- If `shared/` becomes too broad later, refactor it deliberately into a package name such as `netvisor_common`; do not delete it as cleanup.
