# NetVisor

NetVisor is a self-hosted security workspace for managed endpoints and metadata-only BYOD visibility.

## What It Is

- `app/` hosts the backend API and services.
- `agent/` collects managed-endpoint telemetry and DPI evidence.
- `gateway/` handles metadata-only BYOD collection.
- `frontend/` is the analyst console.
- `shared/` contains runtime code reused by the agent and gateway.
- `docs/project-structure.md` defines what belongs in each top-level path.

Generated output lives outside the source tree:

- `runtime/` for local state and backups
- `build/deploy/` for packaged role bundles
- `share_agent.zip` for temporary agent sharing packages

## Quick Start

1. Run `python scripts/init_env.py` to create a local `.env` from the tracked template.
2. Install the NetVisor package: `python scripts/install_package.py`
3. Edit `.env` with the database, secret, and bootstrap keys.
4. Initialize the database with `mysql -u root -p < database\init.sql`.
5. Start the backend with `python run_server.py`.
6. Start the agent with `python run_agent.py`.
7. Start the gateway with `python run_gateway.py`.

## Useful Commands

- `python run_server.py --health-check`
- `python run_agent.py --health-check`
- `python run_gateway.py --health-check`
- `python scripts/build_deploy_bundles.py --role server --role agent --role gateway`

Frontend checks:

```powershell
cd frontend
npm run lint
npm run build
```

## Docs

- [Quick Start](docs/quickstart.md)
- [Environment Setup](docs/env-setup.md)
- [Project Structure](docs/project-structure.md)
- [Agent/Gateway Flow](docs/agent-gateway-flow.md)
- [Runbook](docs/runbook.md)
- [Architecture Spec](docs/architecture-spec.md)
- [Security Operations](docs/security_operations.md)
- [Deployment Overview](deployment/README.md)
- [Server Deployment](deployment/server/README.md)
- [Agent Deployment](deployment/agent/README.md)
- [Gateway Deployment](deployment/gateway/README.md)
