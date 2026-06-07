# NetVisor Infrastructure

Infrastructure-only assets live here so the repository root stays focused on runtime source code.

## Layout

- `docker/` contains Dockerfiles and reverse-proxy configuration used by the root `docker-compose.yml`.
- `database/` contains the base schema and idempotent migration scripts.
- `deployment/` contains role-specific deployment templates for generated server, agent, and gateway bundles.

The root `docker-compose.yml` remains at the repository root because that is the conventional Docker entrypoint for local deployment.
