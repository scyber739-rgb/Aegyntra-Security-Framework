# Aegyntra

**Autonomous AI Agent Security and Credential Protection Framework**

Aegyntra is an educational security research prototype for evaluating *proposed* AI agent actions **before execution**. This starter implementation provides a fail-closed policy engine, decoy-credential alerts, SQLite audit events, and a local FastAPI demonstration API.

> **Security status:** v0.1 is a policy simulator, **not** a secure agent sandbox, credential vault, real HTTP proxy, host monitor, or production-grade enforcement system. It cannot stop agents that bypass the gateway. Never use real credentials in demonstrations.

## Quick start

Python 3.10+ required.

```bash
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -e '.[test]'
python -m aegyntra.demo
pytest -q
```

Run the local API (only on loopback):

```bash
uvicorn aegyntra.api:app --host 127.0.0.1 --port 8000
curl -X POST http://127.0.0.1:8000/evaluate -H 'Content-Type: application/json' -d '{"action":"shell","target":"whoami"}'
```

Available routes: `GET /health`, `POST /evaluate`, `GET /events`. The API **evaluates** actions but does **not** execute them. The endpoint is unauthenticated, so do not expose it beyond loopback. Network checks are advisory only; no network requests are performed.

## Current features

- Allow read of ordinary files under a configured demo workspace
- Deny traversal, missing paths, symlink escapes, hidden paths, `.key`/`.pem` files
- Deny shell and other unsupported actions by default
- Deny network destinations by default
- Detect accesses to synthetic `DECOY_CREDENTIALS.txt`
- Persist decisions and explanations to SQLite
- Offline demo and unit tests

## Planned research roadmap

1. Threat model and sandbox isolation (VirtualBox + separate trusted controller)
2. Tool-call enforcement adapter with strict per-agent permissions
3. Credential broker that never returns raw credentials to agents
4. OS file/process telemetry, decoy correlation, audit integrity
5. OPNsense default-deny egress and tested containment
6. Dashboard, adversarial evaluations, prevention and false-positive metrics

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
