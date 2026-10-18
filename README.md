# Aegyntra — AI Agent Security Platform

**Autonomous AI Agent Security and Credential Protection Framework**

Aegyntra is an evolving security research platform for running controlled evaluations against a real provider-backed AI model while mediating a deliberately limited tool surface. It records policy decisions and provides a professional local dashboard for agent evaluation, event review, and heuristic behavior findings.

> **Important status:** v0.2 is a real-provider evaluation platform, not a production security product. It mediates only tool calls routed through its adapter. It is not a secure VM/container, universal agent interceptor, credential vault, host EDR, tamper-proof SIEM, or network firewall. Use synthetic data in an isolated lab. Never use real credentials in test prompts or files.

## Features in this branch
- Real OpenAI-compatible Chat Completions model calls with tool calling.
- A narrow workspace-file tool; proposed reads pass through the policy engine before adapter execution.
- Default-deny behavior for unsupported actions and unapproved paths.
- SQLite policy event records and synthetic decoy credential alerts.
- Local dashboard with event stream, decision counts, severity indicators, and a real-agent evaluation form.
- Request schema bounds, optional API token auth, bounded tool rounds, and sanitized provider errors.
- Docker Compose hardening defaults: non-root process, read-only root filesystem, dropped capabilities, no-new-privileges, resource limits, loopback-only host port.
- Threat model and real-agent test guide.

## Run locally
Python 3.10+ required:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e '.[test,agent]'
mkdir -p demo_workspace
printf 'Aegyntra lab notes; no secrets here.\\n' > demo_workspace/lab-notes.txt
export OPENAI_API_KEY='your-provider-key'
export AEGYNTRA_MODEL='gpt-4.1-mini'
export AEGYNTRA_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn aegyntra.platform:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. Paste the configured Aegyntra API token into the dashboard if enabled. Keep the provider key only in the server environment; do not put it in browser code, prompts, or the repository.

Run tests:

```bash
pytest -v
```

Run the original offline policy demonstration:

```bash
python -m aegyntra.demo
```

## Docker Compose

Create a `.env` file from `.env.example`, edit it locally with your provider key and a long random Aegyntra token, and ensure `demo_workspace/` exists. Do not commit `.env`.

```bash
cp .env.example .env
mkdir -p demo_workspace
docker compose up --build
```

Open http://127.0.0.1:8000. The host port is bound to loopback. Compose is a hardened starting point, not a guarantee of isolation; inspect and adapt it to your environment.

## Safe evaluation scenarios
See [docs/REAL_AGENT_TESTING.md](docs/REAL_AGENT_TESTING.md). Use synthetic documents and scripted test personas to evaluate benign behavior, prompt injection, decoy access, path escapes, credential solicitation, and repeated policy violations. Do not test manipulative prompts on unsuspecting people or connect the agent to production accounts.

## Security boundaries
- Only tools explicitly provided to the model are available through this adapter; there is no shell tool or arbitrary HTTP tool.
- Aegyntra cannot observe or block a different SDK, process, direct socket, compromised host, or agent that bypasses the adapter.
- Heuristic output findings are indicators, not proof of malicious intent; measure false positives and false negatives.
- Current SQLite evidence is local and mutable. Host telemetry, cryptographic evidence chaining, credential brokerage, universal integrations, and OPNsense containment remain future engineering milestones.
- Keep the control plane outside the agent VM/container trust boundary. Disable shared folders, clipboard, and drag/drop for an adversarial VM; enforce default-deny egress outside this application.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/SECURITY.md](docs/SECURITY.md) before running adversarial tests.
