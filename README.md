# Aegyntra — AI Agent Security Platform

Local-first AI-agent security control plane with Vault storage, one-time runtime pairing, policy decisions and hash-linked event evidence.

> **Runtime status:** This release includes a restricted, deterministic demo agent container. It can pair to one Vault, read a selected text file from that Vault's input folder (read-only mount), submit policy test cases, and report heartbeats. It does not yet run a provider-backed LLM, intercept arbitrary agent tools, or prove container isolation from inside the app. Shell/network deny events are policy simulations; those operations are never executed by the demo agent.

## One-command local startup (Kali WSL / Linux + Podman)

After cloning, run this **single startup command** from the repository directory:

~~~bash
bash start.sh
~~~

The script creates a private `.env` with a random dashboard token if one does not exist, builds/starts the control plane, waits for `/health`, prints the dashboard URL and token, and tries to open the browser. Open **http://127.0.0.1:8010** if the browser cannot be launched automatically. Keep `.env` private; it is git-ignored. Do not paste the token into issues or commit it.

To clone and then start (requires Git, Podman, a working Podman Compose provider, and internet access to build the image):

~~~bash
git clone https://github.com/scyber739-rgb/Aegyntra-Security-Framework.git
cd Aegyntra-Security-Framework
bash start.sh
~~~

The repository cannot safely execute code merely because `git clone` ran; one explicit `bash start.sh` is required. The script does not overwrite an existing `.env`. It does not install Podman or bypass OS permissions. If startup fails, it prints the service status/logs instead of pretending the dashboard is ready.

**Important scope note:** this starts the existing Vault/control-plane dashboard. It does **not** yet mean an Ollama/DeepSeek LLM is deployed, arbitrary external agents are automatically sandboxed, or kernel-level file access is monitored/blocked. Those features need their own implemented and tested runtime/sensor integration; the dashboard must not display them as active until verified.

## Implemented

- Authenticated local FastAPI dashboard.
- Vault storage spaces: input, output, quarantine, evidence.
- Single-use, 15-minute Vault pairing codes scoped to a registered agent and Vault; only a hash is stored.
- Separate runtime token, stored hashed by the server.
- Restricted Docker Compose demo-agent service.
- Agent mounts only the selected Vault input folder read-only; no Docker socket and no outbound network.
- Read-only container root, dropped Linux capabilities, no-new-privileges, PID/memory/CPU limits.
- Server-side policy evaluation, event timeline, incident records and hash-linked audit verification.
- Green/allow and red/deny indicators. Heartbeat is telemetry, not proof of isolation.

## Requirements

- Windows + Docker Desktop with WSL 2 integration, or Linux with Docker Engine and Docker Compose plugin.
- Git and this repository cloned locally.
- The bundled demo agent is deliberately non-executing. Do not run untrusted code on your main host.

## Docker setup and test

Run commands from the repository directory in WSL Ubuntu.

### 1. Configure dashboard token

~~~bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
~~~

Put the generated value into .env:

~~~dotenv
AEGYNTRA_API_TOKEN=put-your-generated-random-value-here
AEGYNTRA_DATA_DIR=/app/data
AEGYNTRA_MAX_UPLOAD_MB=15
~~~

Keep the token private. Never commit .env or paste secrets into public issues. The dashboard login expects AEGYNTRA_API_TOKEN, not a provider API key.

### 2. Build and start the control plane

Stop any local Uvicorn process first so two servers do not write to the same SQLite database concurrently.

~~~bash
docker compose up --build -d aegyntra
docker compose ps
docker compose logs --tail=100 aegyntra
~~~

Open http://127.0.0.1:8010 and enter the token from .env. Persistent project data is under ./data.

### 3. Create a Vault, register an agent, import a safe file

In the dashboard:

1. Open AI Agents and register an agent, for example aegyntra-demo-agent, trust untrusted.
2. Open Vaults & Spaces and create a Vault, for example Agent-Lab-01, mode Secure Testing.
3. Create a harmless text file and import it into that Vault's input space.

~~~bash
mkdir -p /tmp/aegyntra-demo
printf 'Synthetic Aegyntra test data. No secrets.\n' > /tmp/aegyntra-demo/hello.txt
~~~

Use Import selected file to upload hello.txt. Confirm it appears in the Vault inventory. Do not upload secrets or personal files.

### 4. Pair the demo agent

In Vaults & Spaces, find Pair a demo agent:

1. Select the Vault.
2. Select the registered agent.
3. Click Generate one-time access code.
4. Copy the command immediately. The code expires in 15 minutes, can be used once, and is not shown again.

The dashboard prints a command shaped like this:

~~~bash
AEGYNTRA_VAULT_ID='vlt_...' AEGYNTRA_ACCESS_CODE='one-time-code' docker compose --profile agent run --rm agent-runner
~~~

Run the exact generated command from the repository root in WSL. Do not manually substitute the Vault ID or code. The selected Vault's input folder is mounted read-only, and the pairing API checks that the code belongs to that same Vault.

### 5. Observe results

The agent should print READ OK from mounted Vault input if hello.txt is present and policy allows it, ALLOW for permitted policy cases, DENY for path traversal / shell / network policy test cases, and HEARTBEAT OK periodically.

The agent never runs shell commands or arbitrary network requests. The deny cases are simulated policy evaluations. Refresh the dashboard and inspect Vault Interior, Activity & Logs, Alerts & Incidents, and Policies & Health. Runtime status becomes stale after roughly 60 seconds without a heartbeat.

Useful commands:

~~~bash
docker compose ps -a
docker compose logs -f aegyntra
curl -s http://127.0.0.1:8010/health
docker compose down
~~~

Press Ctrl+C in the terminal running the agent to stop it. Generate a new pairing code for each run. The code is single-use.

## Access design

- Dashboard API calls use X-Aegyntra-Token, configured in .env.
- A pairing code is random, short-lived, single-use, and stored only as a SHA-256 hash.
- Pairing exchanges it for a separate runtime token; the server stores only the token hash.
- Runtime endpoints require X-Aegyntra-Runtime-Token.
- Runtime tokens are scoped to one registered agent and one Vault.
- The agent does not receive the dashboard API token.
- The agent gets no Docker socket, no Linux capabilities, a read-only root filesystem, resource limits, and an internal-only network.
- Only the selected Vault input directory is mounted into the agent container, read-only.

## Troubleshooting

**401 / Unauthorized:** Use the exact AEGYNTRA_API_TOKEN from .env. After changing .env, restart with docker compose up --build -d aegyntra.

**Code expired or already used:** Generate a new code and run its command before expiry.

**AEGYNTRA_VAULT_ID missing:** Use the full command printed by the dashboard.

**hello.txt not found:** Import a file whose displayed name is exactly hello.txt into the selected Vault input. Ensure the generated Vault ID matches the selected Vault.

**Agent cannot connect:** Start the control plane first. Check docker compose ps and docker compose logs aegyntra. Ensure Docker Desktop / Docker Engine and Compose are running.

**Existing data missing:** This configuration uses ./data on the host. It does not automatically import data from a previous named Docker volume. Do not delete old volumes before identifying which holds your data.

## Current limitations and next phases

- The included agent is deterministic, not a provider-backed LLM or an OpenClaw / LangChain / AutoGen adapter.
- The policy API logs decisions. The demo runner enforces its limited behavior by only reading a selected mounted text file and never launching arbitrary commands. Do not treat a policy response alone as enforcement for another agent.
- No universal Windows process sensor, ETW/file minifilter/WFP integration, malware scanning, Docker daemon orchestration, VM lifecycle or sandbox-escape proof.
- Heartbeat confirms a paired process can reach the API; it does not cryptographically prove container isolation.
- Vault storage, output, quarantine and evidence are not a replacement for a dedicated disposable VM when testing genuinely malicious code.

## Manual Python development (control plane only)

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
cp .env.example .env
uvicorn aegyntra.platform:app --host 127.0.0.1 --port 8010 --env-file .env
~~~

Set a strong token in .env before running. The manual Python server is control-plane-only; the demo-agent workflow requires Docker Compose.

## Tests

~~~bash
python -m pip install -e '.[test]'
python -m pytest -v
~~~

See docs/ARCHITECTURE.md for the architecture and runtime security assumptions.
