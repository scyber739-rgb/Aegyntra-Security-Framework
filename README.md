# Aegyntra — AI Agent Security Platform

Local-first AI agent security control plane, Secure Spaces and Vault evidence dashboard.

Security status: working mini-project foundation, not a production EDR or universal agent firewall. It does not automatically monitor arbitrary Windows processes, launch a hardened VM, enforce Windows Firewall/WFP policies, scan malware or guarantee host isolation. Do not run untrusted agents or generated code on your primary host. Use a disposable patched VM with no sensitive mounts and restricted networking for adversarial tests.

## Windows PowerShell
Install Python 3.11+ and Git, then from the repository directory:

    py -3.12 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    python -m pip install -e ".[test]"
    Copy-Item .env.example .env
    python -c "import secrets; print(secrets.token_urlsafe(32))"

Put the generated value in .env as AEGYNTRA_API_TOKEN=... and run:

    uvicorn aegyntra.platform:app --host 127.0.0.1 --port 8010 --env-file .env

Open http://127.0.0.1:8010 and enter the same token. Never commit .env or expose provider keys in browser code.

## Ubuntu / WSL

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e '.[test]'
    cp .env.example .env
    python -c 'import secrets; print(secrets.token_urlsafe(32))'

Set the token in .env, then run:

    uvicorn aegyntra.platform:app --host 127.0.0.1 --port 8010 --env-file .env

## Docker Compose
Create .env with a strong token, then run docker compose up --build -d. Open http://127.0.0.1:8010. Stop with docker compose down. This Compose service is the control plane, not the untrusted-agent sandbox.

## Tests

    python -m pip install -e '.[test]'
    python -m pytest -v

See docs/ARCHITECTURE.md, docs/THREAT_MODEL.md and docs/AGENT_INTEGRATION.md. Native OpenClaw adapter, VM lifecycle, Windows endpoint sensor, OS egress kill switch and malware scanning remain future integration work. Do not claim enforcement until tests prove the boundary.
