#!/usr/bin/env bash
# AEGYNTRA one-command local bootstrap for Kali/WSL or Linux with Podman Compose.
# This starts the existing control plane only; it does not claim to install a
# kernel sensor or deploy an Ollama/DeepSeek model.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

say() { printf '\n[AEGYNTRA] %s\n' "$*"; }
fail() { printf '\n[AEGYNTRA ERROR] %s\n' "$*" >&2; exit 1; }

command -v podman >/dev/null 2>&1 || fail "Podman not found. Install Podman and its Compose provider first."
podman compose version >/dev/null 2>&1 || fail "Podman Compose provider is missing. Install/configure podman-compose or Docker Compose compatibility."

# Start the rootless Podman API socket when systemd user services are available.
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user start podman.socket >/dev/null 2>&1 || true
fi
podman info >/dev/null 2>&1 || fail "Podman engine is unavailable. Check 'podman info' before retrying."

# Create a local-only dashboard token once. Never overwrite an existing .env.
if [[ ! -f .env ]]; then
  command -v python3 >/dev/null 2>&1 || fail "python3 is required to create the local token."
  umask 077
  python3 - <<'PY'
from pathlib import Path
import secrets
Path(".env").write_text(
    "AEGYNTRA_API_TOKEN=" + secrets.token_urlsafe(36) + "\n"
    "AEGYNTRA_DATA_DIR=/app/data\n"
    "AEGYNTRA_MAX_UPLOAD_MB=15\n",
    encoding="utf-8",
)
PY
  chmod 600 .env 2>/dev/null || true
  say "Created a private .env and generated a random dashboard token."
elif ! grep -Eq '^AEGYNTRA_API_TOKEN=.{20,}$' .env; then
  fail ".env exists but AEGYNTRA_API_TOKEN is missing/too short. Fix it without sharing the secret."
fi

say "Building and starting the AEGYNTRA control plane..."
podman compose up --build -d aegyntra

say "Waiting for the health endpoint..."
ready=0
for _ in $(seq 1 45); do
  if curl --fail --silent --show-error http://127.0.0.1:8010/health >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done

if [[ "$ready" != "1" ]]; then
  podman compose ps -a || true
  podman compose logs --tail=100 aegyntra || true
  fail "Health check failed. Review the logs above."
fi

printf '\n============================================================\n'
printf ' AEGYNTRA dashboard: http://127.0.0.1:8010\n'
printf ' Health:              http://127.0.0.1:8010/health\n'
printf '============================================================\n'
printf '\nDashboard token (keep private; not an AI provider key):\n'
python3 - <<'PY'
from pathlib import Path
for line in Path(".env").read_text().splitlines():
    if line.startswith("AEGYNTRA_API_TOKEN="):
        print(line.split("=", 1)[1].strip().strip('"').strip("'"))
        break
PY

# Best-effort browser launch. If no desktop/browser bridge exists, print URL above.
if grep -qi microsoft /proc/version 2>/dev/null && command -v cmd.exe >/dev/null 2>&1; then
  cmd.exe /c start http://127.0.0.1:8010 >/dev/null 2>&1 || true
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open http://127.0.0.1:8010 >/dev/null 2>&1 &
fi

say "Dashboard is ready. This bootstrap does not deploy an LLM or enable kernel-level enforcement."
