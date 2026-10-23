# Runtime security: Phase 1 (Podman / Docker Compose)

## Scope and evidence classification

This phase adds a **mediated deterministic demo runner**, not a generic untrusted
AI-agent launcher. Agent actions through `MediatedTools` are policy checked
before a file read. Tool decisions and read outcomes are reported to the
existing authenticated runtime event endpoint and hash-linked event ledger.
Agent-reported telemetry is **not** kernel-verified evidence. No eBPF, seccomp
notification listener, syscall capture, host firewall integration or VM
provisioning is included.

## Starting from Kali WSL (Podman)

```bash
cd "/mnt/c/Users/Ruthra Balan/Aegyntra-Security-Framework"
git fetch origin
git switch feature/vault-visibility-phase1
git pull --ff-only
systemctl --user start podman.socket
podman compose up --build -d aegyntra
podman compose ps
curl -i http://127.0.0.1:8010/health
```

The existing `.env` must contain a private `AEGYNTRA_API_TOKEN`. Do not
publish the token, one-time pairing code, runtime token or real user data.

Open http://127.0.0.1:8010 and authenticate. Register a demo agent in
**AI Agents**, create a testing Vault in **Vaults & Spaces**, and import a
synthetic file named `hello.txt` into its input space. Example:

```bash
printf 'Synthetic test data; no credentials.\n' > /tmp/hello.txt
```

Use **Pair a demo agent** to select that agent and Vault, then generate a
one-time code. Execute the dashboard-provided Compose command, substituting
`podman compose` for `docker compose` if necessary:

```bash
AEGYNTRA_VAULT_ID='vlt_FROM_DASHBOARD' AEGYNTRA_ACCESS_CODE='CODE_FROM_DASHBOARD' \
  podman compose --profile agent run --rm agent-runner
```

Codes expire after 15 minutes and are single-use. Never paste them into a
public issue or share terminal history. The demo agent reports policy
decisions, one mediated file read (if allowed), denied shell/network tool
attempts, and heartbeats. In another terminal:

```bash
podman ps
podman compose logs --tail=80 aegyntra
```

Inspect **Activity & Logs**, **Vault Interior / Runtime Evidence**, and
**Alerts & Incidents**. Event source `runtime-agent` indicates agent-reported
telemetry, not verified OS enforcement. `runtime-policy` indicates a
server-side decision, not that an attempted syscall occurred.

## Existing container restrictions

Compose config limits the demo runner to a read-only root filesystem,
read-only selected Vault input mount, no Docker/Podman socket mount,
no-new-privileges, dropped capabilities, resource limits, and an
internal-only network. Validate Podman support and effective enforcement on
your machine before treating these as security guarantees.

```bash
podman inspect aegyntra-control-plane --format '{{json .HostConfig.SecurityOpt}}'
podman network ls
podman compose config
```

## Stop and cleanup

Press Ctrl+C in the foreground agent terminal. `--rm` removes the agent
container on exit. Restart the control plane with
`podman compose restart aegyntra`. Stop with
`podman compose stop aegyntra`. Remove Compose containers/networks with
`podman compose down`; do not delete `./data` or prune volumes unless
you have backed up evidence.

## Known limitations / follow-up

- No automatic arbitrary agent download or dynamic container provisioning.
- No provider-backed LLM agent adapter.
- No universal interception of file/network/process syscalls.
- No host firewall enforcement or proof of sandbox isolation.
- No end-to-end Podman run verified by the authoring environment.
- Telemetry delivery can fail; tool operations should remain denied when
  policy is unavailable, but existing file-read telemetry is post-operation.
- Do not run untrusted downloaded code on the host. For adversarial code,
  use a patched disposable VM with no sensitive mounts.

Future phases: allowlisted image digests, privileged *separate* provisioning
service, signed agent manifests, mediated LLM tool adapters, kernel-level
observation, network egress gateway, and testable kill/containment workflow.
