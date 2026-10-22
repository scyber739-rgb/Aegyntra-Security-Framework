# Aegyntra v1.0 architecture

Implemented: authenticated local FastAPI control plane; SQLite agents, Vaults, file inventory, requests, events, policies and incidents; default-deny mediated action evaluation; user-selected file import; input/output/quarantine/evidence spaces; file requests with manual import required; hash-linked audit verification; dashboard and external telemetry ingestion.

Not implemented: universal agent interception, native OpenClaw adapter, Windows ETW/file minifilter/WFP sensor, host firewall control, VM/container launcher, malware scanner or sandbox escape protection. Vault folders are storage separation, not safe code execution isolation. Use a patched disposable VM for untrusted agents. Hash-linked logs are tamper-evident, not tamper-proof against privileged attackers.


## Restricted demo runtime integration

The Compose profile runs a deterministic agent process for validating Vault pairing, scoped runtime authentication, server-side policy evaluation, and event ingestion. It is not an LLM and does not execute arbitrary code.

- A Vault access code is random, single-use, expires after 15 minutes, and is stored as a SHA-256 hash.
- Pairing exchanges the code for a separate runtime token; the server stores the runtime token hash.
- The selected Vault input folder is mounted read-only into the agent container.
- The agent container receives no Docker socket, drops Linux capabilities, has no-new-privileges, a read-only root filesystem, PID/memory/CPU limits, and an internal-only network.
- The agent reads a selected text file if the policy allows it, submits policy test cases for traversal / shell / network actions without executing them, and reports a heartbeat every 15 seconds.
- Heartbeats are observed telemetry, not cryptographic attestation. A policy decision is not general-purpose OS enforcement.
- A provider-backed agent should be added only behind a tool broker that enforces policy before actions. For adversarial workloads, use a disposable VM and never mount host secrets or the Docker socket.
