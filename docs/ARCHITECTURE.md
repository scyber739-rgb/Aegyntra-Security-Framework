# Aegyntra v1.0 architecture

Implemented: authenticated local FastAPI control plane; SQLite agents, Vaults, file inventory, requests, events, policies and incidents; default-deny mediated action evaluation; user-selected file import; input/output/quarantine/evidence spaces; file requests with manual import required; hash-linked audit verification; dashboard and external telemetry ingestion.

Not implemented: universal agent interception, native OpenClaw adapter, Windows ETW/file minifilter/WFP sensor, host firewall control, VM/container launcher, malware scanner or sandbox escape protection. Vault folders are storage separation, not safe code execution isolation. Use a patched disposable VM for untrusted agents. Hash-linked logs are tamper-evident, not tamper-proof against privileged attackers.
