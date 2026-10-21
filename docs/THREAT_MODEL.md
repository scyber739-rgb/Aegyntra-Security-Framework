# Threat model

Assets: user files, API tokens, task data, Vault artifacts, policy configuration, audit evidence and endpoint integrity. Threats: malicious prompts, compromised agents, untrusted tools, sensitive-file access, exfiltration, gateway bypass, dashboard/API misuse and audit tampering.

Objectives: least privilege, explicit consent, task-scoped access, default-deny mediated decisions, evidence and safe artifact handling.

Limits: event completeness depends on the adapter; only routed actions or OS/VM-blocked actions can be prevented; filename classification is heuristic, not antivirus; Vault directories do not sandbox execution; privileged attackers can rewrite local data.

Production follow-up: hardened VM lifecycle/snapshots; Windows process/file/network telemetry; VM egress kill switch; OpenClaw adapter; isolated content-aware malware scanning; external append-only evidence; adversarial testing.
