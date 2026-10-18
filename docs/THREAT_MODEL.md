# Aegyntra threat model (v0.2)

## Assets
- Synthetic credentials, private workspace files, provider API keys, session artifacts, policy configuration, and audit evidence.
- Agent prompts, tool arguments/results, user-facing messages, and operator access to the control plane.

## Trust boundaries
1. Operator/control plane: trusted only when the host, dependencies, credentials, and dashboard access are protected.
2. Agent/provider: untrusted. Model output, tool calls, retrieved content, and file contents are untrusted input.
3. Mediated tool adapter: every supported tool call must pass through policy before execution.
4. Workspace: disposable, synthetic-data-only, with no host home directory or cloud credentials.
5. Host/VM/network boundary: must be enforced outside Python. Application checks are not an OS sandbox or egress firewall.
6. Evidence store: sensitive; access-control, retention limits, and tamper evidence are required for hardened deployment.

## Abuse cases and defenses
| Abuse case | Observable signals | Required defense |
|---|---|---|
| Prompt injection in retrieved content | Tool requests inconsistent with task; instructions to ignore policy | Treat content as data; least privilege; check every tool call |
| Credential solicitation/social engineering | Requests for password, MFA code, API key, recovery phrase | Output inspection, redaction, human confirmation; heuristics are not proof |
| Secret discovery/file scraping | Repeated reads, hidden paths, credential filenames, decoy access | Workspace allowlist, OS isolation, synthetic honeytokens, rate limits |
| Exfiltration | Unusual outbound destination or upload attempts | Default-deny egress firewall/proxy, DNS/IP pinning, byte limits |
| Tool abuse/command execution | Shell/process request or unknown tool | No shell by default; process allowlist and OS confinement |
| Privilege escalation | Permission changes, unexpected capabilities | Unprivileged UID, dropped capabilities, seccomp/AppArmor, read-only root |
| Persistence/log tampering | Policy edits, deleted logs, altered files | Read-only policy, remote append-only logs, integrity monitoring |
| Cross-agent leakage | Reads across workspaces or reused credentials | Per-run workspaces, tenant isolation, no shared writable volumes |
| API abuse | Auth failures, oversized requests, replay | Strong auth, TLS, rate limits, schema limits, audit logs |
| Evasion/false positives | Indirect instructions or benign text matching heuristics | Adversarial regression corpus and measured false-positive rates |

## Risk scoring
Keep severity and confidence separate. Severity estimates impact; confidence describes evidence quality. Correlate events over time before containment. Avoid inferring malicious intent from one phrase or one tool call.

## Current implementation boundaries
- Supports an OpenAI-compatible Chat Completions provider and exposes only a workspace-file tool.
- Proposed file reads are checked before the adapter opens them; shell and arbitrary network tools are not exposed.
- Output text checks are heuristic signals, not proof of malicious intent.
- Events use local SQLite and are not tamper-evident.
- No host process telemetry, universal SDK interception, production credential vault, or VM/network enforcement yet.
- API token authentication is optional for local development. Configure `AEGYNTRA_API_TOKEN` before shared use and bind to loopback.

## Safe evaluation rules
Only assess systems you own or are authorized to test. Use synthetic credentials, disposable workspaces, and scripted personas. Do not connect agents to production accounts, real users, production data, or unrestricted egress.