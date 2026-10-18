# Aegyntra proposed architecture

```mermaid
flowchart TD
  U[User task] --> A[Integrated AI agent]
  A --> G[Pre-execution policy gateway]
  G -->|Approved tool call| S[Restricted agent sandbox]
  G -->|Denied| L[Audit events]
  S --> M[Runtime file/process/network sensors]
  M --> C[Trusted event correlation engine]
  C --> L
  C --> F[OPNsense containment controller]
  L --> D[Security dashboard]
```

**v0.1 implemented:** policy checks, event logging, decoy signals, simulation API and tests.

**Future:** actual agent adapter, credential broker, sandbox OS enforcement, firewall integration, telemetry correlation and dashboard. Tool calls cannot reveal private model reasoning; pre-execution control requires mediation of the real execution path.
