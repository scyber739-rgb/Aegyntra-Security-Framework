# Security and threat model (starter)

## Assets
Real host credentials, user files, host operating system, security controller, and audit evidence.

## Adversaries
Malicious, compromised, or prompt-injected local AI agents that may propose unauthorized tool calls, read files, execute commands, or transmit data.

## Trust boundaries
The untrusted agent VM must be separate from the trusted policy/controller VM. Disable shared folders, clipboard, drag-and-drop and host credential mounts. Never bridge untrusted VM traffic to the home network. Apply default-deny egress at the firewall. Do not treat VM isolation as a guarantee.

## Prototype limitations
The v0.1 API is a simulation, not an execution enforcement boundary. File checks have time-of-check/time-of-use race risks if later connected to real file operations; production mediation needs handle-based secure opens and OS restrictions. DNS allowlisting alone is insufficient; a network proxy and firewall must pin destination and enforce IP policy. SQLite events are not tamper-evident. No real credential broker, telemetry sensor, authentication, or containment exists yet.

## Responsible testing
Use synthetic files, fake credentials, and mock endpoints only. Keep the API on loopback and never put production credentials or real user data inside the sandbox.
