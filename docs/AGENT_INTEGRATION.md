# Agent log integration

Aegyntra does not automatically hook arbitrary running agents. Register an agent, then send metadata-only events to POST /api/v1/events/ingest with the X-Aegyntra-Token header.

Example JSON: {"agent_id":"agt_registered_id","session_id":"session-123","action":"file.read","target":"project/src/main.py","decision":"observe","reason":"adapter reported file read","severity":"info","source":"openclaw-adapter","details":{"event_type":"tool_result","duration_ms":12}}

Never send file contents, raw prompts, tokens, passwords or credentials. An ingested event is not proof Windows blocked an action. A native OpenClaw adapter requires version-specific hook/log integration. Run unknown agents in a disposable VM; do not mount home folders, SSH keys, browser profiles or Docker sockets. Distinguish simulator, adapter and OS-sensor evidence.
