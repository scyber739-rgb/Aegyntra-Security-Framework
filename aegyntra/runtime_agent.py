"""Restricted deterministic agent with mediated operations and scoped telemetry.

No arbitrary downloaded agent is executed. Runtime events are adapter-reported.
"""
import json
import os
import time
import urllib.request
from pathlib import Path
from .mediated_tools import MediatedTools

API = os.environ.get("AEGYNTRA_API_URL", "http://aegyntra:8010").rstrip("/")
CODE = os.environ.get("AEGYNTRA_ACCESS_CODE", "")
VAULT_ID = os.environ.get("AEGYNTRA_VAULT_ID", "")
INPUT = Path(os.environ.get("AEGYNTRA_WORKSPACE", "/vault-input")).resolve()
TOKEN = ""

def call(path, payload=None, runtime=False):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if runtime:
        headers["X-Aegyntra-Runtime-Token"] = TOKEN
    request = urllib.request.Request(
        API + path, data=data, headers=headers,
        method="GET" if payload is None else "POST"
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        return json.loads(response.read().decode())

def evaluate(action, target, space="input"):
    # Fail closed: an unavailable policy service raises and the tool does not run.
    return call("/api/v1/runtime/evaluate",
                {"action": action, "target": target, "space": space}, runtime=True)

def emit(action, target, decision, reason, details=None):
    # Operational telemetry: no file contents, prompts or secret tokens.
    return call("/api/v1/runtime/events", {
        "action": action, "target": target, "decision": decision,
        "reason": reason, "severity": "info" if decision == "allow" else "medium",
        "details": details or {}
    }, runtime=True)

def main():
    global TOKEN
    if not CODE or not VAULT_ID:
        raise SystemExit("A Vault ID and one-time pairing code are required.")
    paired = call("/api/v1/runtime/pair", {"code": CODE})
    if paired["vault_id"] != VAULT_ID:
        raise SystemExit("Pairing Vault mismatch. Stop and generate a new code.")
    TOKEN = paired["runtime_token"]
    print("PAIRED", paired["vault_id"], paired["agent_id"], flush=True)

    tools = MediatedTools(evaluate, emit, INPUT)
    # Only this mediated operation actually reads data.
    try:
        data = tools.read_demo_file("hello.txt")
        print("MEDIATED READ", "OK" if data is not None else "DENIED/SKIPPED",
              flush=True)
    except Exception as exc:
        print("MEDIATED READ FAILED CLOSED", type(exc).__name__, flush=True)
    # These calls are never executed as shell commands or network connections.
    for action, target in [
        ("read_file", "../../etc/passwd"),
        ("execute_command", "id"),
        ("network_connect", "example.invalid:443"),
        ("write_file", "report.txt"),
        ("create_artifact", "report.txt"),
    ]:
        try:
            result = evaluate(action, target,
                              "output" if action == "create_artifact" else "input")
            print("POLICY", result["decision"].upper(), action, target, flush=True)
        except Exception as exc:
            print("POLICY UNAVAILABLE", action, type(exc).__name__, flush=True)
    try:
        tools.deny_command("id")
        tools.deny_network("example.invalid:443")
    except Exception as exc:
        print("TOOL DENIED (TELEMETRY ERROR)", type(exc).__name__, flush=True)

    print("HEARTBEAT every 15 seconds; Ctrl+C to stop.", flush=True)
    while True:
        try:
            call("/api/v1/runtime/heartbeat", {
                "action": "runtime.heartbeat", "target": VAULT_ID,
                "decision": "allow", "reason": "demo runtime heartbeat",
                "severity": "info", "details": {}
            }, runtime=True)
            print("HEARTBEAT OK", time.strftime("%H:%M:%S"), flush=True)
        except Exception as exc:
            print("HEARTBEAT ERROR", type(exc).__name__, flush=True)
        time.sleep(15)

if __name__ == "__main__":
    main()
