"""Safe demo runtime: only reads a synthetic fixture and submits policy test cases.
It never runs shell commands or makes arbitrary outbound requests.
"""
import json, os, time, urllib.error, urllib.request
from pathlib import Path

API = os.environ.get("AEGYNTRA_API_URL", "http://aegyntra:8010").rstrip("/")
CODE = os.environ.get("AEGYNTRA_ACCESS_CODE", "")
WORKSPACE = Path(os.environ.get("AEGYNTRA_WORKSPACE", "/workspace")).resolve()
INPUT = (WORKSPACE / "input").resolve()
TOKEN = ""

def call(path, payload=None, runtime=False):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if runtime:
        headers["X-Aegyntra-Runtime-Token"] = TOKEN
    req = urllib.request.Request(API + path, data=data, headers=headers, method="GET" if payload is None else "POST")
    with urllib.request.urlopen(req, timeout=8) as res:
        return json.loads(res.read().decode())

def main():
    global TOKEN
    if not CODE:
        raise SystemExit("Set AEGYNTRA_ACCESS_CODE to the one-time Vault access code.")
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    INPUT.mkdir(parents=True, exist_ok=True)
    fixture = INPUT / "hello.txt"
    if not fixture.exists():
        fixture.write_text("Synthetic Aegyntra safe test fixture. No secrets.\n", encoding="utf-8")
    paired = call("/api/v1/runtime/pair", {"code": CODE})
    TOKEN = paired["runtime_token"]
    print("Paired with Vault:", paired["vault_id"], flush=True)
    print("Agent ID:", paired["agent_id"], flush=True)
    print("Running safe policy test suite. No shell or network probes will be executed.", flush=True)

    tests = [
        ("read_file", "hello.txt", "input"),
        ("read_file", "../../etc/passwd", "input"),
        ("execute_command", "id", "input"),
        ("network_connect", "example.invalid:443", "input"),
        ("write_file", "report.txt", "input"),
        ("create_artifact", "report.txt", "output"),
    ]
    for action, target, space in tests:
        try:
            result = call("/api/v1/runtime/evaluate", {"action": action, "target": target, "space": space}, runtime=True)
            if action == "read_file" and target == "hello.txt" and result["decision"] == "allow":
                safe = (INPUT / target).resolve()
                if safe.is_relative_to(INPUT) and safe.is_file():
                    preview = safe.read_text(encoding="utf-8")[:120]
                    print("READ OK:", target, "->", repr(preview), flush=True)
            print(result["decision"].upper(), action, target, "|", result["reason"], flush=True)
        except Exception as exc:
            print("TEST ERROR:", action, type(exc).__name__, str(exc), flush=True)
    print("Demo tests complete; sending heartbeat every 15 seconds. Ctrl+C to stop.", flush=True)
    while True:
        try:
            call("/api/v1/runtime/heartbeat", {"action": "runtime.heartbeat", "target": paired["vault_id"], "decision": "allow", "reason": "demo runtime heartbeat", "severity": "info", "details": {}}, runtime=True)
            print("HEARTBEAT OK", time.strftime("%H:%M:%S"), flush=True)
        except Exception as exc:
            print("HEARTBEAT ERROR:", type(exc).__name__, str(exc), flush=True)
        time.sleep(15)

if __name__ == "__main__":
    main()
