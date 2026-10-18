"""Offline demonstration: evaluate actions without performing them."""
from pathlib import Path
from tempfile import TemporaryDirectory
from .engine import Engine

def main():
    with TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "resume.txt").write_text("Demo resume (synthetic)", encoding="utf-8")
        (root / "DECOY_CREDENTIALS.txt").write_text("FAKE-DO-NOT-USE", encoding="utf-8")
        engine = Engine(root, root / "events.sqlite3")
        for action, target in [("read_file", "resume.txt"), ("read_file", "DECOY_CREDENTIALS.txt"),
                               ("read_file", "/etc/passwd"), ("shell", "cat ~/.ssh/id_rsa"),
                               ("http_request", "https://example.org/upload")]:
            event = engine.evaluate(action, target)
            print(f'{"ALLOW" if event["allowed"] else "DENY"}: {action} {target} -> {event["reason"]}')

if __name__ == "__main__":
    main()
