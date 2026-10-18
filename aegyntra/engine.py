"""Simulated security gateway; intentionally does not execute shell or network calls."""
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from .security import Policy

class Engine:
    def __init__(self, workspace: Path, db_path: Path):
        self.workspace = workspace.resolve(strict=True)
        self.policy = Policy(self.workspace)
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.lock = threading.Lock()
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, time TEXT, action TEXT, target TEXT, allowed INTEGER, reason TEXT, severity TEXT)")
        self.db.commit()

    def evaluate(self, action: str, target: str) -> dict:
        decision = self.policy.check_action(action, target)
        # Honeytokens are deliberately fake and must never contain real secrets.
        decoy = action == "read_file" and Path(target).name == "DECOY_CREDENTIALS.txt"
        allowed = decision.allowed and not decoy
        reason = "decoy credential access detected" if decoy else decision.reason
        severity = "critical" if decoy else ("high" if not allowed else "info")
        event = {"id": str(uuid4()), "time": datetime.now(timezone.utc).isoformat(), "action": action,
                 "target": target, "allowed": allowed, "reason": reason, "severity": severity}
        with self.lock:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?)", (event["id"], event["time"], action, target, int(allowed), reason, severity))
            self.db.commit()
        return event

    def events(self, limit: int = 50) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT id,time,action,target,allowed,reason,severity FROM events ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [dict(zip(("id","time","action","target","allowed","reason","severity"), (*r[:4], bool(r[4]), *r[5:]))) for r in rows]
