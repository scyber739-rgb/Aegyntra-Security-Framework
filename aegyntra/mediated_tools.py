"""Mediated tools for the restricted AEGYNTRA demo runtime.

Only approved reads are executed. Shell and network operations are denied locally.
This is NOT a universal OS-level syscall monitor.
"""
from pathlib import Path
import hashlib
import os

class MediatedTools:
    def __init__(self, evaluate, emit, workspace):
        self.evaluate = evaluate
        self.emit = emit
        self.workspace = Path(workspace).resolve()

    def _record(self, action, target, decision, reason, **details):
        # Never record file contents, credentials or API tokens.
        self.emit("tool." + action, target, decision, reason, details)

    def read_demo_file(self, name="hello.txt"):
        # Server policy must allow the action before any file is opened.
        decision = self.evaluate("read_file", name, "input")
        if decision["decision"] != "allow":
            self._record("read_file", name, "deny", "server policy denied")
            return None
        if name != "hello.txt":
            self._record("read_file", name, "deny", "demo allowlist")
            return None
        # Imported files have opaque IDs; select only the exact basename suffix.
        candidates = [p for p in self.workspace.iterdir()
                      if p.is_file() and p.name.startswith("fil_") and p.name[21:] == name]
        if len(candidates) != 1:
            self._record("read_file", name, "deny", "file missing or ambiguous")
            return None
        path = candidates[0]
        if path.is_symlink() or not path.resolve().is_relative_to(self.workspace):
            self._record("read_file", name, "deny", "unsafe path")
            return None
        # The demo reads at most 4 KiB; never send content to the control plane.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            data = os.read(fd, 4097)
        finally:
            os.close(fd)
        if len(data) > 4096:
            self._record("read_file", name, "deny", "demo size limit")
            return None
        self._record("read_file", name, "allow", "mediated read completed",
                     size=len(data), sha256=hashlib.sha256(data).hexdigest())
        return data

    def deny_command(self, command):
        self.evaluate("execute_command", command, "input")
        self._record("execute_command", "[command withheld]", "deny",
                     "shell execution disabled in demo")
        return False

    def deny_network(self, destination):
        self.evaluate("network_connect", destination, "input")
        self._record("network_connect", destination, "deny",
                     "network tool disabled; container network is internal-only")
        return False
