"""Fail-closed policy checks for a deliberately small, mediated tool surface."""
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

class Policy:
    def __init__(self, workspace: Path, allowed_hosts: set[str] | None = None):
        self.workspace = workspace.resolve(strict=True)
        self.allowed_hosts = allowed_hosts or set()

    def check_read(self, path: str) -> Decision:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self.workspace)
        except (OSError, ValueError):
            return Decision(False, "path outside workspace or missing")
        if not resolved.is_file():
            return Decision(False, "not a regular file")
        if resolved.name.startswith(".") or resolved.suffix.lower() in {".key", ".pem"}:
            return Decision(False, "sensitive filename")
        if any(part.startswith(".") for part in resolved.relative_to(self.workspace).parts):
            return Decision(False, "hidden path")
        return Decision(True, "workspace read permitted")

    def check_network(self, url: str) -> Decision:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return Decision(False, "only HTTPS URLs without embedded credentials allowed")
        if parsed.port not in (None, 443):
            return Decision(False, "nonstandard port")
        if parsed.hostname.lower() not in self.allowed_hosts:
            return Decision(False, "destination not allowlisted")
        # This check is advisory. A real network proxy must pin verified DNS/IP
        # and enforce egress at connection time to prevent DNS rebinding.
        return Decision(True, "allowlisted destination; external egress enforcement required")

    def check_action(self, action: str, target: str) -> Decision:
        if action == "read_file":
            return self.check_read(target)
        if action == "http_request":
            return self.check_network(target)
        return Decision(False, "unsupported action denied")
