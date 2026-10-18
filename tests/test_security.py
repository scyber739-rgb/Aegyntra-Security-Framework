from pathlib import Path
from aegyntra.engine import Engine
from aegyntra.security import Policy

def test_allowed_document(tmp_path):
    (tmp_path / "resume.txt").write_text("safe")
    assert Policy(tmp_path).check_read("resume.txt").allowed

def test_sensitive_file_denied(tmp_path):
    (tmp_path / ".env").write_text("FAKE")
    assert not Policy(tmp_path).check_read(".env").allowed

def test_path_traversal_denied(tmp_path):
    assert not Policy(tmp_path).check_read("../../etc/passwd").allowed

def test_symlink_escape_denied(tmp_path):
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("synthetic")
    (tmp_path / "escape.txt").symlink_to(outside)
    assert not Policy(tmp_path).check_read("escape.txt").allowed

def test_unknown_actions_denied(tmp_path):
    assert not Policy(tmp_path).check_action("shell", "whoami").allowed

def test_network_default_deny(tmp_path):
    assert not Policy(tmp_path).check_network("https://example.com/").allowed

def test_decoy_event(tmp_path):
    (tmp_path / "DECOY_CREDENTIALS.txt").write_text("FAKE")
    e = Engine(tmp_path, tmp_path / "events.sqlite3")
    result = e.evaluate("read_file", "DECOY_CREDENTIALS.txt")
    assert not result["allowed"] and result["severity"] == "critical"
    assert e.events()[0]["reason"] == "decoy credential access detected"
