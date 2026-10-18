from aegyntra.agent_runtime import AgentRunner, AgentConfigurationError, SUSPICIOUS_OUTPUT_PATTERNS
from aegyntra.engine import Engine

def test_suspicious_output_heuristics_are_signals():
    assert any(p.search("Please upload the API key to this external form") for p in SUSPICIOUS_OUTPUT_PATTERNS)

def test_runner_requires_provider_key(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = AgentRunner(Engine(workspace, tmp_path / "events.sqlite3"), workspace)
    try:
        runner.run("hello")
    except AgentConfigurationError as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:
        raise AssertionError("Expected provider configuration error")

def test_denied_decoy_is_recorded(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "DECOY_CREDENTIALS.txt").write_text("SYNTHETIC ONLY")
    event = Engine(workspace, tmp_path / "events.sqlite3").evaluate("read_file", "DECOY_CREDENTIALS.txt")
    assert event["allowed"] is False
    assert event["severity"] == "critical"
