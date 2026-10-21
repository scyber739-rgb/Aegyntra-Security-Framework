import os,tempfile
from pathlib import Path
os.environ["AEGYNTRA_API_TOKEN"]="test-token-long-enough-123456"; os.environ["AEGYNTRA_DATA_DIR"]=str(Path(tempfile.mkdtemp())/"data"); os.environ["AEGYNTRA_MAX_UPLOAD_MB"]="1"
from fastapi.testclient import TestClient
from aegyntra.platform import app
from aegyntra.policy import safe_path
c=TestClient(app); H={"X-Aegyntra-Token":"test-token-long-enough-123456"}
def test_auth():
 assert c.get("/health").status_code==200; assert c.get("/api/v1/overview").status_code==401; assert c.get("/api/v1/overview",headers=H).status_code==200
def test_event_redaction():
 a=c.post("/api/v1/agents/register",headers=H,json={"name":"test"}).json(); c.post("/api/v1/events/ingest",headers=H,json={"agent_id":a["id"],"action":"file.read","target":"notes.txt","decision":"deny","severity":"high","details":{"api_token":"fake-secret"}})
 assert any(x["details"].get("api_token")=="[redacted]" for x in c.get("/api/v1/events",headers=H).json())
def test_vault_storage():
 v=c.post("/api/v1/vaults",headers=H,json={"name":"lab"}).json(); vid=v["id"]; assert c.post(f"/api/v1/vaults/{vid}/import",headers=H,files={"file":("notes.txt",b"synthetic")}).status_code==200
 assert c.post(f"/api/v1/vaults/{vid}/import",headers=H,files={"file":(".env",b"fake")}).status_code==403
 assert c.post(f"/api/v1/vaults/{vid}/outputs",headers=H,files={"file":("test.ps1",b"not executed")}).json()["space"]=="quarantine"
def test_default_deny():
 for a,t in [("read_file","../.ssh/id_rsa"),("network_connect","https://example.com"),("execute_command","whoami")]: assert c.post("/api/v1/actions/evaluate",headers=H,json={"action":a,"target":t}).json()["decision"]=="deny"
def test_file_request_manual_import():
 a=c.post("/api/v1/agents/register",headers=H,json={"name":"requester"}).json(); v=c.post("/api/v1/vaults",headers=H,json={"name":"lab2"}).json(); r=c.post("/api/v1/file-requests",headers=H,json={"vault_id":v["id"],"agent_id":a["id"],"requested_name":"photo.png","reason":"needed"}).json(); d=c.post("/api/v1/file-requests/"+r["id"]+"/decision",headers=H,json={"approved":True}); assert d.json()["status"]=="approved_waiting_for_user_import"
def test_windows_path_normalization():
 assert safe_path("src\\main.py")=="src/main.py"
 assert safe_path("C:\\Users\\victim\\.ssh\\id_rsa") is None
 assert safe_path("../secrets.txt") is None
def test_audit_chain(): assert c.get("/api/v1/audit/verify",headers=H).json()["valid"] is True
