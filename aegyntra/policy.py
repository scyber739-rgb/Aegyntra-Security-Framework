from pathlib import PurePosixPath
SENSITIVE={".env",".npmrc",".pypirc","id_rsa","id_ed25519","credentials.json","secrets.json","decoy_credentials.txt"}
EXECUTABLE={".exe",".dll",".com",".scr",".msi",".bat",".cmd",".ps1",".vbs",".js",".jse",".hta",".sh",".so",".dylib",".jar",".pyc"}
def classify(name):
 low=name.lower()
 if low in SENSITIVE or low.startswith(".env") or low.endswith((".pem",".key",".p12",".pfx")): return "sensitive"
 if PurePosixPath(low).suffix in EXECUTABLE: return "executable_or_script"
 return "normal"
def safe_path(value):
 value=value.replace("\\\\","/").strip(); p=PurePosixPath(value)
 if not value or p.is_absolute() or any(x in ("..","") for x in p.parts) or ":" in value or "\\x00" in value: return None
 if any(x.startswith(".") for x in p.parts): return None
 return str(p)
def evaluate(action,target,space="input"):
 rel=safe_path(target)
 if action in {"read_file","list_files","write_file","create_artifact"}:
  if rel is None: return {"decision":"deny","severity":"high","reason":"invalid, hidden, absolute or out-of-scope path"}
  c=classify(PurePosixPath(rel).name)
  if c=="sensitive": return {"decision":"deny","severity":"critical","reason":"sensitive filename requires separate review"}
  if action in {"write_file","create_artifact"} and space!="output": return {"decision":"deny","severity":"high","reason":"writes are allowed only in Vault output space"}
  if action in {"read_file","list_files"} and space not in {"input","output"}: return {"decision":"deny","severity":"high","reason":"resource space not granted"}
  if c=="executable_or_script" and action in {"write_file","create_artifact"}: return {"decision":"quarantine","severity":"high","reason":"script/executable requires quarantine and review"}
  return {"decision":"allow","severity":"info","reason":"within explicitly mediated Vault space"}
 if action in {"network_connect","http_request","upload_external"}: return {"decision":"deny","severity":"high","reason":"network egress is not granted by this control plane"}
 if action in {"exec","shell","execute_command","launch_process"}: return {"decision":"deny","severity":"critical","reason":"command execution is not implemented in this release"}
 return {"decision":"deny","severity":"high","reason":"unknown action denied by default"}
