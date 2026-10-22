import hmac,hashlib,secrets
from datetime import datetime,timezone,timedelta
from typing import Literal
from fastapi import Depends,FastAPI,File,Header,HTTPException,Query,UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from .config import API_TOKEN,APP_ROOT,VAULT_ROOT,DB_PATH,MAX_UPLOAD_BYTES
from .policy import evaluate
from .store import Store
from .service import Service
if not API_TOKEN:raise RuntimeError("AEGYNTRA_API_TOKEN is required. Set it in .env before startup.")
db=Store(DB_PATH); svc=Service(db,VAULT_ROOT,MAX_UPLOAD_BYTES)
app=FastAPI(title="Aegyntra AI Agent Security Platform",version="1.0.0",docs_url=None,redoc_url=None,openapi_url=None); app.mount("/assets",StaticFiles(directory=str(APP_ROOT/"dashboard")),name="assets")
class AgentIn(BaseModel): name:str=Field(min_length=1,max_length=100); kind:str=Field(default="external-log-adapter",max_length=64); trust:Literal["untrusted","restricted","trusted"]="untrusted"
class VaultIn(BaseModel): name:str=Field(min_length=1,max_length=100); mode:Literal["testing","protected","quarantine"]="testing"
class EvalIn(BaseModel): agent_id:str|None=None; session_id:str|None=None; action:str=Field(min_length=1,max_length=96); target:str=Field(min_length=1,max_length=512); space:Literal["input","output","quarantine","evidence"]="input"
class EventIn(BaseModel): agent_id:str=Field(min_length=1,max_length=64); session_id:str|None=None; action:str=Field(min_length=1,max_length=96); target:str=Field(default="[redacted]",max_length=512); decision:str=Field(default="observe",max_length=32); reason:str=Field(default="",max_length=500); severity:Literal["info","low","medium","high","critical"]="info"; source:str=Field(default="agent-adapter",max_length=48); details:dict=Field(default_factory=dict)
class RequestIn(BaseModel): vault_id:str; agent_id:str; requested_name:str; reason:str
class DecisionIn(BaseModel): approved:bool
class RuntimeCodeIn(BaseModel): agent_id:str
class PairIn(BaseModel): code:str=Field(min_length=16,max_length=256)
class RuntimeEventIn(BaseModel): action:str=Field(min_length=1,max_length=96); target:str=Field(default="[redacted]",max_length=512); decision:str=Field(default="observe",max_length=32); reason:str=Field(default="",max_length=500); severity:Literal["info","low","medium","high","critical"]="info"; details:dict=Field(default_factory=dict)
class RuntimeEvalIn(BaseModel): action:str=Field(min_length=1,max_length=96); target:str=Field(min_length=1,max_length=512); space:Literal["input","output","quarantine","evidence"]="input"
def auth(x_aegyntra_token:str|None=Header(default=None)):
 if not x_aegyntra_token or not hmac.compare_digest(x_aegyntra_token,API_TOKEN):raise HTTPException(401,"Unauthorized")
def token_hash(value:str)->str:return hashlib.sha256(value.encode()).hexdigest()
def runtime_auth(x_aegyntra_runtime_token:str|None=Header(default=None)):
 if not x_aegyntra_runtime_token:raise HTTPException(401,"Runtime token required")
 with db.lock:r=db.db.execute("SELECT * FROM runtime_tokens WHERE token_hash=? AND revoked_at IS NULL",(token_hash(x_aegyntra_runtime_token),)).fetchone()
 if not r:raise HTTPException(401,"Invalid or revoked runtime token")
 return dict(r)
def fail(e):
 if isinstance(e,KeyError):raise HTTPException(404,str(e).strip("'"))
 if isinstance(e,PermissionError):raise HTTPException(403,str(e))
 if isinstance(e,ValueError):raise HTTPException(400,str(e))
 raise e
@app.get("/")
def home():return FileResponse(APP_ROOT/"dashboard"/"index.html")
@app.get("/health")
def health():return {"status":"ok","version":"1.0.0","auth_required":True}
@app.get("/api/v1/overview",dependencies=[Depends(auth)])
def overview():return {**db.overview(),"audit_chain":db.verify(),"coverage":{"gateway":"routed actions only","endpoint_sensor":"adapter required","host_firewall":"not included","vault":"storage only; use VM for untrusted execution"}}
@app.get("/api/v1/agents",dependencies=[Depends(auth)])
def agents():return svc.agents()
@app.post("/api/v1/agents/register",dependencies=[Depends(auth)])
def register(x:AgentIn):return svc.agent(x.name,x.kind,x.trust)
@app.get("/api/v1/vaults",dependencies=[Depends(auth)])
def vaults():return svc.vaults()
@app.post("/api/v1/vaults",dependencies=[Depends(auth)])
def create_vault(x:VaultIn):return svc.vault(x.name,x.mode)

@app.get("/api/v1/vaults/{vid}/visibility",dependencies=[Depends(auth)])
def vault_visibility(vid:str):
 try:svc.check(vid)
 except Exception as e:fail(e)
 with db.lock:
  vault=dict(db.db.execute("SELECT * FROM vaults WHERE id=?",(vid,)).fetchone())
  files=[dict(x) for x in db.db.execute("SELECT id,name,space,status,size FROM files WHERE vault_id=? ORDER BY created_at DESC LIMIT 100",(vid,)).fetchall()]
  requests=[dict(x) for x in db.db.execute("SELECT id,agent_id,name,status,created_at FROM requests WHERE vault_id=? ORDER BY created_at DESC LIMIT 100",(vid,)).fetchall()]
  events=[]
  for row in db.db.execute("SELECT * FROM events ORDER BY rowid DESC LIMIT 500").fetchall():
   x=db.unpack(row)
   if x["details"].get("vault_id")==vid or (x["action"]=="vault.created" and x["target"]==vid):
    events.append({k:x[k] for k in ("id","time","agent_id","action","target","decision","reason","severity","source")})
 return {"vault":vault,"files":files,"requests":requests,"events":events[:100],
  "runtime":runtime_status(vid),
  "agent_ids_from_file_requests":list(sorted(set(r["agent_id"] for r in requests)))}

@app.post("/api/v1/vaults/{vid}/access-codes",dependencies=[Depends(auth)])
def create_vault_access_code(vid:str,x:RuntimeCodeIn):
 try:svc.check(vid)
 except Exception as e:fail(e)
 with db.lock:a=db.db.execute("SELECT id FROM agents WHERE id=?",(x.agent_id,)).fetchone()
 if not a:raise HTTPException(404,"Register the agent first")
 code=secrets.token_urlsafe(32); expires=(datetime.now(timezone.utc)+timedelta(minutes=15)).isoformat()
 with db.lock,db.db:
  db.db.execute("DELETE FROM runtime_codes WHERE expires_at < ?",(datetime.now(timezone.utc).isoformat(),))
  db.db.execute("INSERT INTO runtime_codes VALUES(?,?,?,?,?,?)",(token_hash(code),vid,x.agent_id,expires,None,datetime.now(timezone.utc).isoformat()))
 db.event(agent_id=x.agent_id,action="vault.access_code.created",target=vid,decision="allow",reason="single-use pairing code created; expires in 15 minutes",severity="medium",source="runtime-control",details={"vault_id":vid})
 return {"vault_id":vid,"agent_id":x.agent_id,"access_code":code,"expires_at":expires,"single_use":True}
@app.post("/api/v1/runtime/pair")
def runtime_pair(x:PairIn):
 with db.lock:
  row=db.db.execute("SELECT * FROM runtime_codes WHERE code_hash=?",(token_hash(x.code),)).fetchone()
 if not row:raise HTTPException(401,"Invalid, expired, or already-used access code")
 if row["used_at"] or row["expires_at"] < datetime.now(timezone.utc).isoformat():raise HTTPException(401,"Invalid, expired, or already-used access code")
 runtime_token=secrets.token_urlsafe(40); t=datetime.now(timezone.utc).isoformat()
 with db.lock,db.db:
  cur=db.db.execute("UPDATE runtime_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at >= ?",(t,row["code_hash"],t))
  if cur.rowcount != 1:raise HTTPException(401,"Access code was already used or expired")
  db.db.execute("INSERT INTO runtime_tokens VALUES(?,?,?,?,?)",(token_hash(runtime_token),row["vault_id"],row["agent_id"],t,None))
  db.db.execute("INSERT INTO vault_runtime VALUES(?,?,?,?,?,?) ON CONFLICT(vault_id) DO UPDATE SET agent_id=excluded.agent_id,state='paired',container_name=excluded.container_name,last_heartbeat=excluded.last_heartbeat,updated_at=excluded.updated_at",(row["vault_id"],row["agent_id"],"paired","agent-runtime",t,t))
 db.event(agent_id=row["agent_id"],action="vault.agent.paired",target=row["vault_id"],decision="allow",reason="runtime paired using single-use code",source="runtime-control",details={"vault_id":row["vault_id"]})
 return {"runtime_token":runtime_token,"vault_id":row["vault_id"],"agent_id":row["agent_id"],"api_base":"/api/v1/runtime"}
@app.post("/api/v1/runtime/heartbeat")
def runtime_heartbeat(x:RuntimeEventIn,rt=Depends(runtime_auth)):
 t=datetime.now(timezone.utc).isoformat()
 with db.lock,db.db:db.db.execute("UPDATE vault_runtime SET state='running',last_heartbeat=?,updated_at=? WHERE vault_id=?",(t,t,rt["vault_id"]))
 db.event(agent_id=rt["agent_id"],action="runtime.heartbeat",target=rt["vault_id"],decision="allow",reason="agent runtime heartbeat",source="runtime-agent",details={"vault_id":rt["vault_id"]})
 return {"ok":True,"state":"running","time":t}
@app.post("/api/v1/runtime/evaluate")
def runtime_evaluate(x:RuntimeEvalIn,rt=Depends(runtime_auth)):
 d=evaluate(x.action,x.target,x.space)
 db.event(agent_id=rt["agent_id"],action=x.action,target=x.target,decision=d["decision"],reason=d["reason"],severity=d["severity"],source="runtime-policy",details={"vault_id":rt["vault_id"],"space":x.space,"enforcement":"decision-only; actual operations must use the mediated runner"})
 return d
@app.post("/api/v1/runtime/events")
def runtime_event(x:RuntimeEventIn,rt=Depends(runtime_auth)):
 details=dict(x.details); details["vault_id"]=rt["vault_id"]
 e=db.event(agent_id=rt["agent_id"],action=x.action,target=x.target,decision=x.decision,reason=x.reason,severity=x.severity,source="runtime-agent",details=details)
 return {"accepted":True,"event_id":e["id"]}
@app.get("/api/v1/runtime/status/{vid}",dependencies=[Depends(auth)])
def runtime_status(vid:str):
 try:svc.check(vid)
 except Exception as e:fail(e)
 with db.lock:r=db.db.execute("SELECT * FROM vault_runtime WHERE vault_id=?",(vid,)).fetchone()
 if not r:return {"vault_id":vid,"state":"not_paired","agent_running":False,"isolated":False,"verified":False}
 heartbeat=r["last_heartbeat"]; fresh=False
 if heartbeat:
  try:fresh=datetime.now(timezone.utc)-datetime.fromisoformat(heartbeat)<timedelta(seconds=60)
  except ValueError:pass
 return {"vault_id":vid,"agent_id":r["agent_id"],"state":"running" if fresh else "stale","agent_running":fresh,"isolated":False,"verified":False,"container_name":r["container_name"],"last_heartbeat":heartbeat,"message":"Agent heartbeat observed. Container isolation is not verified by this control plane."}
@app.get("/api/v1/vaults/{vid}/files",dependencies=[Depends(auth)])
def files(vid:str):
 try:return svc.files(vid)
 except Exception as e:fail(e)
async def limited(f):
 b=await f.read(MAX_UPLOAD_BYTES+1)
 if len(b)>MAX_UPLOAD_BYTES:raise HTTPException(413,"Upload too large")
 if not b:raise HTTPException(400,"Empty file")
 return b
@app.post("/api/v1/vaults/{vid}/import",dependencies=[Depends(auth)])
async def import_file(vid:str,file:UploadFile=File(...)):
 try:return svc.put(vid,file.filename or "upload.bin",await limited(file))
 except Exception as e:fail(e)
@app.post("/api/v1/vaults/{vid}/outputs",dependencies=[Depends(auth)])
async def output_file(vid:str,file:UploadFile=File(...)):
 try:return svc.put(vid,file.filename or "artifact.bin",await limited(file),True)
 except Exception as e:fail(e)
@app.get("/api/v1/vaults/{vid}/export/{fid}",dependencies=[Depends(auth)])
def export(vid:str,fid:str,confirm:bool=Query(default=False)):
 if not confirm:raise HTTPException(400,"Explicit confirm=true required")
 try:svc.check(vid)
 except Exception as e:fail(e)
 with db.lock:r=db.db.execute("SELECT * FROM files WHERE id=? AND vault_id=?",(fid,vid)).fetchone()
 if not r:raise HTTPException(404,"File not found")
 if r["status"]=="quarantined" or r["classification"]!="normal":raise HTTPException(403,"Quarantined artifact cannot be exported")
 p=(VAULT_ROOT/vid/r["space"]/r["relative_path"]).resolve()
 try:p.relative_to((VAULT_ROOT/vid).resolve())
 except ValueError:raise HTTPException(403,"Invalid path")
 if not p.is_file():raise HTTPException(404,"File missing")
 db.event(action="file.export",target=r["name"],decision="allow",reason="explicit user export",severity="medium",source="secure-spaces")
 return FileResponse(p,filename=r["name"],media_type="application/octet-stream")
@app.get("/api/v1/file-requests",dependencies=[Depends(auth)])
def requests():return svc.requests()
@app.post("/api/v1/file-requests",dependencies=[Depends(auth)])
def request_file(x:RequestIn):
 try:return svc.request(x.vault_id,x.agent_id,x.requested_name,x.reason)
 except Exception as e:fail(e)
@app.post("/api/v1/file-requests/{rid}/decision",dependencies=[Depends(auth)])
def decision(rid:str,x:DecisionIn):
 try:return svc.decide(rid,x.approved)
 except Exception as e:fail(e)
@app.post("/api/v1/actions/evaluate",dependencies=[Depends(auth)])
def eval_action(x:EvalIn):
 d=evaluate(x.action,x.target,x.space); db.event(agent_id=x.agent_id,session_id=x.session_id,action=x.action,target=x.target,decision=d["decision"],reason=d["reason"],severity=d["severity"],source="policy-engine",details={"space":x.space}); return d
@app.post("/api/v1/events/ingest",dependencies=[Depends(auth)])
def ingest(x:EventIn):
 with db.lock:a=db.db.execute("SELECT id FROM agents WHERE id=?",(x.agent_id,)).fetchone()
 if not a:raise HTTPException(403,"Unknown agent; register it first")
 safe={}
 for k,v in list(x.details.items())[:20]:
  k=str(k)[:64]
  if any(t in k.lower() for t in ("secret","password","token","credential","content","prompt")):safe[k]="[redacted]"
  elif isinstance(v,(str,int,float,bool)) or v is None:safe[k]=str(v)[:256] if isinstance(v,str) else v
  else:safe[k]="[structured value omitted]"
 e=db.event(agent_id=x.agent_id,session_id=x.session_id,action=x.action,target=x.target,decision=x.decision,reason=x.reason,severity=x.severity,source=x.source,details=safe)
 with db.lock,db.db:db.db.execute("UPDATE agents SET last_seen=? WHERE id=?",(e["time"],x.agent_id))
 return {"accepted":True,"event_id":e["id"],"event_hash":e["event_hash"]}
@app.get("/api/v1/events",dependencies=[Depends(auth)])
def events(limit:int=Query(default=100,ge=1,le=500)):return db.events(limit)
@app.get("/api/v1/incidents",dependencies=[Depends(auth)])
def incidents(limit:int=Query(default=100,ge=1,le=500)):return db.incidents(limit)
@app.get("/api/v1/policies",dependencies=[Depends(auth)])
def policies():
 with db.lock:r=db.db.execute("SELECT * FROM policies ORDER BY id").fetchall()
 return [dict(x) for x in r]
@app.get("/api/v1/audit/verify",dependencies=[Depends(auth)])
def audit_verify():return db.verify()
