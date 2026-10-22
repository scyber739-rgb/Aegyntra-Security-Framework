import hmac
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
def auth(x_aegyntra_token:str|None=Header(default=None)):
 if not x_aegyntra_token or not hmac.compare_digest(x_aegyntra_token,API_TOKEN):raise HTTPException(401,"Unauthorized")
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
  "runtime":{"state":"not_provisioned","isolated":False,"agent_running":False,"verified":False,
  "message":"Storage only. No VM/container or agent runtime is provisioned by this release."},
  "agent_ids_from_file_requests":list(sorted(set(r["agent_id"] for r in requests)))}

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
