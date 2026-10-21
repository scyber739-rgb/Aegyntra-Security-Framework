import hashlib,re
from pathlib import Path
from uuid import uuid4
from .policy import classify
from .store import now
BAD=re.compile(r"[^A-Za-z0-9._ -]+")
def clean(name):
 name=Path(name.replace("\\\\","/")).name; return BAD.sub("_",name).strip().rstrip(" .")[:180] or "unnamed-file"
class Service:
 def __init__(self,db,root,max_bytes): self.db=db; self.root=root; self.max_bytes=max_bytes; root.mkdir(parents=True,exist_ok=True)
 def agent(self,name,kind,trust):
  aid="agt_"+uuid4().hex[:16]; t=now()
  with self.db.lock,self.db.db:self.db.db.execute("INSERT INTO agents VALUES(?,?,?,?,?,?)",(aid,name[:100],kind[:64],trust,t,None))
  self.db.event(agent_id=aid,action="agent.register",target=name,reason="registered; runtime telemetry requires an adapter",source="control-plane")
  return {"id":aid,"name":name,"kind":kind,"trust":trust,"created_at":t}
 def agents(self):
  with self.db.lock:r=self.db.db.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
  return [dict(x) for x in r]
 def vault(self,name,mode):
  vid="vlt_"+uuid4().hex[:16]; t=now()
  for s in ("input","output","quarantine","evidence"):(self.root/vid/s).mkdir(parents=True,exist_ok=True)
  with self.db.lock,self.db.db:self.db.db.execute("INSERT INTO vaults VALUES(?,?,?,?,?)",(vid,name[:100],mode,"active",t))
  self.db.event(action="vault.created",target=vid,decision="allow",reason="Vault storage created; not a VM sandbox",source="control-plane")
  return {"id":vid,"name":name,"mode":mode,"status":"active","created_at":t}
 def vaults(self):
  with self.db.lock:r=self.db.db.execute("SELECT * FROM vaults ORDER BY created_at DESC").fetchall()
  return [{**dict(v),"files_count":self.db.db.execute("SELECT COUNT(*) FROM files WHERE vault_id=?",(v["id"],)).fetchone()[0]} for v in r]
 def check(self,vid):
  with self.db.lock:r=self.db.db.execute("SELECT * FROM vaults WHERE id=?",(vid,)).fetchone()
  if not r:raise KeyError("Vault not found")
  if r["status"]!="active":raise ValueError("Vault not active")
 def put(self,vid,filename,data,output=False):
  self.check(vid)
  if len(data)>self.max_bytes:raise ValueError("Upload too large")
  name=clean(filename); cls=classify(name)
  if cls=="sensitive" and not output:
   self.db.event(action="file.import",target=name,decision="deny",reason="sensitive-looking filename rejected",severity="critical",source="secure-spaces"); raise PermissionError("Sensitive-looking file rejected; use synthetic test data")
  fid="fil_"+uuid4().hex[:16]; quarantine=cls in {"sensitive","executable_or_script"}; space="quarantine" if quarantine else ("output" if output else "input"); rel=fid+"_"+name
  (self.root/vid/space/rel).write_bytes(data); sha=hashlib.sha256(data).hexdigest(); status="quarantined" if quarantine else ("review_required" if output else "available")
  with self.db.lock,self.db.db:self.db.db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)",(fid,vid,space,name,rel,len(data),sha,cls,status,now()))
  self.db.event(action="artifact.created" if output else "file.import",target=name,decision="quarantine" if quarantine else ("review" if output else "allow"),reason="stored in Vault; never auto-executed",severity="high" if quarantine else "info",source="vault-storage",details={"vault_id":vid,"sha256":sha,"size":len(data)})
  return {"id":fid,"vault_id":vid,"name":name,"space":space,"size":len(data),"sha256":sha,"classification":cls,"status":status}
 def files(self,vid):
  self.check(vid)
  with self.db.lock:r=self.db.db.execute("SELECT id,vault_id,space,name,size,sha256,classification,status,created_at FROM files WHERE vault_id=? ORDER BY created_at DESC",(vid,)).fetchall()
  return [dict(x) for x in r]
 def request(self,vid,aid,name,reason):
  self.check(vid)
  with self.db.lock:a=self.db.db.execute("SELECT id FROM agents WHERE id=?",(aid,)).fetchone()
  if not a:raise KeyError("Unknown agent")
  rid="req_"+uuid4().hex[:16]; t=now()
  with self.db.lock,self.db.db:self.db.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?)",(rid,vid,aid,clean(name),reason[:500],"pending",t))
  self.db.event(agent_id=aid,action="file.request",target=clean(name),decision="approval_required",reason="user must manually select and import file",severity="medium",source="secure-spaces",details={"request_id":rid,"vault_id":vid})
  return {"id":rid,"vault_id":vid,"agent_id":aid,"requested_name":clean(name),"reason":reason[:500],"status":"pending","created_at":t}
 def requests(self):
  with self.db.lock:r=self.db.db.execute("SELECT * FROM requests ORDER BY created_at DESC LIMIT 200").fetchall()
  return [dict(x) for x in r]
 def decide(self,rid,approved):
  with self.db.lock,self.db.db:
   r=self.db.db.execute("SELECT * FROM requests WHERE id=?",(rid,)).fetchone()
   if not r:raise KeyError("Request not found")
   status="approved_waiting_for_user_import" if approved else "denied"; self.db.db.execute("UPDATE requests SET status=? WHERE id=?",(status,rid))
  self.db.event(agent_id=r["agent_id"],action="file.request.decision",target=r["name"],decision="approval_required" if approved else "deny",reason="manual import still required" if approved else "user denied request",severity="info" if approved else "medium",source="secure-spaces")
  return {"id":rid,"status":status}
