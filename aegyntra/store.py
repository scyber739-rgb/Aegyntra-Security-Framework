import hashlib,json,sqlite3,threading
from datetime import datetime,timezone
from pathlib import Path
from uuid import uuid4
def now(): return datetime.now(timezone.utc).isoformat()
class Store:
 def __init__(self,path:Path):
  path.parent.mkdir(parents=True,exist_ok=True); self.lock=threading.RLock(); self.db=sqlite3.connect(str(path),check_same_thread=False); self.db.row_factory=sqlite3.Row; self.db.execute("PRAGMA journal_mode=WAL"); self.schema()
 def schema(self):
  with self.lock,self.db:
   self.db.executescript("""CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY,name TEXT,kind TEXT,trust TEXT,created_at TEXT,last_seen TEXT); CREATE TABLE IF NOT EXISTS vaults(id TEXT PRIMARY KEY,name TEXT,mode TEXT,status TEXT,created_at TEXT); CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,vault_id TEXT,space TEXT,name TEXT,relative_path TEXT,size INTEGER,sha256 TEXT,classification TEXT,status TEXT,created_at TEXT); CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,vault_id TEXT,agent_id TEXT,name TEXT,reason TEXT,status TEXT,created_at TEXT); CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,time TEXT,agent_id TEXT,session_id TEXT,action TEXT,target TEXT,decision TEXT,reason TEXT,severity TEXT,source TEXT,details TEXT,prev_hash TEXT,event_hash TEXT); CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,name TEXT,effect TEXT,description TEXT); CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,event_id TEXT,title TEXT,severity TEXT,status TEXT,created_at TEXT);""")
   if not self.db.execute("SELECT 1 FROM policies").fetchone():
    for x in [("default-deny","Default deny","deny","Unknown actions are denied."),("vault-scope","Vault scope","deny","Actions stay within approved spaces."),("sensitive-files","Sensitive file guard","deny","Sensitive files require review."),("network-egress","Network egress","deny","OS/VM controls are required for actual egress enforcement.")]: self.db.execute("INSERT INTO policies VALUES(?,?,?,?)",x)
 def event(self,agent_id=None,session_id=None,action="event",target="[redacted]",decision="observe",reason="",severity="info",source="api",details=None):
  with self.lock,self.db:
   row=self.db.execute("SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1").fetchone(); prev=row[0] if row else "0"*64
   x={"id":str(uuid4()),"time":now(),"agent_id":agent_id,"session_id":session_id,"action":str(action)[:96],"target":str(target)[:512],"decision":str(decision)[:32],"reason":str(reason)[:500],"severity":str(severity)[:16],"source":str(source)[:48],"details":details or {},"prev_hash":prev}
   x["event_hash"]=hashlib.sha256((prev+json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)).encode()).hexdigest()
   self.db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(x["id"],x["time"],x["agent_id"],x["session_id"],x["action"],x["target"],x["decision"],x["reason"],x["severity"],x["source"],json.dumps(x["details"]),prev,x["event_hash"]))
   if severity in ("high","critical") or decision=="deny": self.db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?)",(str(uuid4()),x["id"],x["action"]+": "+(reason or decision),severity,"open",x["time"]))
   return x
 def unpack(self,r):
  x=dict(r); x["details"]=json.loads(x.pop("details")); return x
 def events(self,n=100):
  with self.lock:r=self.db.execute("SELECT * FROM events ORDER BY rowid DESC LIMIT ?",(min(500,max(1,n)),)).fetchall()
  return [self.unpack(x) for x in r]
 def overview(self):
  with self.lock:
   q=lambda s:self.db.execute(s).fetchone()[0]
   return {"events_total":q("SELECT COUNT(*) FROM events"),"blocked_actions":q("SELECT COUNT(*) FROM events WHERE decision='deny'"),"open_critical":q("SELECT COUNT(*) FROM incidents WHERE status='open' AND severity='critical'"),"open_high":q("SELECT COUNT(*) FROM incidents WHERE status='open' AND severity='high'"),"registered_agents":q("SELECT COUNT(*) FROM agents"),"active_vaults":q("SELECT COUNT(*) FROM vaults WHERE status='active'"),"pending_file_requests":q("SELECT COUNT(*) FROM requests WHERE status='pending'")}
 def incidents(self,n=100):
  with self.lock:r=self.db.execute("SELECT i.*,e.action,e.target,e.reason,e.agent_id,e.decision FROM incidents i JOIN events e ON e.id=i.event_id ORDER BY i.created_at DESC LIMIT ?",(min(500,max(1,n)),)).fetchall()
  return [dict(x) for x in r]
 def verify(self):
  with self.lock:r=self.db.execute("SELECT * FROM events ORDER BY rowid").fetchall()
  prev="0"*64
  for row in r:
   x=self.unpack(row)
   if x["prev_hash"]!=prev:return {"valid":False,"checked":len(r),"failed_event":x["id"]}
   item={k:x[k] for k in ("id","time","agent_id","session_id","action","target","decision","reason","severity","source","details","prev_hash")}; h=hashlib.sha256((prev+json.dumps(item,sort_keys=True,separators=(",",":"),ensure_ascii=False)).encode()).hexdigest()
   if h!=x["event_hash"]:return {"valid":False,"checked":len(r),"failed_event":x["id"]}
   prev=h
  return {"valid":True,"checked":len(r),"failed_event":None}
