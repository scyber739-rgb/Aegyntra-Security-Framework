"""Aegyntra platform API and dashboard server. Keep bound to loopback in the lab."""
from __future__ import annotations
import hmac, os
from pathlib import Path
from typing import Optional
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .agent_runtime import AgentConfigurationError, AgentRunner
from .engine import Engine
ROOT=Path(__file__).resolve().parent.parent
WORKSPACE=Path(os.getenv("AEGYNTRA_WORKSPACE",str(ROOT/"demo_workspace"))).resolve(); WORKSPACE.mkdir(parents=True,exist_ok=True)
DB_PATH=Path(os.getenv("AEGYNTRA_DB",str(ROOT/"aegyntra_events.sqlite3")))
engine=Engine(WORKSPACE,DB_PATH); runner=AgentRunner(engine,WORKSPACE)
app=FastAPI(title="Aegyntra Agent Security Platform",version="0.2.0",docs_url=None,redoc_url=None,openapi_url=None)
app.mount("/assets",StaticFiles(directory=str(ROOT/"dashboard")),name="assets")
class EvaluateRequest(BaseModel):
 action:str=Field(min_length=1,max_length=64); target:str=Field(min_length=1,max_length=2048)
class AgentRunRequest(BaseModel):
 prompt:str=Field(min_length=1,max_length=12000); model:Optional[str]=Field(default=None,max_length=128); max_steps:int=Field(default=4,ge=1,le=6)
def authorize(x_aegyntra_token:str|None=Header(default=None)):
 expected=os.getenv("AEGYNTRA_API_TOKEN")
 if expected and (not x_aegyntra_token or not hmac.compare_digest(x_aegyntra_token,expected)): raise HTTPException(status_code=401,detail="Unauthorized")
 return True
@app.get("/")
def dashboard(): return FileResponse(ROOT/"dashboard"/"index.html")
@app.get("/health")
def health(): return {"status":"ok","version":"0.2.0","mode":"mediated-agent-evaluation"}
@app.get("/api/overview",dependencies=[Depends(authorize)])
def overview():
 events=engine.events(limit=500); total=len(events); denied=sum(not e["allowed"] for e in events); critical=sum(e["severity"]=="critical" for e in events)
 return {"status":"operational","version":"0.2.0","total_events":total,"denied_events":denied,"critical_events":critical,"allow_rate":round((total-denied)/total*100,1) if total else 0.0,"events":events[:12]}
@app.get("/api/events",dependencies=[Depends(authorize)])
def events(limit:int=100):
 if limit<1 or limit>500: raise HTTPException(status_code=422,detail="limit must be between 1 and 500")
 return {"events":engine.events(limit=limit)}
@app.post("/api/evaluate",dependencies=[Depends(authorize)])
def evaluate(request:EvaluateRequest): return engine.evaluate(request.action,request.target)
@app.post("/api/agent/run",dependencies=[Depends(authorize)])
def run_agent(request:AgentRunRequest):
 try: return runner.run(request.prompt,request.model,request.max_steps)
 except AgentConfigurationError as exc: raise HTTPException(status_code=503,detail=str(exc)) from exc
 except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc
 except Exception as exc: raise HTTPException(status_code=502,detail=f"Agent provider request failed ({type(exc).__name__})") from exc
