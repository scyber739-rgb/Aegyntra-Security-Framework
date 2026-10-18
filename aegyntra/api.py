"""Loopback-only demonstration API. Do not expose to untrusted networks."""
import os
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel, Field
from .engine import Engine

app = FastAPI(title="Aegyntra Security Gateway", version="0.1.0")
workspace = Path(os.environ.get("AEGYNTRA_WORKSPACE", "./demo_workspace"))
workspace.mkdir(parents=True, exist_ok=True)
engine = Engine(workspace, Path(os.environ.get("AEGYNTRA_DB", "./aegyntra_events.sqlite3")))

class Action(BaseModel):
    action: str = Field(max_length=64)
    target: str = Field(max_length=2048)

@app.get("/health")
def health():
    return {"status": "ok", "mode": "simulation"}

@app.post("/evaluate")
def evaluate(request: Action):
    return engine.evaluate(request.action, request.target)

@app.get("/events")
def events():
    return engine.events()
