"""
MCP Shield - Runtime Security Gateway for AI Tools
One server: serves the dashboard (frontend) AND the policy API (backend).

Run:  uvicorn main:app --reload --port 8000
Open: http://localhost:8000
"""
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).parent.resolve()
SANDBOX = (BASE_DIR / "sandbox_docs").resolve()
STATIC = BASE_DIR / "static"
AUDIT_FILE = BASE_DIR / "audit_log.jsonl"

# ---------------------------------------------------------------- POLICY ----
POLICY = {
    "allowed_tools": ["read_file", "list_docs"],       # deny-by-default
    "allowed_extensions": [".txt", ".md"],
    "sensitive_names": [
        ".env", "id_rsa", "id_ed25519", "passwd", "shadow", "credentials",
        "secrets", ".git", ".ssh", "config.json", "token", "authorized_keys",
    ],
    "max_path_length": 200,
}


class ToolRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any] = {}
    agent: Optional[str] = "demo-agent"


# ------------------------------------------------------------ SECURITY ENGINE
def check_path(raw: Any) -> List[str]:
    """Return a list of violations for a requested file path (empty = safe)."""
    if not isinstance(raw, str) or not raw.strip():
        return ["Path is missing or not a string"]
    problems: List[str] = []

    # Decode repeatedly so %2e%2e%2f and double-encoding can't sneak through.
    decoded = raw
    for _ in range(3):
        new = unquote(decoded)
        if new == decoded:
            break
        decoded = new

    if "\x00" in decoded:
        problems.append("Null byte injection in path")
    if len(decoded) > POLICY["max_path_length"]:
        problems.append("Path too long")

    norm = decoded.replace("\\", "/")
    parts = [p for p in norm.split("/") if p not in ("", ".")]

    if norm.startswith("/") or (len(norm) > 1 and norm[1] == ":"):
        problems.append("Absolute path not allowed (restricted system path)")
    if ".." in parts:
        problems.append("Directory traversal ('..') detected")
    if norm.startswith("~"):
        problems.append("Home-directory expansion not allowed")

    lowered = [p.lower() for p in parts]
    for bad in POLICY["sensitive_names"]:
        if any(bad == p or p.startswith(bad) for p in lowered):
            problems.append(f"Sensitive file/directory blocked: '{bad}'")
            break

    if parts:
        ext = Path(parts[-1]).suffix.lower()
        if ext not in POLICY["allowed_extensions"]:
            problems.append(f"File type '{ext or 'none'}' not in allowlist")

    # Final containment check: resolved path must stay inside the sandbox.
    if not problems:
        try:
            target = (SANDBOX / norm).resolve()
            target.relative_to(SANDBOX)
        except (ValueError, OSError):
            problems.append("Resolved path escapes the sandbox directory")
    return problems


def evaluate(req: ToolRequest) -> Dict[str, Any]:
    reasons: List[str] = []
    if req.tool not in POLICY["allowed_tools"]:
        reasons.append(f"Tool '{req.tool}' is not on the approved list (deny by default)")
    elif req.tool == "read_file":
        reasons += check_path(req.arguments.get("path"))
    elif req.tool == "list_docs":
        extra = set(req.arguments) - set()
        if extra:
            reasons.append(f"Unexpected arguments: {sorted(extra)}")
    allowed = not reasons
    return {"allowed": allowed, "reasons": reasons or ["Request satisfies all policy rules"]}


def execute_tool(req: ToolRequest) -> Dict[str, Any]:
    """Only reached AFTER the policy allows the request."""
    if req.tool == "list_docs":
        return {"files": sorted(p.name for p in SANDBOX.glob("*") if p.is_file())}
    path = (SANDBOX / req.arguments["path"].replace("\\", "/")).resolve()
    if not path.is_file():
        return {"error": "File not found in sandbox"}
    return {"content": path.read_text(encoding="utf-8", errors="replace")[:2000]}


# ------------------------------------------------------------------ AUDIT ---
AUDIT: List[Dict[str, Any]] = []


def record(entry: Dict[str, Any]) -> None:
    AUDIT.append(entry)
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# -------------------------------------------------------------------- APP ---
app = FastAPI(title="MCP Shield")


@app.post("/api/request")
def handle_request(req: ToolRequest):
    started = time.perf_counter()
    verdict = evaluate(req)
    result = execute_tool(req) if verdict["allowed"] else None
    entry = {
        "id": uuid.uuid4().hex[:8],
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "agent": req.agent,
        "tool": req.tool,
        "arguments": req.arguments,
        "decision": "ALLOWED" if verdict["allowed"] else "BLOCKED",
        "reasons": verdict["reasons"],
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    record(entry)
    return {**entry, "result": result}


@app.get("/api/logs")
def logs():
    return list(reversed(AUDIT))[:200]


@app.get("/api/stats")
def stats():
    total = len(AUDIT)
    blocked = sum(1 for e in AUDIT if e["decision"] == "BLOCKED")
    return {"total": total, "allowed": total - blocked, "blocked": blocked}


@app.get("/api/policy")
def policy():
    return POLICY


@app.post("/api/reset")
def reset():
    AUDIT.clear()
    AUDIT_FILE.write_text("", encoding="utf-8")
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
