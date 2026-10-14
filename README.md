# MCP Shield - Runtime Security Gateway for AI Tools

One folder, one server: the FastAPI backend also serves the dashboard.

## Run in VS Code
1. Install Python 3.10+ and open this folder in VS Code (File > Open Folder).
2. Open the terminal (Ctrl + `) and run:

   ```
   python -m venv venv
   venv\Scripts\activate        # Windows   (Mac/Linux: source venv/bin/activate)
   pip install -r requirements.txt
   uvicorn main:app --reload --port 8000
   ```
3. Open http://localhost:8000

## Folder layout
- `main.py` - backend: policy, security engine, audit log, API
- `static/index.html` - frontend dashboard
- `sandbox_docs/` - the only folder the agent may read from
- `audit_log.jsonl` - created automatically; every decision is saved here

## How it works
Intercept -> Inspect -> Decide -> Record. Every tool call goes to `POST /api/request`.
The tool only executes if the policy allows it.

Policy checks: tool allowlist (deny by default), directory traversal, URL-encoded
traversal, absolute paths, null bytes, sensitive filenames, file-type allowlist,
and a final sandbox-containment check.

## Be honest with the judges
This is a working policy-enforcement prototype. The tools (`read_file`, `list_docs`)
are simulated inside a sandbox folder. It is not yet plugged into a real MCP server,
and it does not stop every attack (e.g. prompt injection inside file contents).
Next step: put it in front of a real MCP server as a proxy.

## Deploy to a clean URL (no "replit")
Push this folder to GitHub, then on Render.com create a Web Service:
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
