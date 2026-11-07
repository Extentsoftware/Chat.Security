"""FastAPI web app: login, chat (SSE), tool console, scout data, security views and /mcp."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import logging
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import agent, catalog, db, mcp_server, remote_mcp, tools  # noqa: F401  (tools registers every tool)
from .config import settings
from .executor import RunState, invoke
from .security import AuthError, Perm, Principal, decode_token, impersonate, login, log_event, revoke

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
STATIC = Path(__file__).parent / "static"

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Connect to the allow-listed remote MCP servers and register only their pinned tools.
    await asyncio.to_thread(remote_mcp.load)
    yield


app = FastAPI(title="Bongo AI demo", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

CSP = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
       "style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https://tile.openstreetmap.org https://server.arcgisonline.com "
       "https://unpkg.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if request.url.path.startswith("/api") or request.url.path == "/mcp":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(AuthError)
async def auth_error(_: Request, exc: AuthError):
    headers = {"WWW-Authenticate": 'Bearer error="invalid_token"'} if exc.status == 401 else None
    return JSONResponse({"error": str(exc)}, status_code=exc.status, headers=headers)


# --- simple sliding-window rate limiter ---------------------------------------------------------

_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def rate_limit(key: str, limit: int, window: float = 60.0) -> None:
    now = time.monotonic()
    with _hits_lock:
        q = _hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(429, "Too many requests, slow down.")
        q.append(now)


# --- auth dependencies --------------------------------------------------------------------------

def current_principal(request: Request) -> Principal:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        raise AuthError("Missing bearer token")
    return decode_token(header[7:].strip())


def require(perm: str):
    def check(p: Principal = Depends(current_principal)) -> Principal:
        if not p.has(perm):
            raise AuthError(f"Forbidden: needs permission {perm}", 403)
        return p
    return check


# --- pages ------------------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


# --- auth ---------------------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(default="", max_length=100)
    password: str = Field(default="", max_length=200)


@app.post("/api/auth/login")
def api_login(body: LoginRequest, request: Request):
    ip = request.client.host if request.client else None
    rate_limit(f"login:{ip}", 20)
    return login(body.username, body.password, ip)


@app.get("/api/auth/version")
def api_version():
    return {"major": 1, "minor": 0, "released": "2026-11-07", "flavour": "python-demo"}


@app.post("/api/auth/logout")
def api_logout(p: Principal = Depends(current_principal)):
    revoke(p)
    return {"ok": True}


class ImpersonateRequest(BaseModel):
    userId: str


@app.post("/api/auth/impersonate")
def api_impersonate(body: ImpersonateRequest, p: Principal = Depends(current_principal)):
    return impersonate(p, body.userId)


@app.get("/api/users")
def api_users(p: Principal = Depends(require(Perm.IMPERSONATE))):
    return db.rows("""SELECT u.id, u.username, u.given_name || ' ' || coalesce(u.family_name,'') AS name, r.rolename,
                             t.name AS tenant, u.is_locked AS locked, u.is_disabled AS disabled
                      FROM users u JOIN roles r ON r.id = u.role_id JOIN tenants t ON t.id = u.tenant_id
                      WHERE t.company_id = ? ORDER BY t.name, r.rolename""", (p.company_id,))


@app.get("/api/me")
def api_me(p: Principal = Depends(current_principal)):
    tenant = db.row("SELECT name, latitude, longitude FROM tenants WHERE id = ?", (p.tenant_id,))
    meta = {r["key"]: r["value"] for r in db.rows("SELECT key, value FROM demo_meta")}
    return {"claims": p.claims_for_display(), "displayName": p.display_name, "tenant": tenant,
            "permissions": p.permissions, "canChat": p.has(Perm.VIEW_AI),
            "templates": [{"id": t.id, "name": t.name, "opening": t.opening} for t in agent.TEMPLATES.values()],
            "provider": settings.provider(),
            "model": settings.model_label(),
            "dataSource": meta.get("data_source")}


# --- tools / console ---------------------------------------------------------------------------

@app.get("/api/tools")
def api_tools(template: str | None = None, p: Principal = Depends(current_principal)):
    tmpl = agent.TEMPLATES.get(template or "general")
    out = {}
    for ch in ("chat", "mcp"):
        out[ch] = [{"name": a.tool.name, "plugin": a.tool.plugin, "description": a.tool.description,
                    "allowed": a.allowed, "reason": a.reason, "mutating": catalog.is_mutating(a.tool.name),
                    "gated": a.tool.name in catalog.GATED, "schema": a.tool.input_schema()}
                   for a in catalog.explain(p, tmpl.tools if tmpl else None, ch)]
    calendar = Principal.calendar_runner(p.tenant_id)
    out["calendar"] = [a.tool.name for a in catalog.explain(calendar, agent.TEMPLATES["pest-spray-planner"].tools) if a.allowed]
    return out


class InvokeRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)
    userMessage: str = Field(default="", max_length=500)


@app.post("/api/tools/{name}/invoke")
def api_invoke(name: str, body: InvokeRequest, p: Principal = Depends(require(Perm.VIEW_AI))):
    """Tool Console: call one tool directly, through exactly the same executor the model uses."""
    rate_limit(f"console:{p.jti}", 60)
    conv = db.row("SELECT id FROM chat_conversations WHERE user_id = ? AND tenant_id = ? AND template_id = 'tool-console'",
                  (p.user_id, p.tenant_id))
    cid = conv["id"] if conv else agent.create_conversation(p, "tool-console", "Tool console")
    events: list[dict] = []
    state = RunState(principal=p, channel="console", conversation_id=cid, user_prompt=body.userMessage,
                     max_calls=1, emit=events.append)
    outcome = invoke(state, name, body.arguments)
    try:
        parsed = json.loads(outcome.content)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    return {"outcome": outcome.outcome, "content": outcome.content, "json": parsed, "events": events}


# --- chat ------------------------------------------------------------------------------------------

class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=8000)
    conversationId: str | None = None
    template: str | None = None


@app.post("/api/chat")
async def api_chat(body: ChatRequest, p: Principal = Depends(require(Perm.VIEW_AI))):
    rate_limit(f"chat:{p.user_id}", 20)
    if body.conversationId and agent.load_conversation(p, body.conversationId) is None:
        raise HTTPException(404, "Conversation not found")
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def emit(event: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def worker() -> None:
        try:
            agent.chat(p, body.prompt, body.conversationId, body.template, emit)
        except Exception as exc:  # surface provider errors to the UI without a stack trace
            logging.getLogger("bongo_ai").exception("chat failed")
            emit({"type": "error", "message": f"{type(exc).__name__}: {str(exc)[:300]}"})
        finally:
            emit({"type": "done"})

    threading.Thread(target=worker, daemon=True).start()

    async def stream():
        while True:
            event = await queue.get()
            yield f"data: {json.dumps(event, default=str)}\n\n"
            if event.get("type") == "done":
                break

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


@app.get("/api/conversations")
def api_conversations(p: Principal = Depends(current_principal)):
    return db.rows("""SELECT id, title, template_id AS template, updated_at AS updated FROM chat_conversations
                      WHERE user_id = ? AND tenant_id = ? AND template_id != 'tool-console'
                      ORDER BY updated_at DESC LIMIT 50""", (p.user_id, p.tenant_id))


@app.get("/api/conversations/{cid}")
def api_conversation(cid: str, p: Principal = Depends(current_principal)):
    conv = agent.load_conversation(p, cid)
    if conv is None:
        raise HTTPException(404, "Conversation not found")
    msgs = db.rows("SELECT role, content, tool_name AS tool, created_at AS at FROM chat_messages "
                   "WHERE conversation_id = ? ORDER BY id", (cid,))
    pending = json.loads(conv["pending_tool_json"]) if conv["pending_tool_json"] else None
    return {"id": cid, "title": conv["title"], "template": conv["template_id"], "messages": msgs,
            "pendingConfirmation": pending and {"label": pending["label"], "expiresAt": pending["expiresAt"],
                                                "tool": pending["functionName"], "arguments": pending.get("arguments"),
                                                "reason": pending.get("reason")},
            "taint": json.loads(conv["taint_json"]) if conv.get("taint_json") else []}


# --- scout data browser -----------------------------------------------------------------------

@app.get("/api/scout/sessions")
def api_sessions(p: Principal = Depends(require(Perm.VIEW_OBSERVATIONS))):
    return db.rows("""SELECT s.id, s.scout_date AS date, s.section_code AS section, s.status, s.created_by AS scout,
                             s.phenology_stage AS phenology, s.notes,
                             (SELECT count(*) FROM scout_session_trees t WHERE t.scout_session_id = s.id) AS trees,
                             (SELECT count(*) FROM scout_session_trees t WHERE t.scout_session_id = s.id
                                AND t.nothing_found = 0) AS treesWithFindings
                      FROM scout_sessions s WHERE s.tenant_id = ? ORDER BY s.scout_date DESC, s.section_code""",
                   (p.tenant_id,))


@app.get("/api/scout/sessions/{sid}")
def api_session(sid: str, p: Principal = Depends(require(Perm.VIEW_OBSERVATIONS))):
    from .tools.farm_reads import GetScoutSession
    from .executor import ToolContext
    result = GetScoutSession(ToolContext(p, RunState(principal=p)), sid)
    if not result.get("found"):
        raise HTTPException(404, "Scout session not found")
    return result


@app.get("/api/sections")
def api_sections(p: Principal = Depends(require(Perm.VIEW_OBSERVATIONS))):
    rows = db.rows("""SELECT f.id, f.code, f.area_m2 AS area, f.centroid_lat AS lat, f.centroid_lng AS lng, f.polygon_json,
                             (SELECT max(s.scout_date) FROM scout_sessions s WHERE s.tenant_id = f.tenant_id
                                AND lower(s.section_code) = lower(f.code)) AS lastScouted
                      FROM farm_sections f WHERE f.tenant_id = ? ORDER BY f.code""", (p.tenant_id,))
    for r in rows:
        r["polygon"] = json.loads(r.pop("polygon_json") or "null")
    return rows


@app.get("/api/activities")
def api_activities(p: Principal = Depends(require(Perm.VIEW_ACTIVITIES))):
    acts = db.rows("""SELECT id, activity_type AS type, state, title, priority, created_by AS createdBy,
                             created_at AS createdAt, farm_section_ids AS sectionIds FROM activities
                      WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100""", (p.tenant_id,))
    for a in acts:
        a["events"] = db.rows("SELECT at, actor, from_state AS fromState, to_state AS toState, note FROM activity_events "
                              "WHERE activity_id = ? ORDER BY id", (a["id"],))
    return acts


# --- security views ----------------------------------------------------------------------------

@app.get("/api/mcp/remote")
def api_remote_mcp(p: Principal = Depends(require(Perm.VIEW_SECURITY))):
    """Allow-listed remote MCP servers and which of their tools are approved, new or changed."""
    return {"configFile": str(settings.mcp_servers_file), "servers": remote_mcp.STATUS}


@app.get("/api/security/audit")
def api_audit(p: Principal = Depends(require(Perm.VIEW_SECURITY))):
    return {
        "tools": db.rows("""SELECT at, username, rolename, channel, tool_name AS tool, arguments_json AS arguments,
                                   outcome, detail FROM tool_audit WHERE tenant_id = ? ORDER BY id DESC LIMIT 200""",
                         (p.tenant_id,)),
        "events": db.rows("""SELECT at, username, event, detail, ip FROM security_events
                             WHERE tenant_id = ? OR tenant_id IS NULL ORDER BY id DESC LIMIT 200""", (p.tenant_id,)),
    }


@app.post("/api/calendar/spray-run")
async def api_calendar_run(p: Principal = Depends(require(Perm.AUTHORISE_ACTIVITIES))):
    """Run the pest spray planner as the unattended calendar identity (propose-only tool set)."""
    runner = Principal.calendar_runner(p.tenant_id)
    log_event("calendar_run", p.username, p.tenant_id, "spray planner run as calendar identity")
    events: list[dict] = []

    def run() -> str:
        return agent.chat(runner, agent.TEMPLATES["pest-spray-planner"].opening, None, "pest-spray-planner", events.append)

    answer = await asyncio.to_thread(run)
    return {"answer": answer, "events": [e for e in events if e["type"] in ("progress", "security", "conversation")]}


# --- MCP ------------------------------------------------------------------------------------------

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    try:
        p = current_principal(request)
    except AuthError as exc:
        return JSONResponse({"error": str(exc)}, status_code=401,
                            headers={"WWW-Authenticate": 'Bearer realm="bongo-ai-demo"'})
    rate_limit(f"mcp:{p.jti}", 60)
    try:
        message = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(mcp_server._error(None, -32700, "Parse error"), status_code=400)
    if isinstance(message, list):
        return JSONResponse(mcp_server._error(None, -32600, "Batching is not supported"), status_code=400)
    reply = await asyncio.to_thread(mcp_server.handle, p, message)
    if reply is None:
        return Response(status_code=202)
    return JSONResponse(reply, headers={"Mcp-Session-Id": p.jti[:16]})


@app.get("/mcp")
def mcp_get():
    return Response(status_code=405, headers={"Allow": "POST"})
