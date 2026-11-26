"""
OGK FastAPI Application Entrypoint:
- Lifespan initializes SQLite (WAL) and runs the 90-day data retention worker.
- Global IP rate limiting middleware and CORS configuration.
- Mounts all REST + WebSocket routers and starter Jinja2 dashboard views.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .api import auth, enroll, events, heartbeat, policy, reports, requests, ws
from .core.config import PROJECT_ROOT, settings
from .core.database import init_db
from .core.security import get_client_ip, rate_limiter
from .services.retention import retention_background_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

TEMPLATES_DIR = PROJECT_ROOT / "dashboard" / "templates"
STATIC_DIR = PROJECT_ROOT / "dashboard" / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR)) if TEMPLATES_DIR.exists() else None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    stop_event = asyncio.Event()
    retention_task = None
    if settings.environment != "test":
        retention_task = asyncio.create_task(retention_background_loop(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        if retention_task is not None:
            retention_task.cancel()
            try:
                await retention_task
            except asyncio.CancelledError:
                pass


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description=(
        "OGK — Công cụ đồng hành hỗ trợ quản lý sử dụng máy tính của trẻ em "
        "(Minh bạch, tối thiểu dữ liệu NT1–NT6, không phải phần mềm gián điệp)."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def ip_rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        ip = get_client_ip(request)
        try:
            rate_limiter.check(
                key=f"api:{ip}",
                limit=settings.rate_limit_requests_per_minute,
                window_seconds=60,
            )
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


# Mount dashboard static assets (JS/CSS) unconditionally
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Register API & WebSocket routers
app.include_router(auth.router)
app.include_router(enroll.router)
app.include_router(heartbeat.router)
app.include_router(policy.router)
app.include_router(ws.router)
app.include_router(events.router)
app.include_router(reports.router)
app.include_router(requests.router)


@app.get("/health", tags=["system"])
def health_check() -> dict:
    return {
        "status": "ok",
        "service": "ogk-server",
        "principles": ["NT1", "NT2", "NT3", "NT4", "NT5", "NT6"],
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard_index(request: Request):
    if templates and (TEMPLATES_DIR / "index.html").exists():
        return templates.TemplateResponse(request, "index.html", {"app_name": settings.app_name})
    return HTMLResponse("<h1>OGK Server is running</h1><p>Visit <a href='/docs'>/docs</a> for OpenAPI.</p>")


@app.get("/child-view", response_class=HTMLResponse, include_in_schema=False)
def dashboard_child_view(request: Request):
    if templates and (TEMPLATES_DIR / "child_transparency.html").exists():
        return templates.TemplateResponse(request, "child_transparency.html", {"app_name": settings.app_name})
    return HTMLResponse("<h1>OGK Child Transparency View</h1>")
