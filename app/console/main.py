import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.payloads.registry import STYLES
from app.storage import repository
from app.storage.db import init_db

templates = Jinja2Templates(directory="app/console/templates")
security = HTTPBasic(auto_error=False)

_CONSOLE_USERNAME = "operator"
_ACTIVE_WINDOW_SECONDS = 300


def require_auth(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
    settings = get_settings()
    token = settings.console_token
    valid = (
        bool(token)
        and credentials is not None
        and secrets.compare_digest(credentials.username, _CONSOLE_USERNAME)
        and secrets.compare_digest(credentials.password, token)
    )
    if not valid:
        # 401 + WWW-Authenticate (not 404) is deliberate here: this app only
        # ever runs on its own separate port (see app/run.py), never on the
        # honeypot's public port, so there's no decoy-surface reason to hide
        # its existence behind a fake 404 the way the honeypot itself does.
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Basic"},
        )


def _fmt_ts(value: float | None) -> str:
    if not value:
        return "-"
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _session_rows() -> list[dict]:
    now = time.time()
    rows = []
    for row in repository.list_sessions(limit=200):
        style_counts = repository.get_style_counts(row["session_id"])
        rows.append(
            {
                "session_id": row["session_id"],
                "ip_hash": row["ip_hash"][:12],
                "classification": row["classification"],
                "bot_score": round(row["bot_score"], 2),
                "ai_score": round(row["ai_score"], 2),
                "human_score": round(row["human_score"], 2),
                "js_beacon_fired": bool(row["js_beacon_fired"]),
                "canary_confirmed": bool(row["canary_confirmed"]),
                "first_seen": _fmt_ts(row["first_seen"]),
                "last_seen": _fmt_ts(row["last_seen"]),
                "escalation_count": style_counts.get("reasoning_mimicry", 0),
                "style_counts": style_counts,
                "is_active": bool(row["last_seen"]) and (now - row["last_seen"]) < _ACTIVE_WINDOW_SECONDS,
            }
        )
    return rows


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db(settings.database_path)
    yield


def create_console_app() -> FastAPI:
    app = FastAPI(
        title="Honeypot Console",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.get("/", dependencies=[Depends(require_auth)])
    async def dashboard(request: Request):
        settings = get_settings()
        current_override = repository.get_config("style_override") or "auto"
        dwell_seconds = repository.get_config("reasoning_dwell_seconds") or settings.reasoning_dwell_seconds
        reset_seconds = (
            repository.get_config("reasoning_episode_reset_seconds")
            or settings.reasoning_episode_reset_seconds
        )
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "sessions": _session_rows(),
                "styles": STYLES,
                "current_override": current_override,
                "dwell_seconds": dwell_seconds,
                "reset_seconds": reset_seconds,
            },
        )

    @app.post("/style", dependencies=[Depends(require_auth)])
    async def set_style(style: str = Form(...)):
        if style != "auto" and style not in STYLES:
            raise HTTPException(status_code=400, detail=f"unknown style {style!r}")
        repository.set_config("style_override", style)
        return RedirectResponse(url="/", status_code=303)

    @app.post("/timing", dependencies=[Depends(require_auth)])
    async def set_timing(dwell_seconds: int = Form(...), reset_seconds: int = Form(...)):
        if dwell_seconds <= 0 or reset_seconds <= 0:
            raise HTTPException(status_code=400, detail="dwell/reset seconds must be positive")
        repository.set_config("reasoning_dwell_seconds", str(dwell_seconds))
        repository.set_config("reasoning_episode_reset_seconds", str(reset_seconds))
        return RedirectResponse(url="/", status_code=303)

    return app


app = create_console_app()
