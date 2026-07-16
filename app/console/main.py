import json
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.detection.scoring import Classification, classify
from app.detection.signals import SignalContext
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


# The 13-stage reasoning_mimicry ladder's last index -- the dashboard clamps
# to this so the displayed stage can never exceed what the ladder itself has
# content for (select_and_render clamps the same way when rendering).
_REASONING_MAX_STAGE = 12

_CALLBACK_PATH_PREFIX = "/api/internal/callback/"


@dataclass
class EpisodeClassification:
    classification: Classification
    canary_confirmed: bool
    js_beacon_fired: bool
    served_markers: list[str]


def _episode_classification(
    session_id: str, episode_start: float | None
) -> EpisodeClassification | None:
    """Re-runs the same pure classify() the live pipeline uses
    (app/middleware/request_capture.py), but against a SignalContext built
    ONLY from this session's current episode -- so a session_id that
    collided with an unrelated past visit (see get_session_episode_start)
    can't have its console row show a classification/canary/beacon verdict
    that visit earned, rather than this one. Mirrors "state as of the most
    recent request" the same way the live scorer does, just with the
    trailing window narrowed to the episode instead of the session's whole
    lifetime. Returns None if the episode has no captured requests at all
    (caller falls back to the raw session row, same as first_seen does)."""
    recent = repository.get_recent_events(session_id, limit=21, since=episode_start)
    if not recent:
        return None
    last = recent[-1]
    prior = recent[:-1]
    last_headers = {k.lower(): v for k, v in json.loads(last["headers_json"]).items()}

    served_markers = repository.get_served_markers(session_id, since=episode_start)
    is_marker_referenced = any(marker.lower() in last_headers for marker in served_markers)

    is_comprehension_hit = False
    if last["path"].startswith(_CALLBACK_PATH_PREFIX):
        token = last["path"][len(_CALLBACK_PATH_PREFIX):]
        is_comprehension_hit = repository.was_token_served_to_session(session_id, token)

    canary_confirmed = repository.has_verified_canary_hit(session_id, since=episode_start)
    js_beacon_fired = repository.has_verified_beacon_hit(session_id, since=episode_start)

    ctx = SignalContext(
        headers=last_headers,
        method=last["method"],
        path=last["path"],
        ip="",
        session_id=session_id,
        ts=last["ts"],
        prior_event_timestamps=[e["ts"] for e in prior],
        prior_event_paths=[e["path"] for e in prior],
        # Deliberately NOT scoped to since=episode_start: the live pipeline
        # (request_capture.py) never scopes this either -- it's the session's
        # full-lifetime request count, used by curated_wordlist_recall_signal
        # to distinguish "few requests total" from "long-lived session."
        # Narrowing it to the episode would make this signal fire here when
        # it never fired live (a session with total_event_count > 30 but a
        # small, curated-looking recent episode), showing the operator a
        # classification the live scorer never actually produced.
        total_event_count=repository.count_events(session_id),
        is_canary_hit=canary_confirmed,
        is_comprehension_hit=is_comprehension_hit,
        is_marker_referenced=is_marker_referenced,
        js_beacon_fired=js_beacon_fired,
        # Persisted per-event (events.used_fallback_identity) specifically so
        # this can be reconstructed here -- it's what the live pipeline used
        # for the cookie_retention_signal contribution on this exact request.
        used_fallback_identity=bool(last["used_fallback_identity"]),
    )
    return EpisodeClassification(classify(ctx), canary_confirmed, js_beacon_fired, served_markers)


def _session_rows(dwell_seconds: float, reset_seconds: float) -> list[dict]:
    now = time.time()
    rows = []
    for row in repository.list_sessions(limit=200):
        session_id = row["session_id"]
        # A session_id can collide across many unrelated, time-disjoint
        # visits (the fallback-identity limitation documented on
        # fallback_identity()) -- episode_start scopes every displayed field
        # below to just the current, unbroken run of activity, not the
        # session_id's entire lifetime history, so an old test run from
        # hours/days ago can't blend its style/fingerprint/classification
        # data into what's showing for a session that's active right now.
        episode_start = repository.get_session_episode_start(session_id, reset_seconds)
        style_counts = repository.get_style_counts(session_id, since=episode_start)
        escalation_count = min(
            repository.get_reasoning_escalation_count(
                session_id, dwell_seconds, reset_seconds, now=now
            ),
            _REASONING_MAX_STAGE,
        )
        episode = _episode_classification(session_id, episode_start)
        cls = episode.classification if episode else None
        rows.append(
            {
                "session_id": session_id,
                "ip_hash": row["ip_hash"][:12],
                "classification": cls.label if cls else row["classification"],
                "bot_score": round(cls.bot_score if cls else row["bot_score"], 2),
                "ai_score": round(cls.ai_score if cls else row["ai_score"], 2),
                "human_score": round(cls.human_score if cls else row["human_score"], 2),
                "js_beacon_fired": episode.js_beacon_fired if episode else bool(row["js_beacon_fired"]),
                "canary_confirmed": episode.canary_confirmed if episode else bool(row["canary_confirmed"]),
                "first_seen": _fmt_ts(episode_start if episode_start is not None else row["first_seen"]),
                "last_seen": _fmt_ts(row["last_seen"]),
                "escalation_count": escalation_count,
                "style_counts": style_counts,
                "marker_values": repository.get_marker_values(
                    session_id,
                    since=episode_start,
                    markers=episode.served_markers if episode else None,
                ),
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
        dwell_seconds = int(
            repository.get_config("reasoning_dwell_seconds") or settings.reasoning_dwell_seconds
        )
        reset_seconds = int(
            repository.get_config("reasoning_episode_reset_seconds")
            or settings.reasoning_episode_reset_seconds
        )
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "sessions": _session_rows(dwell_seconds, reset_seconds),
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
