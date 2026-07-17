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


def _episode_classification_from_bulk(
    session_id: str,
    episode_start: float | None,
    events_desc: list,
    served_markers: list[str],
    total_event_count: int,
) -> EpisodeClassification | None:
    """Same logic/output as re-running classify() against a SignalContext
    built ONLY from this session's current episode (see the module's
    dashboard-performance notes), but operating on rows already bulk-fetched
    for the whole page (see _session_rows) instead of this function issuing
    its own queries. `events_desc` is this session's events, most-recent-
    first, from repository.get_events_bulk. Returns None if the episode has
    no captured requests at all (caller falls back to the raw session row,
    same as first_seen does)."""
    # Reproduces get_recent_events(session_id, limit=21, since=episode_start)
    # against the pre-fetched, most-recent-first list: take the since-cutoff
    # prefix (events_desc is already sorted DESC, so that's a contiguous
    # prefix), then the newest 21 of those.
    if episode_start is None:
        recent_desc = events_desc[:21]
    else:
        recent_desc = [e for e in events_desc if e["ts"] >= episode_start][:21]
    if not recent_desc:
        return None
    recent = list(reversed(recent_desc))
    last = recent[-1]
    prior = recent[:-1]
    last_headers = {k.lower(): v for k, v in json.loads(last["headers_json"]).items()}

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
        # Persisted per-event (events.waf_triggered) specifically so this can
        # be reconstructed here -- same treatment as used_fallback_identity
        # below.
        waf_triggered=bool(last["waf_triggered"]),
        vuln_probe_detected=bool(last["vuln_probe_detected"]),
        # Deliberately NOT scoped to since=episode_start: the live pipeline
        # (request_capture.py) never scopes this either -- it's the session's
        # full-lifetime request count, used by curated_wordlist_recall_signal
        # to distinguish "few requests total" from "long-lived session."
        # Narrowing it to the episode would make this signal fire here when
        # it never fired live (a session with total_event_count > 30 but a
        # small, curated-looking recent episode), showing the operator a
        # classification the live scorer never actually produced.
        total_event_count=total_event_count,
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


def _session_rows(dwell_seconds: float, reset_seconds: float, limit: int, offset: int) -> list[dict]:
    now = time.time()
    page_rows = repository.list_sessions(limit=limit, offset=offset)
    session_ids = [row["session_id"] for row in page_rows]

    # One bulk query per data source for the whole page, instead of one
    # query per session per data source (the N+1 pattern this replaces).
    # Each session's since=episode_start cutoff differs, so every bulk fetch
    # below is unfiltered by since -- the per-session cutoff is applied in
    # Python against the shared result inside the loop.
    events_by_session = repository.get_events_bulk(session_ids)
    reasoning_starts = repository.get_reasoning_episode_starts_bulk(session_ids, reset_seconds, now)
    style_rows_by_session = repository.get_style_counts_bulk(session_ids)
    served_marker_rows_by_session = repository.get_served_markers_bulk(session_ids)
    marker_event_rows_by_session = repository.get_marker_value_events_bulk(session_ids)
    total_event_counts = repository.count_events_bulk(session_ids)

    rows = []
    for row in page_rows:
        session_id = row["session_id"]
        events_desc = events_by_session.get(session_id, [])
        # A session_id can collide across many unrelated, time-disjoint
        # visits (the fallback-identity limitation documented on
        # fallback_identity()) -- episode_start scopes every displayed field
        # below to just the current, unbroken run of activity, not the
        # session_id's entire lifetime history, so an old test run from
        # hours/days ago can't blend its style/fingerprint/classification
        # data into what's showing for a session that's active right now.
        episode_start = repository.episode_start_from_timestamps(
            [e["ts"] for e in events_desc], reset_seconds
        )
        style_counts = repository.style_counts_from_rows(
            style_rows_by_session.get(session_id, []), since=episode_start
        )
        escalation_count = min(
            repository.escalation_count_from_episode_start(
                reasoning_starts.get(session_id), dwell_seconds, now
            ),
            _REASONING_MAX_STAGE,
        )
        served_markers = repository.served_markers_from_rows(
            served_marker_rows_by_session.get(session_id, []), since=episode_start
        )
        episode = _episode_classification_from_bulk(
            session_id, episode_start, events_desc, served_markers,
            total_event_counts.get(session_id, 0),
        )
        cls = episode.classification if episode else None
        waf_block_count = sum(
            1
            for e in events_desc
            if (episode_start is None or e["ts"] >= episode_start) and e["waf_triggered"]
        )
        vuln_probe_count = sum(
            1
            for e in events_desc
            if (episode_start is None or e["ts"] >= episode_start) and e["vuln_probe_detected"]
        )
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
                "waf_block_count": waf_block_count,
                "vuln_probe_count": vuln_probe_count,
                "first_seen": _fmt_ts(episode_start if episode_start is not None else row["first_seen"]),
                "last_seen": _fmt_ts(row["last_seen"]),
                "escalation_count": escalation_count,
                "style_counts": style_counts,
                "marker_values": repository.marker_values_from_rows(
                    marker_event_rows_by_session.get(session_id, []),
                    served_markers,
                    since=episode_start,
                    limit_per_marker=5,
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
    async def dashboard(request: Request, page: int = 1):
        settings = get_settings()
        current_override = repository.get_config("style_override") or "auto"
        dwell_seconds = int(
            repository.get_config("reasoning_dwell_seconds") or settings.reasoning_dwell_seconds
        )
        reset_seconds = int(
            repository.get_config("reasoning_episode_reset_seconds")
            or settings.reasoning_episode_reset_seconds
        )
        waf_override = repository.get_config("waf_enabled")
        waf_enabled = settings.waf_enabled if waf_override is None else waf_override == "on"
        page_size = settings.console_page_size
        total_sessions = repository.count_sessions()
        total_pages = max((total_sessions + page_size - 1) // page_size, 1)
        # Clamp rather than error on an out-of-range page: sessions churn
        # between renders (offset-pagination drift under concurrent writes
        # is an accepted limitation for a small admin console), and a
        # manually-typed ?page=9999 should degrade to the last real page
        # instead of silently rendering zero rows.
        page = min(max(page, 1), total_pages)
        offset = (page - 1) * page_size
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "sessions": _session_rows(dwell_seconds, reset_seconds, limit=page_size, offset=offset),
                "styles": STYLES,
                "current_override": current_override,
                "dwell_seconds": dwell_seconds,
                "reset_seconds": reset_seconds,
                "waf_enabled": waf_enabled,
                "page": page,
                "total_pages": total_pages,
                "total_sessions": total_sessions,
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

    @app.post("/waf", dependencies=[Depends(require_auth)])
    async def set_waf(waf_enabled: str = Form(...)):
        if waf_enabled not in ("on", "off"):
            raise HTTPException(status_code=400, detail=f"unknown waf_enabled {waf_enabled!r}")
        repository.set_config("waf_enabled", waf_enabled)
        return RedirectResponse(url="/", status_code=303)

    return app


app = create_console_app()
