import time

from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.config import get_settings
from app.payloads.registry import DeliveryVector, resolve_session_style, select_and_render
from app.storage import repository

templates = Jinja2Templates(directory="app/templates")


def inject_payload(vector: DeliveryVector, context: str, request: Request, path: str) -> str:
    """Selects+renders a payload for this vector/context/session, records it
    as served (this is what makes the comprehension signal possible later),
    and returns the rendered text ready to embed in a response.

    `context` identifies the artifact format the rendered text must read
    like -- "html", "env_file", "git_config", "sql_dump", "json",
    "robots_txt", "openapi", "stack_trace" -- so the same vector never
    renders identical text into incompatible formats (see
    app/payloads/library.py docstring)."""
    settings = get_settings()
    session_id = request.state.session_id
    now = time.time()
    dwell = float(repository.get_config("reasoning_dwell_seconds") or settings.reasoning_dwell_seconds)
    reset_gap = float(
        repository.get_config("reasoning_episode_reset_seconds")
        or settings.reasoning_episode_reset_seconds
    )
    episode_start = repository.get_reasoning_episode_start(session_id, reset_gap)
    if episode_start is None:
        episode_start = now
    escalation_count = int((now - episode_start) // dwell)
    style_override = repository.get_config("style_override")
    session_style = resolve_session_style(session_id, style_override)
    template, token, rendered = select_and_render(
        vector,
        context,
        session_id,
        settings.canary_base_url,
        settings.hmac_secret,
        escalation_count=escalation_count,
        session_style=session_style,
    )
    repository.insert_payload_served(
        session_id=session_id,
        token=token,
        template_id=template.id,
        intent=template.intent.value,
        vector=template.vector.value,
        path=path,
        ts=now,
        marker=template.marker,
        style=template.style,
    )
    return rendered
