import base64
import time

from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.config import get_settings
from app.payloads.registry import DeliveryVector, resolve_session_style, select_and_render
from app.storage import repository

templates = Jinja2Templates(directory="app/templates")


def header_safe(text: str) -> str:
    """HTTP header values must be Latin-1 (RFC 7230) -- most payload text is
    plain ASCII/English and passes through untouched, but
    context_bombs_chinese.py's Chinese-language content isn't, and setting
    it directly as a header value raises UnicodeEncodeError and crashes the
    response. Falls back to base64 instead of dropping/refusing the
    content: theory/context-bombs.txt notes this retains effectiveness --
    models that encounter it recognize and decode base64 in the large
    majority of cases."""
    try:
        text.encode("latin-1")
        return text
    except UnicodeEncodeError:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")


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
    escalation_count = repository.get_reasoning_escalation_count(
        session_id, dwell, reset_gap, now=now
    )
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
        path=path,
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
