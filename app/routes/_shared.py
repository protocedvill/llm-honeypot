import base64
import time

from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.config import get_settings
from app.payloads.registry import DeliveryVector, resolve_session_style, select_and_render
from app.storage import repository

templates = Jinja2Templates(directory="app/templates")

_EPISODE_SCOPING_GAP_SECONDS = 240


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
    min_req = int(
        repository.get_config("reasoning_min_requests_per_tier")
        or settings.reasoning_min_requests_per_tier
    )

    # Resolve the session's style BEFORE computing the escalation count so
    # the count is scoped to the correct ladder (reasoning_mimicry vs.
    # reciprocity_lure) rather than always using reasoning_mimicry.
    style_override = repository.get_config("style_override")
    session_style = resolve_session_style(session_id, style_override)

    escalation_count = repository.get_reasoning_escalation_count(
        session_id, dwell, now=now, style=session_style,
        min_requests_per_tier=min_req,
        reset_gap_seconds=_EPISODE_SCOPING_GAP_SECONDS,
    )

    def _store_mapping(diag_token: str, cb_token: str) -> None:
        repository.insert_diagnostic_token_mapping(diag_token, cb_token, session_id, now)

    result = select_and_render(
        vector,
        context,
        session_id,
        settings.canary_base_url,
        settings.hmac_secret,
        escalation_count=escalation_count,
        session_style=session_style,
        path=path,
        store_diagnostic_mapping=_store_mapping,
    )
    if result is None:
        return ""
    template, token, rendered = result
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
