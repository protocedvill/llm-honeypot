import time

from fastapi import APIRouter, Request, Response

from app.config import get_settings
from app.detection.canary_tokens import verify_token
from app.storage import repository

router = APIRouter()


@router.get("/api/internal/callback/{token}")
async def canary_callback(token: str, request: Request):
    """Hit only ever occurs if a client fetched a URL that was embedded
    inside an instruction-style payload -- never a clickable link. A valid
    signature proves we minted this token (not guessed), which is the core
    AI-agent signal fed into scoring on the *next* request in this session."""
    settings = get_settings()
    verified_session_id = verify_token(token, settings.hmac_secret)
    repository.insert_canary_hit(
        session_id=verified_session_id or request.state.session_id,
        token=token,
        path=str(request.url.path),
        ts=time.time(),
        verified=verified_session_id is not None,
    )
    if verified_session_id:
        # Persisted directly on the session the token was minted for -- not
        # request.state.session_id, which is whatever session THIS callback
        # request resolves to and can differ (e.g. an LLM agent's tool-calling
        # HTTP fetch of the embedded URL doesn't carry the original session's
        # cookie). This also makes the AI_AGENT determination durable: it's
        # read back on every future request in that session, not just this one.
        repository.mark_canary_confirmed(verified_session_id)
    return Response(status_code=204)


@router.get("/api/internal/beacon/{token}")
async def js_beacon(token: str):
    """Fired only by a rendering engine executing the login page's script
    tag -- proves a real browser or a browser-use/computer-use agent, as
    opposed to a raw HTTP fetcher that only reads response bodies."""
    settings = get_settings()
    verified_session_id = verify_token(token, settings.hmac_secret)
    if verified_session_id:
        repository.mark_js_beacon_fired(verified_session_id)
    return Response(status_code=204)
