import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.config import get_settings
from app.detection.scoring import classify
from app.detection.session import SESSION_COOKIE_NAME, fallback_identity, hash_ip
from app.detection.signals import SignalContext
from app.storage import repository

# Headers whose VALUES are never persisted, since they can carry secrets or
# PII (a real client IP behind a future reverse proxy, session cookies,
# credentials an attacker probes with). We still record that the header was
# present -- only the value is replaced -- since presence/absence is itself
# a useful signal.
_REDACTED_HEADERS = {
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
}


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        k: ("[REDACTED]" if k in _REDACTED_HEADERS else v) for k, v in headers.items()
    }


class RequestCaptureMiddleware(BaseHTTPMiddleware):
    """Times each request, resolves/persists session identity, runs the
    detection signals once the response is known, and writes the resulting
    score + event row to storage."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        settings = get_settings()
        start_ts = time.time()

        ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        cookie_session_id = request.cookies.get(SESSION_COOKIE_NAME)
        # Falsy, not just `is None` -- an empty `Cookie: hp_sid=` is valid
        # cookie syntax and parses to "", which is also what `or` below falls
        # through on. Using `is None` here would desync this flag from which
        # branch `session_id` actually took.
        used_fallback = not cookie_session_id
        session_id = cookie_session_id or fallback_identity(
            ip,
            user_agent,
            settings.hmac_secret,
            request.headers.get("accept", ""),
            request.headers.get("accept-language", ""),
            request.headers.get("accept-encoding", ""),
        )

        request.state.session_id = session_id

        ip_hash = hash_ip(ip, settings.hmac_secret)
        repository.upsert_session(session_id, ip_hash, user_agent, start_ts)

        prior_events = repository.get_recent_events(session_id)
        prior_timestamps = [row["ts"] for row in prior_events]
        prior_paths = [row["path"] for row in prior_events]

        try:
            response = await call_next(request)
        except Exception:
            # Even though the route raised, still record the event and score
            # this session -- otherwise a single unhandled exception silently
            # drops this request from every detection signal with no trace.
            self._record(
                request=request,
                session_id=session_id,
                ip=ip,
                start_ts=start_ts,
                prior_timestamps=prior_timestamps,
                prior_paths=prior_paths,
                used_fallback=used_fallback,
                status_code=500,
                response=None,
            )
            raise

        self._record(
            request=request,
            session_id=session_id,
            ip=ip,
            start_ts=start_ts,
            prior_timestamps=prior_timestamps,
            prior_paths=prior_paths,
            used_fallback=used_fallback,
            status_code=response.status_code,
            response=response,
        )
        return response

    def _record(
        self,
        *,
        request: Request,
        session_id: str,
        ip: str,
        start_ts: float,
        prior_timestamps: list[float],
        prior_paths: list[str],
        used_fallback: bool,
        status_code: int,
        response: Response | None,
    ) -> None:
        requested_token = (request.path_params or {}).get("token")
        is_comprehension_hit = bool(
            requested_token
            and repository.was_token_served_to_session(session_id, requested_token)
        )

        session_row = repository.get_session(session_id)
        js_beacon_fired = bool(session_row["js_beacon_fired"]) if session_row else False
        # Read back as a persisted flag (set directly on this session by the
        # canary route, however it was reached) rather than an ephemeral
        # per-request value -- so the AI_AGENT determination survives across
        # every later request in the session, not just the one that hit the
        # callback.
        canary_confirmed = bool(session_row["canary_confirmed"]) if session_row else False

        headers_lower = {k.lower(): v for k, v in request.headers.items()}
        # A marker (e.g. a header name a payload asked to be echoed) showing
        # up in THIS request -- with any value -- proves the client read and
        # tested a hypothesis from a prior response's text, regardless of
        # whether it complied with what the instruction actually asked for.
        served_markers = repository.get_served_markers(session_id)
        is_marker_referenced = any(marker.lower() in headers_lower for marker in served_markers)

        total_event_count = repository.count_events(session_id)

        ctx = SignalContext(
            headers=headers_lower,
            method=request.method,
            path=request.url.path,
            ip=ip,
            session_id=session_id,
            ts=start_ts,
            prior_event_timestamps=prior_timestamps,
            prior_event_paths=prior_paths,
            total_event_count=total_event_count,
            is_canary_hit=canary_confirmed,
            is_comprehension_hit=is_comprehension_hit,
            is_marker_referenced=is_marker_referenced,
            js_beacon_fired=js_beacon_fired,
            used_fallback_identity=used_fallback,
        )
        classification = classify(ctx)
        repository.update_session_scores(
            session_id,
            classification.bot_score,
            classification.ai_score,
            classification.human_score,
            classification.label,
        )

        think_time_ms = None
        if prior_timestamps:
            think_time_ms = (start_ts - prior_timestamps[-1]) * 1000

        repository.insert_event(
            session_id=session_id,
            ts=start_ts,
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            headers=_redact_headers(headers_lower),
            think_time_ms=think_time_ms,
        )

        # Only reachable when call_next returned normally -- if the route
        # raised, there's no response object left to attach a Set-Cookie to;
        # the visitor's fallback identity is still deterministic from ip+ua,
        # so a later request from the same client still resolves to the same
        # session even without the cookie.
        if used_fallback and response is not None:
            response.set_cookie(
                SESSION_COOKIE_NAME,
                session_id,
                httponly=True,
                samesite="lax",
                max_age=60 * 60 * 24 * 30,
            )
