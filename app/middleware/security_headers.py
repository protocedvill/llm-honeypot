from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_settings


class BodySizeLimitMiddleware:
    """Caps request bodies at settings.max_body_bytes, enforced against the
    real byte stream as it's consumed (not just a declared Content-Length
    header), so chunked-transfer-encoded or dishonestly-labeled bodies can't
    bypass the cap.

    Implemented as a raw ASGI middleware rather than BaseHTTPMiddleware:
    BaseHTTPMiddleware forwards the request body through an internal anyio
    TaskGroup, which wraps any exception raised from a substituted receive()
    into an ExceptionGroup -- losing its type and breaking Starlette's
    HTTPException handler matching. A plain ASGI middleware forwards receive()
    directly with no such indirection.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > settings.max_body_bytes:
                response = PlainTextResponse("Payload Too Large", status_code=413)
                await response(scope, receive, send)
                return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > settings.max_body_bytes:
                    raise HTTPException(status_code=413, detail="Payload Too Large")
            return message

        await self.app(scope, limited_receive, send)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Replaces the real Server header with a decoy value, so the honeypot
    doesn't advertise that it's a FastAPI/uvicorn service."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
        return response
