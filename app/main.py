import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI

from app.config import DEFAULT_HMAC_SECRET, get_settings
from app.logging_conf import configure_logging
from app.middleware.request_capture import RequestCaptureMiddleware
from app.middleware.security_headers import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.routes import canary, catchall, decoy_api, decoy_config, decoy_docs, decoy_pages
from app.storage.db import init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    settings = get_settings()
    if settings.hmac_secret == DEFAULT_HMAC_SECRET:
        raise RuntimeError(
            "HMAC_SECRET is still set to the public default from .env.example. "
            "This secret signs canary tokens and IP hashes -- set a real random "
            "value (e.g. `python -c \"import secrets; print(secrets.token_hex(32))\"`) "
            "before starting this service."
        )
    # canary_base_url is just as safety-critical as hmac_secret -- every
    # canary/callback URL embedded in every payload is built from it, and if
    # it were malformed or blank, payloads would render with no working
    # callback URL at all. Unlike hmac_secret, its correct value legitimately
    # varies by deployment (localhost in dev, a real domain in prod), so we
    # can't reject it for a specific value -- only for being unparseable, and
    # by logging it loudly so an operator reviewing startup logs can catch a
    # copy-paste mistake or a forgotten override before it ships.
    parsed_canary_url = urlparse(settings.canary_base_url)
    if parsed_canary_url.scheme not in ("http", "https") or not parsed_canary_url.netloc:
        raise RuntimeError(
            f"CANARY_BASE_URL={settings.canary_base_url!r} is not a valid http(s) "
            "URL. Every payload's callback URL is built from this value -- set it "
            "to this service's own real, reachable address before starting."
        )
    logger.warning("Starting with CANARY_BASE_URL=%s", settings.canary_base_url)
    init_db(settings.database_path)
    yield


def create_app() -> FastAPI:
    # Real docs/openapi are disabled so the honeypot's actual route map never
    # leaks -- the "API docs" attackers see come from decoy_docs.py instead.
    app = FastAPI(
        title="Acme Portal",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # add_middleware() prepends internally, so the LAST one added here ends
    # up outermost. BodySizeLimitMiddleware is added FIRST (innermost, right
    # next to Starlette's built-in ExceptionMiddleware/router) so that a 413
    # it produces -- whether from the honest-Content-Length pre-check or the
    # receive-wrapping enforcement -- still flows back out through
    # RequestCaptureMiddleware (gets logged) and SecurityHeadersMiddleware
    # (gets the decoy Server header) instead of bypassing both. This is safe
    # despite BodySizeLimitMiddleware's own docstring concern about
    # BaseHTTPMiddleware + wrapped-receive exceptions: that failure mode only
    # occurs when a BaseHTTPMiddleware sits BETWEEN the raise point and
    # Starlette's ExceptionMiddleware, and ExceptionMiddleware is always
    # innermost (wraps the router directly) regardless of this ordering, so
    # it still catches the raised HTTPException before it ever has to cross
    # a BaseHTTPMiddleware task-group boundary.
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(RequestCaptureMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(decoy_pages.router)
    app.include_router(decoy_api.router)
    app.include_router(decoy_docs.router)
    app.include_router(decoy_config.router)
    app.include_router(canary.router)
    app.include_router(catchall.router)

    catchall.register_error_handlers(app)

    return app


app = create_app()
