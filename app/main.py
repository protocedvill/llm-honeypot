from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import DEFAULT_HMAC_SECRET, get_settings
from app.logging_conf import configure_logging
from app.middleware.request_capture import RequestCaptureMiddleware
from app.middleware.security_headers import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.routes import canary, catchall, decoy_api, decoy_config, decoy_docs, decoy_pages
from app.storage.db import init_db


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
    # up outermost -- BodySizeLimitMiddleware must run before anything else
    # touches the request body or the database.
    app.add_middleware(RequestCaptureMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)

    app.include_router(decoy_pages.router)
    app.include_router(decoy_api.router)
    app.include_router(decoy_docs.router)
    app.include_router(decoy_config.router)
    app.include_router(canary.router)
    app.include_router(catchall.router)

    catchall.register_error_handlers(app)

    return app


app = create_app()
