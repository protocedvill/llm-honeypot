import logging
import time

from fastapi import APIRouter, FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.middleware.security_headers import DECOY_SERVER_HEADER
from app.payloads.registry import DeliveryVector
from app.routes._shared import header_safe, inject_payload, templates

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/robots.txt")
async def robots_txt(request: Request):
    payload_text = inject_payload(DeliveryVector.ROBOTS_TXT, "robots_txt", request, "/robots.txt")
    body = f"User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\n{payload_text}\n"
    return PlainTextResponse(body)


@router.get("/sitemap.xml")
async def sitemap_xml(request: Request):
    payload_text = inject_payload(DeliveryVector.ROBOTS_TXT, "sitemap_xml", request, "/sitemap.xml")
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url><loc>/login</loc></url>\n"
        f"  <!-- {payload_text} -->\n"
        "</urlset>\n"
    )
    return PlainTextResponse(body, media_type="application/xml")


async def not_found_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code != 404:
        return await http_exception_handler(request, exc)
    payload_text = inject_payload(DeliveryVector.STACK_TRACE, "stack_trace", request, request.url.path)
    response = JSONResponse(
        {"detail": "Not Found", "trace_id": f"req-{int(time.time() * 1000)}"},
        status_code=404,
    )
    response.headers["X-Debug-Info"] = header_safe(payload_text)
    return response


async def server_error_handler(request: Request, exc: Exception):
    # This is the only place that ever sees an unhandled exception -- without
    # logging it here, a real bug is silently indistinguishable from the
    # intentional decoy 500 page, leaving zero operator-visible trace.
    logger.error(
        "Unhandled exception on %s %s", request.method, request.url.path, exc_info=exc
    )
    payload_text = inject_payload(DeliveryVector.STACK_TRACE, "stack_trace", request, request.url.path)
    fake_trace = (
        "Traceback (most recent call last):\n"
        '  File "app/services/billing.py", line 214, in process_request\n'
        "    raise InternalServiceError(reason)\n"
        "queeber.errors.InternalServiceError: upstream ledger timeout\n"
    )
    response = templates.TemplateResponse(
        request,
        "error_500.html",
        {"payload_text": payload_text, "stack_trace": fake_trace},
        status_code=500,
    )
    # SecurityHeadersMiddleware never runs for this response -- Starlette's
    # ServerErrorMiddleware (which invokes this handler) sits outside every
    # app.add_middleware() layer, so the decoy Server header has to be set
    # here directly or a 500 would leak the real default header instead.
    response.headers["Server"] = DECOY_SERVER_HEADER
    return response


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, not_found_handler)
    app.add_exception_handler(Exception, server_error_handler)
