"""WordPress-lookalike routes -- reads as the CMS behind /blog. Detection
only, no inject_payload calls: the point is baiting/recognizing real
exploit attempts against a classic scanner target, not LLM payload
comprehension.

/xmlrpc.php never touches a real XML parser -- no DOCTYPE/entity
resolution happens regardless of what's submitted, so there's no XXE risk
to guard against in the first place; detection here is purely about
noticing the attempt, not about a special-cased safety check."""

import re

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from app.routes._shared import templates

router = APIRouter()

_MULTICALL_PATTERN = re.compile(r"system\.multicall", re.IGNORECASE)
_XXE_PATTERN = re.compile(r"<!ENTITY|<!DOCTYPE", re.IGNORECASE)


@router.get("/wp-login.php", response_class=HTMLResponse)
async def wp_login_form(request: Request):
    return templates.TemplateResponse(request, "wp_login.html", {"error": None})


@router.post("/wp-login.php", response_class=HTMLResponse)
async def wp_login_submit(request: Request):
    # Deliberately doesn't validate/parse the submitted body -- same
    # "never validate, always the same safe failure" reasoning as /login.
    return templates.TemplateResponse(
        request,
        "wp_login.html",
        {"error": "ERROR: Invalid username or password."},
        status_code=200,
    )


@router.get("/wp-admin/")
async def wp_admin_redirect():
    # Real WordPress redirects unauthenticated /wp-admin/ requests to the
    # login screen with a reauth flag -- matching that exactly here.
    return RedirectResponse(url="/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1")


@router.post("/xmlrpc.php")
async def xmlrpc(request: Request):
    body = (await request.body()).decode("utf-8", errors="replace")
    if _MULTICALL_PATTERN.search(body) or _XXE_PATTERN.search(body):
        request.state.vuln_probe_detected = True
    # A generic XML-RPC fault -- matches what a patched/hardened instance
    # returns regardless of the call's contents; never actually dispatches
    # a pingback request or resolves any entity.
    fault_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<methodResponse><fault><value><struct>"
        "<member><name>faultCode</name><value><int>405</int></value></member>"
        "<member><name>faultString</name><value><string>"
        "Method not supported for this request"
        "</string></value></member>"
        "</struct></value></fault></methodResponse>"
    )
    return PlainTextResponse(fault_xml, media_type="text/xml")
