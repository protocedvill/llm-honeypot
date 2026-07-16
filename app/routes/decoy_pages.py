from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.detection.canary_tokens import mint_token
from app.config import get_settings
from app.payloads.registry import DeliveryVector
from app.routes._shared import inject_payload, templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index() -> RedirectResponse:
    return RedirectResponse(url="/login")


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    payload_text = inject_payload(DeliveryVector.HTML_COMMENT, "html", request, "/login")
    settings = get_settings()
    beacon_token = mint_token(request.state.session_id, settings.hmac_secret)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"payload_text": payload_text, "beacon_token": beacon_token},
    )


@router.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request):
    # Deliberately doesn't require/parse any particular field shape -- a real
    # login form doesn't 422 just because a client posted something odd, and
    # neither should this. Every submission gets the same fake failure.
    payload_text = inject_payload(DeliveryVector.HTML_COMMENT, "html", request, "/login")
    settings = get_settings()
    beacon_token = mint_token(request.state.session_id, settings.hmac_secret)
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "payload_text": payload_text,
            "beacon_token": beacon_token,
            "error": "Invalid username or password.",
        },
        status_code=401,
    )


@router.get("/admin")
async def admin(request: Request):
    accept = request.headers.get("accept", "")
    if "application/json" in accept and "text/html" not in accept:
        payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, "/admin")
        return JSONResponse({"detail": payload_text}, status_code=403)
    payload_text = inject_payload(DeliveryVector.HTML_COMMENT, "html", request, "/admin")
    return templates.TemplateResponse(
        request, "admin.html", {"payload_text": payload_text}, status_code=403
    )
