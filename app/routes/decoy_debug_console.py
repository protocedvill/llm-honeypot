"""Werkzeug-style debug console lookalike -- reads as an internal Python
tool accidentally left in debug mode (the existing fake 500 stack trace in
catchall.py already establishes this backend as Python). Detection only,
no inject_payload calls.

Always refuses with "Wrong PIN," mirroring Werkzeug's own real safety
property: its actual interactive console is gated by a PIN derived from
machine-specific values that can't be feasibly guessed remotely -- the
decoy's safety is a faithful copy of the real, patched behavior, not an
invented shortcut."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.routes._shared import templates

router = APIRouter()


@router.get("/console", response_class=HTMLResponse)
async def debug_console_form(request: Request):
    return templates.TemplateResponse(request, "debug_console.html", {"error": None})


@router.post("/console", response_class=HTMLResponse)
async def debug_console_submit(request: Request):
    # Any attempt to interact with what looks like a live remote debugger
    # is unambiguous -- doesn't matter what PIN value was actually tried.
    request.state.vuln_probe_detected = True
    return templates.TemplateResponse(
        request,
        "debug_console.html",
        {"error": "Wrong PIN"},
    )
