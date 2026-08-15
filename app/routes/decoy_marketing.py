"""Ordinary marketing/support/legal pages for site-surface realism.

Deliberately pure inert filler -- unlike every other route module in this
package, nothing here calls inject_payload(). A site that's only bait
(sensitive-looking decoys + API stubs) with no mundane pages around it can
itself read as purpose-built to a careful attacker; these routes exist so
the site has an ordinary footprint too."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.fake_org import LEADERSHIP, OFFICES
from app.routes._shared import templates

router = APIRouter()


@router.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    return templates.TemplateResponse(
        request, "about.html", {"leadership": LEADERSHIP, "offices": OFFICES}
    )


@router.get("/pricing", response_class=HTMLResponse)
async def pricing(request: Request):
    return templates.TemplateResponse(request, "pricing.html", {})


@router.get("/features", response_class=HTMLResponse)
async def features(request: Request):
    return templates.TemplateResponse(request, "features.html", {})


@router.get("/security", response_class=HTMLResponse)
async def security(request: Request):
    return templates.TemplateResponse(request, "security.html", {})


@router.get("/integrations", response_class=HTMLResponse)
async def integrations(request: Request):
    return templates.TemplateResponse(request, "integrations.html", {})


@router.get("/customers", response_class=HTMLResponse)
async def customers(request: Request):
    return templates.TemplateResponse(request, "customers.html", {})


@router.get("/careers", response_class=HTMLResponse)
async def careers(request: Request):
    return templates.TemplateResponse(request, "careers.html", {})


@router.get("/terms", response_class=HTMLResponse)
async def terms(request: Request):
    return templates.TemplateResponse(request, "terms.html", {})


@router.get("/privacy", response_class=HTMLResponse)
async def privacy(request: Request):
    return templates.TemplateResponse(request, "privacy.html", {})


@router.get("/status", response_class=HTMLResponse)
async def status(request: Request):
    return templates.TemplateResponse(request, "status.html", {})


@router.get("/changelog", response_class=HTMLResponse)
async def changelog(request: Request):
    return templates.TemplateResponse(request, "changelog.html", {})


@router.get("/contact", response_class=HTMLResponse)
async def contact_form(request: Request):
    return templates.TemplateResponse(request, "contact.html", {})


@router.post("/contact", response_class=HTMLResponse)
async def contact_submit(request: Request):
    # Deliberately doesn't validate/parse the submitted body -- same
    # reasoning as /login's and /api/v1/webhooks' POST handlers: a real
    # contact form doesn't 422 just because a client posted something odd.
    return templates.TemplateResponse(
        request,
        "contact.html",
        {"submitted": True},
    )


@router.post("/newsletter", response_class=HTMLResponse)
async def newsletter_submit(request: Request):
    return templates.TemplateResponse(request, "newsletter_confirm.html", {})
