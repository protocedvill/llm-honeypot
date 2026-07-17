"""Help-center index + article pages -- pure inert filler, no
inject_payload calls.

Unknown topics are deliberately not special-cased: raising a plain 404 lets
them fall through to the existing global not_found_handler
(app/routes/catchall.py), same as any other unmatched path."""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.routes._shared import templates

router = APIRouter()

CATEGORIES: list[dict] = [
    {
        "name": "Account & Billing",
        "articles": ["reset-password", "understanding-your-invoice", "exporting-billing-history"],
    },
    {
        "name": "API & Integrations",
        "articles": ["generating-an-api-key", "setting-up-webhook-endpoints"],
    },
    {
        "name": "Troubleshooting",
        "articles": ["webhook-failing"],
    },
]

ARTICLES: dict[str, dict] = {
    "reset-password": {
        "title": "How do I reset my password?",
        "category": "Account & Billing",
        "body": [
            "Go to the sign-in page and click \"Forgot password.\" We'll "
            "send a reset link to the email address on your account, "
            "valid for 60 minutes.",
            "If you don't receive the email within a few minutes, check "
            "your spam folder, and confirm your workspace admin has the "
            "correct email address on file for you.",
        ],
    },
    "understanding-your-invoice": {
        "title": "Understanding your monthly invoice",
        "category": "Account & Billing",
        "body": [
            "Your invoice has three sections: a flat subscription fee for "
            "your plan, usage-based line items for any metered billing "
            "rules configured on your workspace, and any one-time "
            "adjustments applied by our team.",
            "Usage line items show the metric name, the tier or rate "
            "applied, and the raw usage count for the billing period. You "
            "can see a day-by-day breakdown from the Usage tab in your "
            "dashboard.",
        ],
    },
    "exporting-billing-history": {
        "title": "How do I export my billing history?",
        "category": "Account & Billing",
        "body": [
            "From your dashboard, go to Billing &rsaquo; History and click "
            "\"Export CSV.\" Exports include invoice number, date, "
            "amount, status, and line-item detail for the date range you "
            "select.",
            "For automated exports, use the API's "
            "<code>GET /api/v1/orders/{id}/invoice</code> endpoint.",
        ],
    },
    "generating-an-api-key": {
        "title": "Generating an API key",
        "category": "API & Integrations",
        "body": [
            "From your dashboard, go to Settings &rsaquo; API Keys and "
            "click \"Generate new key.\" Keys are scoped to a single "
            "workspace and can be restricted to read-only access.",
            "Store your key securely -- it's only shown once at creation "
            "time. If a key is compromised, revoke it immediately from "
            "the same page; revocation takes effect within a minute.",
        ],
    },
    "setting-up-webhook-endpoints": {
        "title": "Setting up webhook endpoints",
        "category": "API & Integrations",
        "body": [
            "Add an endpoint URL from Settings &rsaquo; Webhooks and "
            "select which event types to subscribe to (invoice.created, "
            "invoice.paid, subscription.updated, and others).",
            "Every webhook request is signed; verify the signature header "
            "against your endpoint's signing secret before trusting the "
            "payload. See the API docs for the verification algorithm.",
        ],
    },
    "webhook-failing": {
        "title": "Why is my webhook failing?",
        "category": "Troubleshooting",
        "body": [
            "The most common cause is the endpoint returning a non-2xx "
            "status code or timing out -- both are treated as delivery "
            "failures and trigger a retry per your configured retry "
            "policy.",
            "Check Settings &rsaquo; Webhooks &rsaquo; Delivery Log for "
            "the response code and body your endpoint returned on the "
            "last attempt. If deliveries have been failing for a while, "
            "the endpoint may have been automatically disabled -- "
            "re-enable it from the same page once the issue is fixed.",
        ],
    },
}


@router.get("/help", response_class=HTMLResponse)
async def help_index(request: Request):
    return templates.TemplateResponse(
        request,
        "help_index.html",
        {"categories": CATEGORIES, "articles": ARTICLES},
    )


@router.get("/help/{topic}", response_class=HTMLResponse)
async def help_article(topic: str, request: Request):
    article = ARTICLES.get(topic)
    if article is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(request, "help_article.html", {"article": article})
