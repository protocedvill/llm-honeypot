"""Blog index + post pages -- pure inert filler, no inject_payload calls.

Unknown slugs are deliberately not special-cased: raising a plain 404 lets
them fall through to the existing global not_found_handler
(app/routes/catchall.py), same as any other unmatched path."""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.routes._shared import templates

router = APIRouter()

POSTS: list[dict] = [
    {
        "slug": "usage-based-billing-for-teams",
        "title": "Introducing Usage-Based Billing for Teams",
        "date": "June 3, 2026",
        "excerpt": "Meter any event and turn it into an invoice line item, with tiered and graduated pricing built in.",
        "body": [
            "Today we're rolling out usage-based billing rules for every "
            "workspace on the Growth plan and above. Instead of writing "
            "custom logic to translate metered events into invoice line "
            "items, you can now define tiered or graduated pricing "
            "directly in the dashboard.",
            "A tiered rule charges a flat rate per unit within a bracket "
            "(e.g. $0.01/call for the first 100k calls, $0.008/call "
            "after). A graduated rule instead charges progressively "
            "higher rates as usage increases within a single invoice. "
            "Both support monthly resets and proration for partial "
            "billing periods.",
            "Existing customers on custom-coded usage billing can migrate "
            "at their own pace; the old metering API continues to work "
            "unchanged.",
        ],
    },
    {
        "slug": "scaling-api-to-50m-requests",
        "title": "How We Scaled Our API to 50M Requests a Day",
        "date": "May 14, 2026",
        "excerpt": "Notes on the database sharding and caching work behind our latest throughput milestone.",
        "body": [
            "Eighteen months ago our API handled about 4M requests a day. "
            "Last week we crossed 50M. This post is a short account of "
            "the three changes that mattered most: sharding the "
            "invoice-line-item table by workspace, moving idempotency-key "
            "lookups to a dedicated cache tier, and rewriting our webhook "
            "dispatcher as a pull-based queue instead of a push loop.",
            "Sharding was the highest-effort, highest-payoff change. We "
            "went with workspace_id as the shard key since almost every "
            "query is already scoped to one workspace, which let us avoid "
            "cross-shard joins entirely.",
        ],
    },
    {
        "slug": "acme-named-leader-2026-billing-report",
        "title": "Acme Named a Leader in the 2026 Billing Platforms Report",
        "date": "Apr 22, 2026",
        "excerpt": "An independent analyst report ranked Acme highest for usage-based billing flexibility.",
        "body": [
            "We're proud to share that Acme was named a Leader in this "
            "year's independent billing platforms market report, scoring "
            "highest among evaluated vendors for usage-based billing "
            "flexibility and API reliability.",
            "The report cites our tiered/graduated pricing engine and "
            "webhook retry guarantees as differentiators against "
            "traditional subscription-billing incumbents.",
        ],
    },
    {
        "slug": "5-tips-reconciling-invoices-faster",
        "title": "5 Tips for Reconciling Invoices Faster",
        "date": "Mar 30, 2026",
        "excerpt": "Small workflow changes that cut our own finance team's monthly close time in half.",
        "body": [
            "1. Export audit logs alongside invoices, not after the fact "
            "-- most discrepancies are easier to explain with the "
            "context of who changed what, when.",
            "2. Use webhook events to reconcile in near-real-time instead "
            "of a nightly batch job; catching a failed payment the same "
            "day is much cheaper than catching it a month later.",
            "3. Tag invoices with a cost-center field at creation time "
            "rather than backfilling it during close.",
            "4. Automate dunning emails for failed payments rather than "
            "manually tracking retries in a spreadsheet.",
            "5. Review your proration rules quarterly -- most reconciliation "
            "surprises we see come from an edge case in a mid-cycle plan "
            "change.",
        ],
    },
    {
        "slug": "webhook-retry-policies",
        "title": "Product Update: New Webhook Retry Policies",
        "date": "Jan 30, 2026",
        "excerpt": "Configure fixed-interval or exponential-backoff retries per webhook endpoint.",
        "body": [
            "Webhook endpoints can now be configured with either a "
            "fixed-interval or exponential-backoff retry policy, up to a "
            "maximum of 10 attempts over 24 hours. Previously every "
            "endpoint used the same fixed 5-retry schedule.",
            "This is especially useful for endpoints that occasionally "
            "get overwhelmed during a deploy -- an exponential backoff "
            "gives your service more room to recover before the next "
            "attempt.",
        ],
    },
]

_POSTS_BY_SLUG = {post["slug"]: post for post in POSTS}


@router.get("/blog", response_class=HTMLResponse)
async def blog_index(request: Request):
    return templates.TemplateResponse(request, "blog_index.html", {"posts": POSTS})


@router.get("/blog/{slug}", response_class=HTMLResponse)
async def blog_post(slug: str, request: Request):
    post = _POSTS_BY_SLUG.get(slug)
    if post is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(request, "blog_post.html", {"post": post})
