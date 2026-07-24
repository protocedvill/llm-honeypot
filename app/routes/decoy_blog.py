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
        "slug": "instant-payouts-for-sellers",
        "title": "Introducing Instant Payouts for Sellers",
        "date": "June 3, 2026",
        "excerpt": "Cash out the moment your item sells, no more waiting for the weekly payout batch.",
        "body": [
            "Today we're rolling out instant payouts for every verified "
            "seller on Queeber. Instead of waiting for the weekly payout "
            "batch, funds from a completed sale now land in your linked "
            "account within minutes of the buyer confirming pickup or "
            "delivery.",
            "Instant payouts are available first to sellers with a "
            "verified campus email and at least 5 completed sales, and "
            "we're expanding eligibility campus by campus over the next "
            "few months.",
            "Sellers who prefer the old weekly batch can keep it -- "
            "nothing changes unless you opt in.",
        ],
    },
    {
        "slug": "scaling-search-to-2m-listings",
        "title": "How We Scaled Search to 2M Active Listings",
        "date": "May 14, 2026",
        "excerpt": "Notes on the database sharding and caching work behind our latest search-latency milestone.",
        "body": [
            "Eighteen months ago Queeber had about 40k active listings "
            "across a dozen campuses. Last week we crossed 2 million. "
            "This post is a short account of the three changes that "
            "mattered most: sharding the listings table by campus, "
            "moving saved-search matching to a dedicated cache tier, and "
            "rewriting our notification dispatcher as a pull-based queue "
            "instead of a push loop.",
            "Sharding was the highest-effort, highest-payoff change. We "
            "went with campus_id as the shard key since almost every "
            "search is already scoped to one campus, which let us avoid "
            "cross-shard joins entirely.",
        ],
    },
    {
        "slug": "queeber-500-campuses-2026",
        "title": "Queeber Crosses 500 Campuses Ahead of Fall Move-In",
        "date": "Apr 22, 2026",
        "excerpt": "We're now live at 500 colleges and universities, just in time for back-to-school season.",
        "body": [
            "We're proud to share that Queeber is now live at over 500 "
            "campuses nationwide, just in time for fall move-in and the "
            "start-of-semester textbook rush.",
            "Since launch, students have used Queeber to buy and sell "
            "everything from textbooks and mini-fridges to concert "
            "tickets and tutoring sessions with verified classmates -- "
            "all without ever leaving campus.",
        ],
    },
    {
        "slug": "5-tips-selling-textbooks-faster",
        "title": "5 Tips for Selling Your Textbooks Faster",
        "date": "Mar 30, 2026",
        "excerpt": "Small listing changes that cut our top sellers' average time-to-sale in half.",
        "body": [
            "1. Photograph the actual copy you're selling, not a stock "
            "photo -- listings with real photos of the cover and any "
            "highlighting sell noticeably faster.",
            "2. List as soon as you know you're done with a class, not "
            "the week before finals -- the first sellers for a given "
            "course code get the most views.",
            "3. Price a few dollars under the lowest current listing for "
            "your ISBN rather than matching it exactly.",
            "4. Turn on instant offers so buyers can make a lower bid "
            "instead of scrolling past a listing that's slightly out of "
            "budget.",
            "5. Bundle a full course's readings into one listing when you "
            "can -- bundles consistently outsell the same books listed "
            "separately.",
        ],
    },
    {
        "slug": "webhook-notifications-for-partners",
        "title": "Product Update: Webhook Notifications for Campus Partners",
        "date": "Jan 30, 2026",
        "excerpt": "Configure fixed-interval or exponential-backoff retries for order and listing events.",
        "body": [
            "Campus bookstore and student-org partners can now subscribe "
            "to webhook notifications for order and listing events, "
            "configurable with either a fixed-interval or "
            "exponential-backoff retry policy, up to a maximum of 10 "
            "attempts over 24 hours. Previously every endpoint used the "
            "same fixed 5-retry schedule.",
            "This is especially useful for partners who occasionally get "
            "overwhelmed during add/drop week -- an exponential backoff "
            "gives their systems more room to recover before the next "
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
