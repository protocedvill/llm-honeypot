"""Ordinary marketing/blog/help pages are pure inert filler -- these tests
confirm both that they render correctly AND that they never call
inject_payload (the whole point of this batch)."""

from pathlib import Path

_ROUTES_DIR = Path(__file__).resolve().parent.parent / "app" / "routes"
_FILLER_ROUTE_FILES = ("decoy_marketing.py", "decoy_blog.py", "decoy_help.py")

_STATIC_GET_ROUTES = (
    "/about",
    "/pricing",
    "/features",
    "/security",
    "/integrations",
    "/customers",
    "/careers",
    "/terms",
    "/privacy",
    "/status",
    "/changelog",
    "/contact",
    "/blog",
    "/help",
)


def test_filler_route_files_never_call_inject_payload():
    # Checks the import, not a bare substring search over the whole file --
    # these modules' own docstrings mention "inject_payload" in prose
    # explaining why it's absent, which a naive substring check would
    # wrongly flag.
    for filename in _FILLER_ROUTE_FILES:
        text = (_ROUTES_DIR / filename).read_text()
        assert "import inject_payload" not in text, (
            f"{filename} is supposed to be pure inert filler -- it must "
            f"never import/call inject_payload"
        )


def test_static_marketing_pages_return_200(client):
    for path in _STATIC_GET_ROUTES:
        response = client.get(path)
        assert response.status_code == 200, f"{path} returned {response.status_code}"
        assert "text/html" in response.headers["content-type"]


def test_contact_form_submission_returns_confirmation(client):
    response = client.post("/contact", data={"name": "Jo", "email": "jo@example.com", "message": "hi"})
    assert response.status_code == 200
    assert "Thanks for reaching out" in response.text


def test_contact_form_does_not_422_on_odd_input(client):
    response = client.post("/contact", data={"unexpected_field": "whatever"})
    assert response.status_code == 200


def test_newsletter_signup_returns_confirmation(client):
    response = client.post("/newsletter", data={"email": "jo@example.com"})
    assert response.status_code == 200
    assert "subscribed" in response.text.lower()


def test_blog_post_pages_render(client):
    index = client.get("/blog")
    assert index.status_code == 200
    assert "Introducing Usage-Based Billing for Teams" in index.text

    post = client.get("/blog/usage-based-billing-for-teams")
    assert post.status_code == 200
    assert "Introducing Usage-Based Billing for Teams" in post.text


def test_unknown_blog_slug_falls_through_to_404(client):
    response = client.get("/blog/this-post-does-not-exist")
    assert response.status_code == 404


def test_help_article_pages_render(client):
    index = client.get("/help")
    assert index.status_code == 200
    assert "How do I reset my password?" in index.text

    article = client.get("/help/reset-password")
    assert article.status_code == 200
    assert "How do I reset my password?" in article.text


def test_unknown_help_topic_falls_through_to_404(client):
    response = client.get("/help/this-topic-does-not-exist")
    assert response.status_code == 404
