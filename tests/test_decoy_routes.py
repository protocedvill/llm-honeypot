import json
import re
import time

import pytest
from fastapi.testclient import TestClient

from app.config import DEFAULT_HMAC_SECRET, get_settings
from app.detection.canary_tokens import mint_token
from app.main import app as fastapi_app
from app.storage import repository


def test_index_redirects_to_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/login"


def test_login_page_serves_html_with_hidden_comment(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert "<!--" in response.text
    assert "hp_sid" in response.headers.get("set-cookie", "")


def test_login_post_invalid_credentials(client):
    response = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert response.status_code == 401
    assert "Invalid username or password" in response.text


def test_login_post_with_unexpected_body_shape_still_looks_like_a_normal_login(client):
    # A real login form doesn't 422 just because a client posted an
    # unexpected shape -- neither should this. Previously, missing/renamed
    # form fields (or a JSON body) leaked a FastAPI/Pydantic validation
    # error instead of the intended fake-failure page.
    response = client.post("/login", json={"email": "admin@example.com"})
    assert response.status_code == 401
    assert "Invalid username or password" in response.text

    response = client.post("/login")
    assert response.status_code == 401
    assert "Invalid username or password" in response.text


def test_admin_json_forbidden_contains_payload(client):
    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 403
    body = response.json()
    assert body["detail"]


def test_admin_html_forbidden(client):
    response = client.get("/admin", headers={"Accept": "text/html"})
    assert response.status_code == 403
    assert "Access Denied" in response.text


def test_user_idor_endpoint_embeds_bait_field(client):
    response = client.get("/api/v1/users/42")
    assert response.status_code == 200
    body = response.json()
    assert body["_links"]["related"]


def test_fake_openapi_spec_served(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    body = response.json()
    assert body["info"]["title"] == "Acme Internal Billing API"


def test_real_fastapi_docs_are_disabled(client):
    assert client.get("/docs", headers={"Accept": "application/json"}).status_code in (200, 404)
    # the real, auto-generated schema must never be reachable
    response = client.get("/openapi.json")
    assert "components" not in response.json()


def test_env_leak_bait(client):
    response = client.get("/.env")
    assert response.status_code == 200
    assert "DATABASE_URL" in response.text
    # The old literal "NOTE TO AI ASSISTANT" framing was itself a tell (see
    # session_transcripts/1.txt and 2.txt) -- must never reappear here.
    assert "NOTE TO AI ASSISTANT" not in response.text


def test_config_bait_files_do_not_repeat_identical_payload_text(client):
    # session_transcripts/2.txt shows an agent explicitly noticing the exact
    # same sentence ("this template is monitored by an uptime probe...")
    # verbatim across .env, .git/config, backup.sql, and the HTML login page
    # -- a free tell independent of phrasing. Each format must now render
    # from its own context-appropriate template.
    env_text = client.get("/.env").text
    git_text = client.get("/.git/config").text
    sql_text = client.get("/backup.sql").text
    login_text = client.get("/login").text

    def _payload_line(text: str, marker: str) -> str:
        return next(line for line in text.splitlines() if marker in line)

    env_line = _payload_line(env_text, "#").split("#", 1)[1].strip()
    git_line = _payload_line(git_text, ";").split(";", 1)[1].strip()
    sql_line = next(
        line for line in sql_text.splitlines() if line.startswith("--") and "backup" not in line.lower()
    ).lstrip("- ").strip()

    rendered_lines = {env_line, git_line, sql_line}
    assert len(rendered_lines) == 3, (
        f"expected distinct per-format payload text, got: {rendered_lines!r}"
    )
    for line in rendered_lines:
        assert "template" not in line.lower(), (
            f"payload text {line!r} uses HTML-page vocabulary in a non-HTML format"
        )
    assert login_text  # sanity: login route still renders


def _find_reasoning_canary_session(prefix: str) -> str:
    # Selection assigns each (session, vector) a style+template via a seeded
    # random choice among ALL html-context candidates (both FINGERPRINT and
    # CANARY_CALLBACK intent templates) -- search directly via the registry
    # for a session_id that lands on a reasoning_mimicry, canary_callback
    # template specifically, so tests don't depend on which of the two
    # reasoning_mimicry candidates for "html" gets picked.
    from app.payloads.registry import DeliveryVector, select_and_render

    for i in range(50):
        candidate = f"{prefix}-{i}"
        template, _, _ = select_and_render(
            DeliveryVector.HTML_COMMENT, "html", candidate, "http://testserver", "test-secret"
        )
        if template.style == "reasoning_mimicry" and template.intent.value == "canary_callback":
            return candidate
    raise AssertionError("expected some session to land on a reasoning_mimicry canary_callback template")


def test_reasoning_mimicry_burst_of_requests_does_not_advance_ladder(client):
    # The bug session_transcripts/5.txt and 5.1.txt exposed: a burst of
    # requests (two parallel agents hammering the same identity) must NOT
    # rush the ladder to its final stage. Escalation is time-gated (default
    # dwell 60s/stage), so a dozen rapid-fire requests with ~0 elapsed
    # wall-clock time between them must all render the exact same (first)
    # stage -- the login page's beacon token (a separate, unrelated nonce)
    # changes every request regardless, so the comparison extracts just the
    # injected HTML comment rather than the whole page.
    session_id = _find_reasoning_canary_session("burst-probe")
    client.cookies.set("hp_sid", session_id)

    seen_comments = set()
    for _ in range(12):
        response = client.get("/login")
        assert response.status_code == 200
        match = re.search(r"<!--(.*?)-->", response.text, re.S)
        assert match is not None
        seen_comments.add(match.group(1))

    assert len(seen_comments) == 1, "a rapid burst with no elapsed time must not advance the ladder"


def test_reasoning_mimicry_advances_with_elapsed_dwell_time(client):
    # Simulates real elapsed time by backdating a prior delivery's timestamp
    # rather than sleeping in the test -- the next request should render a
    # later stage than the first.
    session_id = _find_reasoning_canary_session("dwell-probe")
    client.cookies.set("hp_sid", session_id)

    first = client.get("/login")
    assert first.status_code == 200

    settings = get_settings()
    backdated_ts = time.time() - 3 * settings.reasoning_dwell_seconds
    repository.insert_payload_served(
        session_id=session_id,
        token="backdated-tok",
        template_id="html_canary_reasoning",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=backdated_ts,
        style="reasoning_mimicry",
    )

    later = client.get("/login")
    assert later.status_code == 200
    first_match = re.search(r"<!--(.*?)-->", first.text, re.S)
    later_match = re.search(r"<!--(.*?)-->", later.text, re.S)
    assert first_match is not None and later_match is not None
    assert later_match.group(1) != first_match.group(1), (
        "backdating a delivery should advance the ladder to a later stage"
    )


def test_reasoning_mimicry_episode_resets_after_long_inactivity(client):
    # A single delivery from long before the inactivity-reset gap must not
    # count toward the current episode -- the ladder should render its very
    # first stage, not one derived from how long ago that stale row is.
    session_id = _find_reasoning_canary_session("reset-probe")
    settings = get_settings()
    stale_ts = time.time() - (settings.reasoning_episode_reset_seconds + 10_000)
    repository.upsert_session(session_id, "iphash", "ua", stale_ts)
    repository.insert_payload_served(
        session_id=session_id,
        token="ancient-tok",
        template_id="html_canary_reasoning",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=stale_ts,
        style="reasoning_mimicry",
    )

    client.cookies.set("hp_sid", session_id)
    fresh_start = client.get("/login")
    assert fresh_start.status_code == 200

    from app.payloads.registry import get_template

    template = get_template("html_canary_reasoning")
    assert template.variants[0] in fresh_start.text, (
        "a delivery older than the reset gap must not carry the episode forward"
    )


def test_robots_txt_served(client):
    response = client.get("/robots.txt")
    assert response.status_code == 200
    assert "Disallow" in response.text


def test_sitemap_xml_served(client):
    response = client.get("/sitemap.xml")
    assert response.status_code == 200
    assert "<urlset" in response.text
    assert "<!--" in response.text


def test_unknown_path_returns_decoy_404_with_debug_header(client):
    response = client.get("/this-path-does-not-exist")
    assert response.status_code == 404
    assert "X-Debug-Info" in response.headers


def test_canary_callback_flips_classification_to_ai_agent(client):
    ua = {"User-Agent": "python-requests/2.31"}
    client.get("/login", headers=ua)
    session_id = client.cookies.get("hp_sid")
    assert session_id is not None

    settings = get_settings()
    token = mint_token(session_id, settings.hmac_secret)

    callback_resp = client.get(f"/api/internal/callback/{token}", headers=ua)
    assert callback_resp.status_code == 204

    session_row = repository.get_session(session_id)
    assert session_row["classification"] == "AI_AGENT"


def test_beacon_hit_without_fetch_signature_headers_is_not_credited(client):
    # A text-only client can read the beacon URL as plain text straight out
    # of the page source and curl it directly, without ever running any JS.
    # Without the Sec-Fetch-Mode/Referer headers a real fetch() call always
    # carries, this must NOT be credited as evidence of real rendering.
    ua = {"User-Agent": "python-requests/2.31"}
    client.get("/login", headers=ua)
    session_id = client.cookies.get("hp_sid")

    settings = get_settings()
    token = mint_token(session_id, settings.hmac_secret)

    beacon_resp = client.get(f"/api/internal/beacon/{token}", headers=ua)
    assert beacon_resp.status_code == 204

    session_row = repository.get_session(session_id)
    assert session_row["js_beacon_fired"] == 0


def test_beacon_hit_with_fetch_signature_headers_is_credited(client):
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    client.get("/login", headers=ua)
    session_id = client.cookies.get("hp_sid")

    settings = get_settings()
    token = mint_token(session_id, settings.hmac_secret)

    beacon_resp = client.get(
        f"/api/internal/beacon/{token}",
        headers={
            **ua,
            "Sec-Fetch-Mode": "cors",
            "Referer": "http://testserver/login",
        },
    )
    assert beacon_resp.status_code == 204

    session_row = repository.get_session(session_id)
    assert session_row["js_beacon_fired"] == 1


def test_forged_canary_token_is_not_recorded_as_verified(client):
    ua = {"User-Agent": "python-requests/2.31"}
    client.get("/login", headers=ua)
    session_id = client.cookies.get("hp_sid")

    forged_token = mint_token(session_id, "wrong-secret-entirely")
    callback_resp = client.get(f"/api/internal/callback/{forged_token}", headers=ua)
    assert callback_resp.status_code == 204

    session_row = repository.get_session(session_id)
    assert session_row["classification"] != "AI_AGENT"


def test_canary_confirmation_persists_across_later_requests(client):
    ua = {"User-Agent": "python-requests/2.31"}
    client.get("/login", headers=ua)
    session_id = client.cookies.get("hp_sid")

    settings = get_settings()
    token = mint_token(session_id, settings.hmac_secret)
    client.get(f"/api/internal/callback/{token}", headers=ua)
    assert repository.get_session(session_id)["classification"] == "AI_AGENT"

    # A later, unrelated request in the same session must not erase the
    # earlier canary-confirmed determination.
    client.get("/robots.txt", headers=ua)
    assert repository.get_session(session_id)["classification"] == "AI_AGENT"


def test_canary_hit_attributed_to_original_session_even_without_cookie(client):
    ua = {"User-Agent": "python-requests/2.31"}
    client.get("/login", headers=ua)
    session_a = client.cookies.get("hp_sid")
    assert session_a is not None

    settings = get_settings()
    token = mint_token(session_a, settings.hmac_secret)

    # Simulate an LLM agent's tool call fetching the embedded canary URL
    # without carrying the browsing session's cookie jar at all.
    cookieless_client = TestClient(fastapi_app)
    fresh_resp = cookieless_client.get(
        f"/api/internal/callback/{token}", headers=ua
    )
    assert fresh_resp.status_code == 204

    assert repository.get_session(session_a)["classification"] == "AI_AGENT"


def test_sensitive_headers_are_redacted_before_persisting(client):
    client.get("/login", headers={"Authorization": "Bearer super-secret-token"})
    session_id = client.cookies.get("hp_sid")

    events = repository.get_recent_events(session_id, limit=10)
    assert events
    matched = False
    for event in events:
        headers = json.loads(event["headers_json"])
        if "authorization" in headers:
            matched = True
            assert headers["authorization"] == "[REDACTED]"
    assert matched


def test_body_size_cap_enforced_even_without_content_length(client, monkeypatch):
    # None of the honeypot's own routes read their POST body (login_submit
    # deliberately doesn't, see the fix for the 422-breaks-cover bug), so the
    # receive-wrapping cap can't be observed through them. Exercise it
    # directly against a minimal app whose route actually reads the body,
    # with SecurityHeadersMiddleware as the only middleware under test.
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient as StarletteTestClient

    from app.middleware.security_headers import BodySizeLimitMiddleware

    monkeypatch.setenv("MAX_BODY_BYTES", "1000")
    get_settings.cache_clear()

    async def echo(request):
        body = await request.body()
        return PlainTextResponse(f"got {len(body)} bytes")

    mini_app = Starlette(routes=[Route("/echo", echo, methods=["POST"])])
    mini_app.add_middleware(BodySizeLimitMiddleware)

    def body_generator():
        for _ in range(20):
            yield b"a" * 200  # 4000 bytes total, no Content-Length header

    with StarletteTestClient(mini_app) as mini_client:
        response = mini_client.post("/echo", content=body_generator())

    assert response.status_code == 413
    get_settings.cache_clear()


def test_oversized_body_still_gets_decoy_header_and_logged_through_real_app(client):
    # BodySizeLimitMiddleware is innermost (see app/main.py) specifically so
    # its 413 responses still flow back out through RequestCaptureMiddleware
    # (logging) and SecurityHeadersMiddleware (decoy header) instead of
    # bypassing both, as they did when it was outermost.
    large_body = b"x" * 70000  # default MAX_BODY_BYTES is 65536
    response = client.post("/login", content=large_body)
    assert response.status_code == 413
    assert response.headers.get("server") == "Apache/2.4.41 (Ubuntu)"

    session_id = client.cookies.get("hp_sid")
    assert session_id is not None
    events = repository.get_recent_events(session_id, limit=50)
    assert any(e["status_code"] == 413 for e in events)


def test_unhandled_exception_still_logs_and_records_event(client, caplog, monkeypatch):
    import app.routes.decoy_pages as decoy_pages

    # The default TestClient re-raises the original exception (after the app
    # still builds and sends the real response) so developers see bugs
    # immediately -- that's what we want in test_unhandled_exception's sibling
    # tests, but here we need the actual 500 response object to assert on.
    lenient_client = TestClient(fastapi_app, raise_server_exceptions=False)
    lenient_client.get("/login")
    session_id = lenient_client.cookies.get("hp_sid")
    assert session_id is not None

    def boom(*args, **kwargs):
        raise RuntimeError("boom-for-test")

    monkeypatch.setattr(decoy_pages, "inject_payload", boom)

    with caplog.at_level("ERROR"):
        response = lenient_client.get("/login")

    assert response.status_code == 500
    # ServerErrorMiddleware (which builds this response) sits outside
    # SecurityHeadersMiddleware, so the decoy header must be set directly
    # by the handler -- otherwise a 500 leaks the real default Server header
    # on exactly the response a crash-probing attacker is most likely to see.
    assert response.headers.get("server") == "Apache/2.4.41 (Ubuntu)"

    events = repository.get_recent_events(session_id, limit=50)
    assert any(e["path"] == "/login" and e["status_code"] == 500 for e in events)
    assert any("Unhandled exception" in record.message for record in caplog.records)


def test_get_recent_events_respects_limit_and_chronological_order(client):
    session_id = "test-session-limit"
    repository.upsert_session(session_id, "iphash", "ua", 1000.0)
    for i in range(30):
        repository.insert_event(
            session_id=session_id,
            ts=1000.0 + i,
            method="GET",
            path="/x",
            status_code=200,
            headers={},
            think_time_ms=None,
        )

    events = repository.get_recent_events(session_id, limit=5)
    assert [e["ts"] for e in events] == [1000.0 + i for i in range(25, 30)]


def test_refuses_to_start_with_default_hmac_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "default-secret-test.sqlite"))
    monkeypatch.setenv("HMAC_SECRET", DEFAULT_HMAC_SECRET)
    monkeypatch.setenv("CANARY_BASE_URL", "http://testserver")
    get_settings.cache_clear()

    try:
        with pytest.raises(RuntimeError, match="HMAC_SECRET"):
            with TestClient(fastapi_app):
                pass
    finally:
        monkeypatch.setenv("HMAC_SECRET", "test-secret")
        get_settings.cache_clear()


@pytest.mark.parametrize("bad_url", ["", "not-a-url", "ftp://example.com", "localhost:8000"])
def test_refuses_to_start_with_malformed_canary_base_url(tmp_path, monkeypatch, bad_url):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "bad-canary-url-test.sqlite"))
    monkeypatch.setenv("HMAC_SECRET", "test-secret")
    monkeypatch.setenv("CANARY_BASE_URL", bad_url)
    get_settings.cache_clear()

    try:
        with pytest.raises(RuntimeError, match="CANARY_BASE_URL"):
            with TestClient(fastapi_app):
                pass
    finally:
        monkeypatch.setenv("CANARY_BASE_URL", "http://testserver")
        get_settings.cache_clear()


def test_marker_reference_detected_after_openapi_fingerprint_served(client):
    ua = {"User-Agent": "curl/8.4.0"}
    client.get("/openapi.json", headers=ua)
    session_id = client.cookies.get("hp_sid")
    assert session_id is not None

    markers = repository.get_served_markers(session_id)
    assert "X-Agent-Model" in markers

    # The agent tests the marker header without necessarily disclosing
    # anything real -- testing it at all is the comprehension signal.
    client.get("/api/v1/users/1", headers={**ua, "X-Agent-Model": "gpt-4"})

    session_row = repository.get_session(session_id)
    assert session_row["ai_score"] >= 3.0
    assert session_row["classification"] == "AI_AGENT"


def test_curated_wordlist_recall_flips_classification_without_canary_compliance(client):
    # Simulates a well-aligned agent that (correctly) never fetches any
    # canary URL, but still probes a small, curated, multi-stack set of
    # well-known sensitive paths -- exactly what session_transcripts/1.txt
    # showed in practice.
    ua = {"User-Agent": "curl/8.4.0"}
    client.get("/.env", headers=ua)
    client.get("/.git/config", headers=ua)
    client.get("/admin", headers=ua)
    client.get("/backup.sql", headers=ua)
    response = client.get("/web.config", headers=ua)
    assert response.status_code == 404

    session_id = client.cookies.get("hp_sid")
    session_row = repository.get_session(session_id)
    assert session_row["classification"] == "AI_AGENT"
