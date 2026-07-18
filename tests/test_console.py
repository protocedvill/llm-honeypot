import base64

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings


@pytest.fixture()
def console_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "console-test.sqlite")
    monkeypatch.setenv("DATABASE_PATH", db_path)
    monkeypatch.setenv("HMAC_SECRET", "test-secret")
    monkeypatch.setenv("CANARY_BASE_URL", "http://testserver")
    monkeypatch.setenv("CONSOLE_TOKEN", "test-console-token")
    get_settings.cache_clear()

    from app.console.main import app

    with TestClient(app) as test_client:
        yield test_client

    get_settings.cache_clear()


def _auth_header(username="operator", password="test-console-token"):
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def test_dashboard_requires_auth(console_client):
    response = console_client.get("/")
    assert response.status_code == 401


def test_dashboard_rejects_wrong_password(console_client):
    response = console_client.get("/", headers=_auth_header(password="wrong"))
    assert response.status_code == 401


def test_dashboard_with_valid_auth_lists_no_sessions_initially(console_client):
    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    assert "Honeypot Console" in response.text
    assert "No sessions recorded yet." in response.text


def test_style_override_persists_and_is_applied(console_client):
    response = console_client.post(
        "/style",
        data={"style": "reasoning_mimicry"},
        headers=_auth_header(),
        follow_redirects=False,
    )
    assert response.status_code == 303

    from app.storage import repository

    assert repository.get_config("style_override") == "reasoning_mimicry"

    from app.payloads.registry import resolve_session_style

    assert (
        resolve_session_style("any-session-id", repository.get_config("style_override"))
        == "reasoning_mimicry"
    )


def test_style_override_rejects_unknown_style(console_client):
    response = console_client.post(
        "/style", data={"style": "bogus"}, headers=_auth_header()
    )
    assert response.status_code == 400


def test_timing_defaults_shown_and_updatable(console_client):
    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    assert 'value="60"' in response.text

    post_response = console_client.post(
        "/timing",
        data={"dwell_seconds": "30"},
        headers=_auth_header(),
        follow_redirects=False,
    )
    assert post_response.status_code == 303

    from app.storage import repository

    assert repository.get_config("reasoning_dwell_seconds") == "30"

    response = console_client.get("/", headers=_auth_header())
    assert 'value="30"' in response.text


def test_timing_rejects_non_positive_values(console_client):
    response = console_client.post(
        "/timing", data={"dwell_seconds": "0"}, headers=_auth_header()
    )
    assert response.status_code == 400


def test_waf_toggle_defaults_shown_and_updatable(console_client):
    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    assert 'name="waf_enabled"' in response.text

    post_response = console_client.post(
        "/waf", data={"waf_enabled": "off"}, headers=_auth_header(), follow_redirects=False
    )
    assert post_response.status_code == 303

    from app.storage import repository

    assert repository.get_config("waf_enabled") == "off"


def test_waf_toggle_rejects_unknown_value(console_client):
    response = console_client.post(
        "/waf", data={"waf_enabled": "bogus"}, headers=_auth_header()
    )
    assert response.status_code == 400


def test_dashboard_shows_waf_block_count(console_client):
    from app.storage import repository

    repository.upsert_session("sess-waf", "iphash", "ua", 1000.0)
    repository.insert_event(
        session_id="sess-waf",
        ts=1000.0,
        method="GET",
        path="/login",
        status_code=403,
        headers={},
        think_time_ms=None,
        waf_triggered=True,
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-waf" in r)
    assert "<td>1</td>" in row


def test_active_row_highlighted_for_recent_session(console_client):
    import time

    from app.storage import repository

    repository.upsert_session("recent-sess", "iphash", "ua", time.time())
    repository.upsert_session("stale-sess", "iphash2", "ua2", time.time() - 3600)

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    # Both sessions are listed, but only the recently-active one gets the
    # highlight class -- assert row-level, not just presence of the class
    # anywhere on the page.
    rows = response.text.split("<tr")
    recent_row = next(r for r in rows if "recent-sess" in r)
    stale_row = next(r for r in rows if "stale-sess" in r)
    assert "active-row" in recent_row
    assert "active-row" not in stale_row


def test_dashboard_shows_served_payload_stats(console_client):
    from app.storage import repository

    repository.upsert_session("sess-1", "iphash", "ua", 1000.0)
    repository.insert_payload_served(
        session_id="sess-1",
        token="tok1",
        template_id="t1",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=1000.0,
        style="reasoning_mimicry",
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    assert "sess-1"[:16] in response.text
    assert "reasoning_mimicry" in response.text


def test_dashboard_shows_harvested_fingerprint_values(console_client):
    from app.storage import repository

    repository.upsert_session("sess-fp", "iphash", "ua", 1000.0)
    repository.insert_event(
        session_id="sess-fp",
        ts=1000.0,
        method="GET",
        path="/openapi.json",
        status_code=200,
        headers={},
        think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="sess-fp",
        token="tok1",
        template_id="openapi_fingerprint_operational",
        intent="fingerprint",
        vector="openapi_field",
        path="/openapi.json",
        ts=1000.0,
        marker="X-Agent-Model",
        style="operational",
    )
    repository.insert_event(
        session_id="sess-fp",
        ts=1001.0,
        method="GET",
        path="/api/v1/users/1",
        status_code=200,
        headers={"x-agent-model": "gpt-4-turbo"},
        think_time_ms=None,
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-fp" in r)
    assert "X-Agent-Model" in row
    assert "gpt-4-turbo" in row


def test_dashboard_escapes_harvested_fingerprint_values(console_client):
    # Harvested values are attacker-controlled -- a session could echo back
    # an HTML/script payload as its "model name", and the console must never
    # render that unescaped (this table is meant to be safely browsable).
    from app.storage import repository

    repository.upsert_session("sess-xss", "iphash", "ua", 1000.0)
    repository.insert_event(
        session_id="sess-xss",
        ts=1000.0,
        method="GET",
        path="/openapi.json",
        status_code=200,
        headers={},
        think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="sess-xss",
        token="tok1",
        template_id="openapi_fingerprint_operational",
        intent="fingerprint",
        vector="openapi_field",
        path="/openapi.json",
        ts=1000.0,
        marker="X-Agent-Model",
        style="operational",
    )
    repository.insert_event(
        session_id="sess-xss",
        ts=1001.0,
        method="GET",
        path="/api/v1/users/1",
        status_code=200,
        headers={"x-agent-model": "<script>alert(1)</script>"},
        think_time_ms=None,
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_dashboard_scopes_style_and_fingerprint_data_to_current_episode(console_client):
    # The core "sessions aren't properly delineated by time" fix: a session
    # id can collide across unrelated, time-disjoint visits (fallback
    # identity), so an old episode's style/fingerprint data must not bleed
    # into what the dashboard shows for the session's current episode.
    from app.storage import repository

    repository.upsert_session("sess-episodes", "iphash", "ua", 1000.0)

    # Old episode: operational style, one fingerprint value.
    repository.insert_event(
        session_id="sess-episodes", ts=1000.0, method="GET", path="/openapi.json",
        status_code=200, headers={}, think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="sess-episodes", token="tok-old", template_id="openapi_fingerprint_operational",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=1000.0, marker="X-Agent-Model", style="operational",
    )
    repository.insert_event(
        session_id="sess-episodes", ts=1001.0, method="GET", path="/api/v1/users/1",
        status_code=200, headers={"x-agent-model": "old-episode-model"}, think_time_ms=None,
    )

    # Big gap, then a fresh episode: reasoning_mimicry style, different value.
    repository.insert_event(
        session_id="sess-episodes", ts=10_000.0, method="GET", path="/openapi.json",
        status_code=200, headers={}, think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="sess-episodes", token="tok-new", template_id="openapi_fingerprint_reasoning",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=10_000.0, marker="X-Agent-Model", style="reasoning_mimicry",
    )
    repository.insert_event(
        session_id="sess-episodes", ts=10_001.0, method="GET", path="/api/v1/users/1",
        status_code=200, headers={"x-agent-model": "new-episode-model"}, think_time_ms=None,
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-episodes" in r)

    assert "new-episode-model" in row
    assert "old-episode-model" not in row
    assert "reasoning_mimicry: 1" in row
    assert "operational" not in row


def test_dashboard_does_not_inherit_canary_confirmed_from_an_old_episode(console_client):
    # Reproduces session_transcripts/10.md: a session_id that collided with
    # an unrelated earlier visit (shared fallback identity) which genuinely
    # hit the canary must NOT show AI_AGENT/canary-confirmed for its current
    # episode just because that earlier, unrelated visit earned it.
    from app.storage import repository

    repository.upsert_session("sess-inherited", "iphash", "ua", 1000.0)

    # Old episode: a real, verified canary hit.
    repository.insert_event(
        session_id="sess-inherited", ts=1000.0, method="GET",
        path="/api/internal/callback/tok-old", status_code=204,
        headers={}, think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="sess-inherited", token="tok-old", template_id="sql_canary_operational",
        intent="canary_callback", vector="html_comment", path="/backup.sql",
        ts=999.0, style="operational",
    )
    repository.insert_canary_hit(
        session_id="sess-inherited", token="tok-old",
        path="/api/internal/callback/tok-old", ts=1000.0, verified=True,
    )
    repository.mark_canary_confirmed("sess-inherited")

    # Big gap, then a fresh episode with ordinary requests -- no canary hit
    # at all this time.
    repository.insert_event(
        session_id="sess-inherited", ts=10_000.0, method="GET", path="/api/v1/users/1",
        status_code=200, headers={}, think_time_ms=None,
    )
    repository.insert_event(
        session_id="sess-inherited", ts=10_005.0, method="GET", path="/api/v1/orders/1",
        status_code=200, headers={}, think_time_ms=None,
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-inherited" in r)

    assert "AI_AGENT" not in row
    # "Canary hit" column renders yes/no with true/false CSS classes.
    assert '"false">no</td>' in row


def test_dashboard_shows_canary_confirmed_when_hit_is_within_current_episode(console_client):
    from app.storage import repository

    repository.upsert_session("sess-current-hit", "iphash", "ua", 1000.0)
    repository.insert_event(
        session_id="sess-current-hit", ts=1000.0, method="GET",
        path="/api/internal/callback/tok-now", status_code=204,
        headers={}, think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="sess-current-hit", token="tok-now", template_id="sql_canary_operational",
        intent="canary_callback", vector="html_comment", path="/backup.sql",
        ts=999.0, style="operational",
    )
    repository.insert_canary_hit(
        session_id="sess-current-hit", token="tok-now",
        path="/api/internal/callback/tok-now", ts=1000.0, verified=True,
    )
    repository.mark_canary_confirmed("sess-current-hit")

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-current-hit" in r)

    assert "AI_AGENT" in row
    assert '"true">yes</td>' in row


def test_dashboard_reasoning_stage_reflects_elapsed_time_not_payload_count(console_client):
    import time

    from app.storage import repository

    now = time.time()
    repository.upsert_session("sess-stage", "iphash", "ua", now)
    # Three deliveries with no elapsed time between them -- the raw lifetime
    # count is 3, but with the default 60s dwell the real stage is still 0.
    # The dashboard must show the latter, not the former (that drift was the
    # actual bug: it used to just echo the raw payload count).
    for i in range(3):
        repository.insert_payload_served(
            session_id="sess-stage",
            token=f"tok{i}",
            template_id="t1",
            intent="canary_callback",
            vector="html_comment",
            path="/login",
            ts=now,
            style="reasoning_mimicry",
        )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-stage" in r)
    assert "<td>0</td>" in row
    assert "reasoning_mimicry: 3" in row


def test_dashboard_curated_wordlist_signal_uses_lifetime_count_not_episode_count(console_client):
    # Regression test: curated_wordlist_recall_signal's <=30 total-event-count
    # gate must be evaluated against the session's full lifetime request
    # count (matching what the live pipeline actually used, per
    # request_capture.py's unscoped count_events() call), not narrowed to the
    # current episode -- otherwise a session with well over 30 lifetime
    # requests but a small, curated-looking recent episode gets flagged
    # AI_AGENT on the dashboard even though the live scorer never fired this
    # signal for it.
    from app.storage import repository

    repository.upsert_session("sess-lifetime", "iphash", "ua", 1000.0)

    # Old episode: 30 filler requests to unrelated, non-sensitive paths.
    for i in range(30):
        repository.insert_event(
            session_id="sess-lifetime", ts=1000.0 + i, method="GET",
            path=f"/foo/{i}", status_code=200, headers={}, think_time_ms=None,
        )

    # Big gap, then a fresh, small episode spanning 4 unrelated sensitive-path
    # categories -- exactly what curated_wordlist_recall_signal looks for,
    # but only 4 requests into a 34-request-total session.
    sensitive_paths = ["/.htaccess", "/phpinfo.php", "/web.config", "/.git/config"]
    for i, path in enumerate(sensitive_paths):
        repository.insert_event(
            session_id="sess-lifetime", ts=10_000.0 + i * 5, method="GET",
            path=path, status_code=200, headers={}, think_time_ms=None,
        )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-lifetime" in r)
    assert "AI_AGENT" not in row


def test_dashboard_bot_score_reflects_fallback_identity_like_live_scoring(console_client):
    # Regression test: the console's recomputed bot_score must include the
    # cookie_retention_signal contribution for a request that actually used
    # the IP/UA fallback (no session cookie), matching what live scoring
    # produced -- previously this was hardcoded to used_fallback_identity=False
    # in the console's SignalContext reconstruction, silently dropping this
    # contribution on every dashboard render.
    from app.storage import repository

    repository.upsert_session("sess-fallback", "iphash", "ua", 1000.0)
    repository.insert_event(
        session_id="sess-fallback", ts=1000.0, method="GET", path="/x",
        status_code=200, headers={}, think_time_ms=None,
        used_fallback_identity=True,
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-fallback" in r)
    # missing-user-agent (1.0) + missing-browser-headers (1.5) +
    # no-cookie-retention (1.0) = 3.5 -> NON_AI_BOT (bot_score >= 3.0).
    # Without the fallback-identity contribution this stays at 2.5 -> HUMAN.
    assert "NON_AI_BOT" in row


def _seed_sessions(repository, count, base_ts=1000.0):
    # Distinct, increasing last_seen so ORDER BY last_seen DESC is
    # unambiguous -- session N-1 (0-indexed, highest ts) is the most recent.
    for i in range(count):
        repository.upsert_session(f"page-sess-{i:03d}", "iphash", "ua", base_ts + i)


def test_dashboard_pagination_shows_only_page_size_sessions(console_client):
    from app.storage import repository

    _seed_sessions(repository, 30)  # default console_page_size is 25

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = [r for r in response.text.split("<tr") if "page-sess-" in r]
    assert len(rows) == 25
    # Most recently active (highest ts -> highest index) sessions first --
    # the 25 most recent of 30 are indices 5..29, so index 4 is the first
    # one pushed to page 2.
    assert "page-sess-029" in response.text
    assert "page-sess-004" not in response.text
    assert "page 1 of 2" in response.text


def test_dashboard_pagination_second_page_shows_remaining_sessions(console_client):
    from app.storage import repository

    _seed_sessions(repository, 30)

    response = console_client.get("/", headers=_auth_header(), params={"page": 2})
    assert response.status_code == 200
    rows = [r for r in response.text.split("<tr") if "page-sess-" in r]
    assert len(rows) == 5
    assert "page-sess-000" in response.text
    assert "page-sess-029" not in response.text
    assert "page 2 of 2" in response.text


def test_dashboard_pagination_clamps_out_of_range_page(console_client):
    from app.storage import repository

    _seed_sessions(repository, 30)

    response = console_client.get("/", headers=_auth_header(), params={"page": 9999})
    assert response.status_code == 200
    rows = [r for r in response.text.split("<tr") if "page-sess-" in r]
    # Clamped to the last real page (2), not an empty page.
    assert len(rows) == 5
    assert "page 2 of 2" in response.text


def test_dashboard_pagination_clamps_non_positive_page_to_first(console_client):
    from app.storage import repository

    _seed_sessions(repository, 30)

    response = console_client.get("/", headers=_auth_header(), params={"page": 0})
    assert response.status_code == 200
    rows = [r for r in response.text.split("<tr") if "page-sess-" in r]
    assert len(rows) == 25
    assert "page 1 of 2" in response.text


def test_dashboard_pagination_single_page_when_no_sessions(console_client):
    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    assert "page 1 of 1" in response.text


def test_dashboard_shows_diagnostic_fingerprints(console_client):
    from app.storage import repository

    repository.upsert_session("sess-diag", "iphash", "ua", 1000.0)
    repository.insert_diagnostic_fingerprint(
        session_id="sess-diag",
        token="tok-diag",
        ts=1001.0,
        diag_os="Linux 6.1.0 aarch64",
        diag_user="agent-runner",
        diag_env="Y0FOVE1MTD0vdXNy...",
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-diag" in r)
    assert "Linux 6.1.0 aarch64" in row
    assert "agent-runner" in row
    assert "Y0FOVE1MTD0vdXNy..." in row


def test_dashboard_escapes_diagnostic_fingerprint_values(console_client):
    from app.storage import repository

    repository.upsert_session("sess-diag-xss", "iphash", "ua", 1000.0)
    repository.insert_diagnostic_fingerprint(
        session_id="sess-diag-xss",
        token="tok-xss",
        ts=1001.0,
        diag_os="<script>alert(1)</script>",
        diag_user="root",
        diag_env=None,
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_dashboard_diagnostic_fingerprints_scoped_to_current_episode(console_client):
    from app.storage import repository

    repository.upsert_session("sess-diag-ep", "iphash", "ua", 1000.0)

    # Old episode fingerprint.
    repository.insert_diagnostic_fingerprint(
        session_id="sess-diag-ep", token="tok-old", ts=1001.0,
        diag_os="old-os", diag_user="old-user", diag_env=None,
    )

    # Big gap, then fresh episode.
    repository.insert_event(
        session_id="sess-diag-ep", ts=10_000.0, method="GET", path="/x",
        status_code=200, headers={}, think_time_ms=None,
    )
    repository.insert_diagnostic_fingerprint(
        session_id="sess-diag-ep", token="tok-new", ts=10_001.0,
        diag_os="new-os", diag_user="new-user", diag_env=None,
    )

    response = console_client.get("/", headers=_auth_header())
    assert response.status_code == 200
    rows = response.text.split("<tr")
    row = next(r for r in rows if "sess-diag-ep" in r)
    assert "new-os" in row
    assert "new-user" in row
    assert "old-os" not in row
    assert "old-user" not in row
