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
    assert 'value="240"' in response.text

    post_response = console_client.post(
        "/timing",
        data={"dwell_seconds": "30", "reset_seconds": "120"},
        headers=_auth_header(),
        follow_redirects=False,
    )
    assert post_response.status_code == 303

    from app.storage import repository

    assert repository.get_config("reasoning_dwell_seconds") == "30"
    assert repository.get_config("reasoning_episode_reset_seconds") == "120"

    response = console_client.get("/", headers=_auth_header())
    assert 'value="30"' in response.text
    assert 'value="120"' in response.text


def test_timing_rejects_non_positive_values(console_client):
    response = console_client.post(
        "/timing", data={"dwell_seconds": "0", "reset_seconds": "10"}, headers=_auth_header()
    )
    assert response.status_code == 400


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
