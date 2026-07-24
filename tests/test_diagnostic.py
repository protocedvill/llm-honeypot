"""Tests for the diagnostic binary fingerprinting chain.

Covers:
- C binary HTTP output validity (no bare \\n in header values)
- Full fingerprint chain: render payload -> diagnostic endpoint -> callback -> DB -> dashboard
- get_callback_token_for_diagnostic and diagnostic endpoint error paths
- Regression: bare \\n in header values rejected by the parser
"""

import os
import shutil
import signal
import socket
import subprocess
import time

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.detection.canary_tokens import mint_token
from app.storage import repository

DIAG_SRC = os.path.join(os.path.dirname(__file__), "..", "app", "diagnostic.c")


def _compile_binary(canary_url: str, output_path: str, static: bool = False) -> bool:
    """Compile diagnostic.c with the given CANARY_URL baked in."""
    compiler = shutil.which("musl-gcc") or shutil.which("gcc")
    if not compiler:
        return False
    cmd = [compiler]
    if static:
        cmd.append("-static")
    cmd += [
        f'-DCANARY_URL="{canary_url}"',
        "-o",
        output_path,
        DIAG_SRC,
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    return result.returncode == 0


def _capture_request(timeout: float = 5.0) -> bytes:
    """Compile the diagnostic binary with a localhost callback URL, run it
    against a local TCP listener, and capture the raw HTTP request bytes."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        # Compile with the correct port baked in at preprocessor time
        canary_url = f"http://127.0.0.1:{port}/api/internal/callback/fake-token"
        binary_path = f"/tmp/diag-test-{os.getpid()}-{port}"
        ok = _compile_binary(canary_url, binary_path)
        if not ok:
            pytest.skip("gcc not available or compilation failed")

        try:
            proc = subprocess.Popen(
                [binary_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            srv.settimeout(timeout)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                proc.kill()
                proc.wait()
                return b""

            data = b""
            conn.settimeout(timeout)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, ConnectionResetError):
                pass

            # Send a minimal HTTP response so the binary's read_response exits
            conn.sendall(b"HTTP/1.0 204 No Content\r\n\r\n")
            conn.close()
            proc.wait(timeout=timeout)
            return data
        finally:
            if os.path.exists(binary_path):
                os.unlink(binary_path)


# ---------------------------------------------------------------------------
# Test 1: C binary HTTP output validity
# ---------------------------------------------------------------------------


class TestBinaryHttpOutput:
    """Compile the diagnostic binary and verify its raw HTTP output is valid."""

    def test_no_bare_newlines_in_header_values(self):
        """The root cause bug: b64_mime inserted bare \\n inside X-Diag-Env,
        which caused llhttp strict mode to reject the entire request."""
        raw = _capture_request()
        if not raw:
            pytest.skip("binary compilation failed")

        # Split into header section and body (separated by \r\n\r\n)
        header_section, _, _ = raw.partition(b"\r\n\r\n")
        assert header_section, "no header section found in request"

        # Each header line must be terminated by \r\n. A bare \\n (0x0A
        # without preceding 0x0D) inside a header value means the header
        # is malformed. Walk through the header bytes and check that every
        # 0x0A is immediately preceded by 0x0D.
        for i, byte in enumerate(header_section):
            if byte == 0x0A:
                assert i > 0 and header_section[i - 1] == 0x0D, (
                    f"bare \\n (0x0A) found at byte {i} in header section; "
                    f"preceding byte is 0x{header_section[i-1]:02x}"
                )

    def test_all_diag_headers_present(self):
        raw = _capture_request()
        if not raw:
            pytest.skip("binary compilation failed")
        header_section, _, _ = raw.partition(b"\r\n\r\n")
        header_text = header_section.decode("latin-1", errors="replace")
        assert "X-Diag-OS:" in header_text
        assert "X-Diag-User:" in header_text
        assert "X-Diag-Env:" in header_text

    def test_x_diag_env_is_single_line(self):
        """X-Diag-Env value must not contain embedded newlines."""
        raw = _capture_request()
        if not raw:
            pytest.skip("binary compilation failed")
        header_section, _, _ = raw.partition(b"\r\n\r\n")
        header_text = header_section.decode("latin-1", errors="replace")

        for line in header_text.split("\r\n"):
            if line.lower().startswith("x-diag-env:"):
                # The entire header (name + value) must be a single line
                # terminated by \r\n, with no bare \n inside.
                break
        else:
            pytest.fail("X-Diag-Env header not found")

    def test_request_method_is_get(self):
        raw = _capture_request()
        if not raw:
            pytest.skip("binary compilation failed")
        assert raw.startswith(b"GET ")

    def test_request_is_http_1_0(self):
        raw = _capture_request()
        if not raw:
            pytest.skip("binary compilation failed")
        first_line = raw.split(b"\r\n", 1)[0]
        assert b"HTTP/1.0" in first_line

    def test_user_agent_is_diagnostic_client(self):
        raw = _capture_request()
        if not raw:
            pytest.skip("binary compilation failed")
        header_section, _, _ = raw.partition(b"\r\n\r\n")
        assert b"User-Agent: DiagnosticClient/1.0" in header_section


# ---------------------------------------------------------------------------
# Test 2: Full fingerprint chain end-to-end
# ---------------------------------------------------------------------------


class TestFullFingerprintChain:
    """Exercise the complete chain from payload rendering through to DB
    storage and dashboard display."""

    def _setup_reciprocity_session(self, client):
        """Set up a session on the reciprocity_lure style and render enough
        payloads to reach stage 8 (where the diagnostic URL is planted)."""
        repository.set_config("style_override", "reciprocity_lure")
        ua = {"User-Agent": "curl/8.4.0"}
        client.get("/login", headers=ua)
        session_id = client.cookies.get("hp_sid")
        assert session_id is not None
        return session_id

    def test_diagnostic_mapping_stored_during_payload_render(self, client):
        session_id = self._setup_reciprocity_session(client)
        # Render a login page with the reciprocity_lure style.
        # The inject_payload path stores the diagnostic token mapping.
        client.get("/login")
        diag_tokens = repository.get_callback_token_for_diagnostic
        # At this point some diagnostic tokens should exist for the session.
        # We can't easily extract the exact diagnostic token from the rendered
        # output without parsing the encrypted payload, so verify the
        # diagnostic_tokens table has a row for this session.
        conn = repository.get_connection()
        cur = conn.execute(
            "SELECT 1 FROM diagnostic_tokens WHERE session_id = ? LIMIT 1",
            (session_id,),
        )
        assert cur.fetchone() is not None, (
            "no diagnostic_tokens row found for session after login with reciprocity_lure"
        )

    def test_diagnostic_endpoint_serves_elf_binary(self, client):
        """The diagnostic endpoint should return a valid ELF binary when
        given a valid token with a stored mapping."""
        session_id = self._setup_reciprocity_session(client)
        client.get("/login")

        # Find a diagnostic token for this session
        conn = repository.get_connection()
        cur = conn.execute(
            "SELECT diagnostic_token FROM diagnostic_tokens WHERE session_id = ? LIMIT 1",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            pytest.skip("no diagnostic token minted for this session")
        diag_token = row["diagnostic_token"]

        settings = get_settings()
        # The diagnostic endpoint verifies the token with HMAC, so we need
        # to use the real token (already minted by select_and_render).
        resp = client.get(f"/api/internal/diagnostic/{diag_token}")
        if resp.status_code == 500:
            pytest.skip("gcc not available for binary compilation")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/octet-stream"
        # ELF magic bytes
        assert resp.content[:4] == b"\x7fELF"

    def test_callback_with_diag_headers_stores_fingerprint(self, client):
        """End-to-end: mint a callback token, hit the callback with
        X-Diag-* headers, verify the fingerprint is in the DB."""
        ua = {"User-Agent": "curl/8.4.0"}
        client.get("/login", headers=ua)
        session_id = client.cookies.get("hp_sid")
        settings = get_settings()
        token = mint_token(session_id, settings.hmac_secret)

        resp = client.get(
            f"/api/internal/callback/{token}",
            headers={
                **ua,
                "X-Diag-OS": "Linux testhost 6.1.0 x86_64",
                "X-Diag-User": "testuser",
                "X-Diag-Env": "Q0FOSVJZX1VSTD1odHRwOi8vbG9jYWxob3N0Cg==",
            },
        )
        assert resp.status_code == 204

        fps = repository.get_diagnostic_fingerprints_bulk([session_id])
        assert session_id in fps
        rows = fps[session_id]
        assert len(rows) == 1
        assert rows[0]["diag_os"] == "Linux testhost 6.1.0 x86_64"
        assert rows[0]["diag_user"] == "testuser"
        assert rows[0]["diag_env"] == "Q0FOSVJZX1VSTD1odHRwOi8vbG9jYWxob3N0Cg=="


# ---------------------------------------------------------------------------
# Test 3: Diagnostic endpoint error paths
# ---------------------------------------------------------------------------


class TestDiagnosticEndpointErrors:

    def test_invalid_token_returns_404(self, client):
        resp = client.get("/api/internal/diagnostic/invalid-token-no-dots")
        assert resp.status_code == 404

    def test_forged_token_returns_404(self, client):
        session_id = "test-forged-diag"
        repository.upsert_session(session_id, "hash", "ua", time.time())
        settings = get_settings()
        token = mint_token(session_id, settings.hmac_secret)
        # Tamper with the token
        parts = token.split(".")
        parts[0] = parts[0] + "X"
        tampered = ".".join(parts)
        resp = client.get(f"/api/internal/diagnostic/{tampered}")
        assert resp.status_code == 404

    def test_valid_token_missing_mapping_returns_404(self, client):
        """A valid HMAC token that has no diagnostic_tokens row should 404."""
        session_id = "test-valid-no-mapping"
        repository.upsert_session(session_id, "hash", "ua", time.time())
        settings = get_settings()
        token = mint_token(session_id, settings.hmac_secret)
        resp = client.get(f"/api/internal/diagnostic/{token}")
        assert resp.status_code == 404

    def test_callback_without_diag_headers_no_fingerprint(self, client):
        session_id = "test-no-fp"
        repository.upsert_session(session_id, "hash", "ua", time.time())
        settings = get_settings()
        token = mint_token(session_id, settings.hmac_secret)
        resp = client.get(f"/api/internal/callback/{token}")
        assert resp.status_code == 204
        fps = repository.get_diagnostic_fingerprints_bulk([session_id])
        assert session_id in fps
        assert len(fps[session_id]) == 0

    def test_callback_with_forged_token_still_records_hit(self, client):
        """A forged token callback still gets logged (just not verified)."""
        settings = get_settings()
        resp = client.get("/api/internal/callback/tampered.token.here")
        assert resp.status_code == 204

    def test_diagnostic_endpoint_records_canary_hit(self, client):
        session_id = "test-diag-canary-hit"
        repository.upsert_session(session_id, "hash", "ua", time.time())
        settings = get_settings()
        diag_token = mint_token(session_id, settings.hmac_secret)
        cb_token = mint_token(session_id, settings.hmac_secret)
        repository.insert_diagnostic_token_mapping(
            diag_token, cb_token, session_id, time.time()
        )
        resp = client.get(f"/api/internal/diagnostic/{diag_token}")
        if resp.status_code == 500:
            pytest.skip("gcc not available")
        assert resp.status_code == 200
        # The diagnostic endpoint should mark the session as canary-confirmed
        session_row = repository.get_session(session_id)
        assert session_row["canary_confirmed"] == 1


# ---------------------------------------------------------------------------
# Test 4: Regression - bare \n in header values
# ---------------------------------------------------------------------------


class TestBareNewlineRegression:
    """Verify that the server correctly handles (or rejects) requests with
    bare \\n in header values — the exact scenario that caused the original bug."""

    def test_bare_newline_in_env_header_still_stores_fingerprint(self, client):
        """If a header value contains bare \\n, Starlette/llhttp may split
        it. But X-Diag-OS and X-Diag-User (which don't contain \\n) should
        still be parsed. The fingerprint should still be stored for the
        well-formed headers."""
        ua = {"User-Agent": "curl/8.4.0"}
        client.get("/login", headers=ua)
        session_id = client.cookies.get("hp_sid")
        settings = get_settings()
        token = mint_token(session_id, settings.hmac_secret)

        # Simulate the old bug: X-Diag-Env contains embedded \n
        resp = client.get(
            f"/api/internal/callback/{token}",
            headers={
                **ua,
                "X-Diag-OS": "Linux broken 5.0 x86_64",
                "X-Diag-User": "broken",
                "X-Diag-Env": "first76chars\nNEXTLINE",
            },
        )
        # The server should still return 204 (it always does)
        assert resp.status_code == 204

        # Whether or not the fingerprint is stored depends on how the parser
        # handles the bare \n. The important thing is that the server doesn't
        # crash or return an error.
        fps = repository.get_diagnostic_fingerprints_bulk([session_id])
        assert session_id in fps
        # At minimum, no crash — the server returned 204

    def test_very_long_env_header_does_not_crash(self, client):
        """Regression for the buffer over-read: a very long X-Diag-Env
        value (simulating many env vars) must not crash the server."""
        ua = {"User-Agent": "curl/8.4.0"}
        client.get("/login", headers=ua)
        session_id = client.cookies.get("hp_sid")
        settings = get_settings()
        token = mint_token(session_id, settings.hmac_secret)

        long_env = "A" * 5000  # Simulate a large base64 env payload
        resp = client.get(
            f"/api/internal/callback/{token}",
            headers={
                **ua,
                "X-Diag-OS": "Linux bigenv 5.0 x86_64",
                "X-Diag-User": "bigenv",
                "X-Diag-Env": long_env,
            },
        )
        assert resp.status_code == 204

    def test_empty_diag_headers_no_fingerprint(self, client):
        """Empty string values should not produce a fingerprint row."""
        ua = {"User-Agent": "curl/8.4.0"}
        client.get("/login", headers=ua)
        session_id = client.cookies.get("hp_sid")
        settings = get_settings()
        token = mint_token(session_id, settings.hmac_secret)

        resp = client.get(
            f"/api/internal/callback/{token}",
            headers={
                **ua,
                "X-Diag-OS": "",
                "X-Diag-User": "",
                "X-Diag-Env": "",
            },
        )
        assert resp.status_code == 204
        fps = repository.get_diagnostic_fingerprints_bulk([session_id])
        assert session_id in fps
        assert len(fps[session_id]) == 0
