from app.detection.canary_tokens import mint_token, verify_token


def test_round_trip():
    token = mint_token("session-123", "secret-a")
    assert verify_token(token, "secret-a") == "session-123"


def test_tamper_rejected():
    token = mint_token("session-123", "secret-a")
    tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert verify_token(tampered, "secret-a") is None


def test_wrong_secret_rejected():
    token = mint_token("session-123", "secret-a")
    assert verify_token(token, "secret-b") is None


def test_malformed_token_rejected():
    assert verify_token("not-a-valid-token", "secret-a") is None
    assert verify_token("a.b", "secret-a") is None
    assert verify_token("", "secret-a") is None
