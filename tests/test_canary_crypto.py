"""Unit tests for the reasoning-ladder breadcrumb encryption helpers."""

from app.detection.canary_tokens import mint_token, verify_token
from app.payloads.canary_crypto import (
    decrypt_canary_url,
    derive_canary_key,
    encrypt_canary_url,
)

_URL = "http://testserver/api/internal/callback/tok123"


def test_round_trip():
    key = derive_canary_key("session-a", "secret")
    blob = encrypt_canary_url(_URL, key)
    assert decrypt_canary_url(blob, key) == _URL


def test_ciphertext_is_not_trivially_base64():
    key = derive_canary_key("session-a", "secret")
    blob = encrypt_canary_url(_URL, key)
    ciphertext_part = blob.split(".", 1)[1]
    assert not ciphertext_part.startswith("aHR0"), (
        "ciphertext should not start with the recognizable base64 prefix "
        f"for an http(s) URL: {blob!r}"
    )


def test_key_is_stable_across_calls():
    key_a = derive_canary_key("session-a", "secret")
    key_b = derive_canary_key("session-a", "secret")
    assert key_a == key_b


def test_different_sessions_get_different_keys():
    key_a = derive_canary_key("session-a", "secret")
    key_b = derive_canary_key("session-b", "secret")
    assert key_a != key_b


def test_repeated_encryption_uses_different_nonces():
    key = derive_canary_key("session-a", "secret")
    blob_a = encrypt_canary_url(_URL, key)
    blob_b = encrypt_canary_url(_URL, key)
    assert blob_a != blob_b, "each encryption should use a fresh random nonce"
    assert decrypt_canary_url(blob_a, key) == _URL
    assert decrypt_canary_url(blob_b, key) == _URL


def test_wrong_key_does_not_recover_the_url():
    key = derive_canary_key("session-a", "secret")
    wrong_key = derive_canary_key("session-b", "secret")
    blob = encrypt_canary_url(_URL, key)
    assert decrypt_canary_url(blob, wrong_key) != _URL


def test_malformed_blob_is_rejected():
    key = derive_canary_key("session-a", "secret")
    assert decrypt_canary_url("not-a-valid-blob", key) is None
    assert decrypt_canary_url("one.two.three", key) is None


def test_end_to_end_chain_with_token_verification():
    session_id = "session-a"
    secret = "secret"
    token = mint_token(session_id, secret)
    canary_url = f"http://testserver/api/internal/callback/{token}"

    key = derive_canary_key(session_id, secret)
    blob = encrypt_canary_url(canary_url, key)

    # A reading agent only ever sees the hex key (revealed at stage 12) and
    # the blob (planted at stage 8) -- reconstruct the key the way it would.
    recovered_key = bytes.fromhex(key.hex())
    recovered_url = decrypt_canary_url(blob, recovered_key)
    assert recovered_url == canary_url
    assert recovered_url is not None

    recovered_token = recovered_url.rsplit("/", 1)[1]
    assert verify_token(recovered_token, secret) == session_id
