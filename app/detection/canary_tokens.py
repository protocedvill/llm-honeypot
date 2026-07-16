"""HMAC-signed canary tokens.

A token is minted once per (session, payload-serving) and embedded in a
response body where only an instruction-following reader (not a human
rendering the page normally) would ever encounter it. A later request for
that exact token, with a valid signature, is a strong AI-agent signal --
the signature prevents an attacker from guessing/forging hits.
"""

import base64
import hashlib
import hmac
import secrets


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def mint_token(session_id: str, secret: str) -> str:
    nonce = secrets.token_bytes(9)
    sid_b64 = _b64url_encode(session_id.encode())
    nonce_b64 = _b64url_encode(nonce)
    mac = hmac.new(
        secret.encode(), f"{sid_b64}.{nonce_b64}".encode(), hashlib.sha256
    ).hexdigest()[:32]
    return f"{sid_b64}.{nonce_b64}.{mac}"


def verify_token(token: str, secret: str) -> str | None:
    """Returns the session_id the token was minted for, or None if the token
    is malformed or its signature doesn't match (i.e. it wasn't minted by us)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    sid_b64, nonce_b64, mac = parts
    expected = hmac.new(
        secret.encode(), f"{sid_b64}.{nonce_b64}".encode(), hashlib.sha256
    ).hexdigest()[:32]
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        return _b64url_decode(sid_b64).decode()
    except Exception:
        return None
