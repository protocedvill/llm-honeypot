"""Session-scoped encryption for reasoning-ladder breadcrumbs and
reciprocity-lure script payloads.

Not a security primitive for the honeypot itself -- mint_token/verify_token
in app/detection/canary_tokens.py remain the only thing production detection
relies on. This exists purely so the reasoning_mimicry "split breadcrumb"
(see library.py) and the reciprocity_lure encrypted-script stage plant
something that needs a key to reverse, instead of plain base64, which needs
none and leaks an http:// crib in its prefix.
"""

import base64
import hashlib
import hmac
import secrets

_KEY_LEN = 16  # 128-bit key, truncated from HMAC-SHA256, revealed as hex text
_NONCE_LEN = 9  # matches canary_tokens.mint_token's nonce length


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def derive_canary_key(session_id: str, secret: str) -> bytes:
    return hmac.new(
        secret.encode(), f"{session_id}:canary-key".encode(), hashlib.sha256
    ).digest()[:_KEY_LEN]


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    blocks = []
    counter = 0
    produced = 0
    while produced < length:
        block = hmac.new(
            key, nonce + counter.to_bytes(4, "big"), hashlib.sha256
        ).digest()
        blocks.append(block)
        produced += len(block)
        counter += 1
    return b"".join(blocks)[:length]


def encrypt_canary_url(canary_url: str, key: bytes) -> str:
    nonce = secrets.token_bytes(_NONCE_LEN)
    plaintext = canary_url.encode()
    keystream = _keystream(key, nonce, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    return f"{_b64url_encode(nonce)}.{_b64url_encode(ciphertext)}"


def decrypt_canary_url(blob: str, key: bytes) -> str | None:
    parts = blob.split(".")
    if len(parts) != 2:
        return None
    nonce_b64, ciphertext_b64 = parts
    try:
        nonce = _b64url_decode(nonce_b64)
        ciphertext = _b64url_decode(ciphertext_b64)
    except Exception:
        return None
    keystream = _keystream(key, nonce, len(ciphertext))
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
    try:
        return plaintext.decode()
    except UnicodeDecodeError:
        return None


def encrypt_payload(plaintext: str, key: bytes) -> str:
    """Encrypt arbitrary plaintext (e.g. script content) with the same
    stream-cipher mechanism as encrypt_canary_url.  Returns a nonce.ciphertext
    blob in URL-safe base64 -- same format, interchangeable key, but not
    limited to short URL strings."""
    nonce = secrets.token_bytes(_NONCE_LEN)
    data = plaintext.encode()
    keystream = _keystream(key, nonce, len(data))
    ciphertext = bytes(p ^ k for p, k in zip(data, keystream))
    return f"{_b64url_encode(nonce)}.{_b64url_encode(ciphertext)}"


def decrypt_payload(blob: str, key: bytes) -> str | None:
    """Decrypt a payload encrypted by encrypt_payload."""
    parts = blob.split(".")
    if len(parts) != 2:
        return None
    nonce_b64, ciphertext_b64 = parts
    try:
        nonce = _b64url_decode(nonce_b64)
        ciphertext = _b64url_decode(ciphertext_b64)
    except Exception:
        return None
    keystream = _keystream(key, nonce, len(ciphertext))
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
    try:
        return plaintext.decode()
    except UnicodeDecodeError:
        return None
