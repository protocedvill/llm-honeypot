import hashlib
import hmac
import uuid

SESSION_COOKIE_NAME = "hp_sid"


def new_session_id() -> str:
    return uuid.uuid4().hex


def hash_ip(ip: str, secret: str) -> str:
    """IPs are only ever persisted as this HMAC -- raw IP never hits the database."""
    return hmac.new(secret.encode(), ip.encode(), hashlib.sha256).hexdigest()


def fallback_identity(
    ip: str,
    user_agent: str,
    secret: str,
    accept: str = "",
    accept_language: str = "",
    accept_encoding: str = "",
) -> str:
    """Correlates clients that don't retain the session cookie. Needing this
    fallback at all is itself folded in as a bot signal by the caller.

    Folding in a few more low-entropy request headers is a best-effort
    improvement, not a fix: two invocations of the literal same HTTP client
    library (e.g. two parallel `curl` processes with no cookie jar) still
    send byte-identical headers and are genuinely indistinguishable over
    HTTP -- session_transcripts/5.txt and 5.1.txt confirmed this collapses
    them into one identity. What this does help with is not colliding
    unrelated clients that merely share an IP (different bots/tools behind
    the same NAT, a browser and a script on the same box) into the same
    bucket.
    """
    return hmac.new(
        secret.encode(),
        f"{ip}|{user_agent}|{accept}|{accept_language}|{accept_encoding}".encode(),
        hashlib.sha256,
    ).hexdigest()[:32]
