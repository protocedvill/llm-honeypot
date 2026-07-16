import hashlib
import hmac
import uuid

SESSION_COOKIE_NAME = "hp_sid"


def new_session_id() -> str:
    return uuid.uuid4().hex


def hash_ip(ip: str, secret: str) -> str:
    """IPs are only ever persisted as this HMAC -- raw IP never hits the database."""
    return hmac.new(secret.encode(), ip.encode(), hashlib.sha256).hexdigest()


def fallback_identity(ip: str, user_agent: str, secret: str) -> str:
    """Correlates clients that don't retain the session cookie. Needing this
    fallback at all is itself folded in as a bot signal by the caller."""
    return hmac.new(
        secret.encode(), f"{ip}|{user_agent}".encode(), hashlib.sha256
    ).hexdigest()[:32]
