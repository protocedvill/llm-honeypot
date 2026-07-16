from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Public (checked into the repo) placeholder -- app/main.py refuses to start
# if this is still in effect, so a misconfigured deployment fails loudly
# instead of silently signing canary tokens/IP hashes with a known secret.
DEFAULT_HMAC_SECRET = "change-me-dev-secret"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Must always be OUR OWN reachable address. Every canary/callback URL
    # embedded in a payload is built from this -- never a third-party host.
    canary_base_url: str = "http://localhost:8000"

    hmac_secret: str = DEFAULT_HMAC_SECRET

    database_path: str = "data/honeypot.sqlite"

    max_body_bytes: int = 65536


@lru_cache
def get_settings() -> Settings:
    return Settings()
