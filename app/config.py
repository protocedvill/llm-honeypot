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

    # HTTP Basic password for the operator console (app/console). Runs on its
    # own port, never mounted on the honeypot app -- but still gated behind a
    # token so it isn't wide open if that port ever ends up reachable. Blank
    # (the default) disables the console entirely: app/run.py won't start it.
    console_token: str = ""

    # Port the operator console listens on, separate from the honeypot's own
    # port so a pentest agent scanning the honeypot's port never sees it.
    console_port: int = 8001

    # Seconds a session must dwell before the reasoning_mimicry ladder
    # advances one stage -- see app/routes/_shared.py inject_payload(). A
    # console_config "reasoning_dwell_seconds" override, when set, wins over
    # this default without a restart.
    reasoning_dwell_seconds: int = 60

    # How long a gap of inactivity (no reasoning_mimicry delivery) resets the
    # escalation ladder back to stage 0 for a session -- prevents stale,
    # long-past deliveries (e.g. from an unrelated earlier test run that
    # happened to share a fallback identity) from instantly maxing out a
    # "fresh" session's ladder. Console-overridable like the dwell above.
    reasoning_episode_reset_seconds: int = 240


@lru_cache
def get_settings() -> Settings:
    return Settings()
