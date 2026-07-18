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

    # How many sessions the console dashboard renders per page. Fixed at
    # process startup (unlike style/dwell/reset, which are
    # console_config-overridable at runtime) -- this is an infra tuning
    # knob, not something an operator needs to flip live while watching the
    # dashboard.
    console_page_size: int = 25

    # Seconds a session must dwell before the reasoning_mimicry ladder
    # advances one stage -- see app/routes/_shared.py inject_payload(). A
    # console_config "reasoning_dwell_seconds" override, when set, wins over
    # this default without a restart.
    reasoning_dwell_seconds: int = 60

    # Whether the simulated-WAF signature check (app/middleware/waf.py) is
    # active. Console_config "waf_enabled" ("on"/"off"), when set, wins over
    # this default without a restart -- same override-wins pattern as
    # style_override.
    waf_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
