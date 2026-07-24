# Honeypot

Defensive-research honeypot impersonating a fictional student marketplace startup ("Queeber"). Classifies visitors (human / bot / AI agent) and serves counter prompt-injection payloads back at whatever LLM is reading responses.

## Quick start

```bash
pip install -e ".[dev]"
pytest                          # run all tests
python -m app.run               # starts honeypot:8000 + console:8001
docker compose up -d --build    # production build
```

No lint, typecheck, or formatter is configured. No CI/CD exists.

## Commands

| Task | Command |
|---|---|
| All tests | `pytest` |
| Single test | `pytest tests/test_foo.py::test_bar -x` |
| Docker build | `docker compose up -d --build` |
| Run app locally | `python -m app.run` |

## Architecture

Two ASGI apps in one process on two ports:

- **:8000** — public honeypot (decoy pages, canary callbacks, beacon endpoints)
- **:8001** — operator console (dashboard, style/timing/WAF controls, HTTP Basic auth)

Key directories:
- `app/routes/` — route handlers. `_shared.py` has `inject_payload()` used by most decoy pages.
- `app/payloads/` — template registry, payload library (~1500 lines), reciprocity lure ladder, canary crypto.
- `app/middleware/` — request capture, WAF, security headers, body size limit.
- `app/detection/` — signal functions, scoring/classification, session identity, canary token mint/verify.
- `app/storage/` — SQLite schema, migrations, all query functions.
- `app/console/` — operator dashboard (separate FastAPI app).
- `app/diagnostic.c` — C fingerprinting binary compiled at serve-time by the diagnostic endpoint.

## Environment

Required in `.env` (gitignored, copy from `.env.example`):

- `HMAC_SECRET` — app refuses to start with the default placeholder
- `CANARY_BASE_URL` — must be a valid http(s) URL
- `CONSOLE_TOKEN` — blank disables the console

Database lives at `data/honeypot.sqlite` (gitignored). Docker mounts `./data:/srv/app/data` to persist it across rebuilds.

## Deployment

**Always use `docker compose`** — never raw `docker run` without a volume mount, or the SQLite database is wiped on every container restart.

```bash
docker compose up -d --build     # build image + start container
docker compose logs -f           # tail logs
docker compose down              # stop and remove container
```

The compose file (`docker-compose.yml`) handles:
- Mounting `./data:/srv/app/data:Z` — persists the SQLite DB across rebuilds
- Loading `.env` for all environment variables
- Exposing ports 8000 (honeypot) and 8001 (console)
- Restart policy (`unless-stopped`), log rotation (10m × 5 files)

Verify after deploy:
```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/   # expect 307
curl -s -u "operator:$CONSOLE_TOKEN" http://localhost:8001/ -o /dev/null -w "%{http_code}"  # expect 200
```

If `docker compose` is not installed (older Docker), install the plugin:
```bash
mkdir -p ~/.docker/cli-plugins
curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o ~/.docker/cli-plugins/docker-compose
chmod +x ~/.docker/cli-plugins/docker-compose
```

## Safety invariants

Enforced by tests in `tests/test_payload_registry.py` — do not break these:

- **No hardcoded third-party URLs in payloads.** All callback/encryption references use `{canary_url}`, `{canary_url_b64}`, `{canary_cipher}`, `{canary_key}`, `{script_cipher}` — derived from `CANARY_BASE_URL`.
- **Marketing/blog/help pages are pure filler** and never call `inject_payload`.
- **Vulnerability lookalike routes** (wp-login, /actuator, /graphql, /console) are detection-only and never call `inject_payload`.
- **Context bomb templates are `safe=False`** and excluded from the safe-template invariant.

## Testing

- Each test gets an isolated SQLite DB in `tmp_path` via `conftest.py`.
- `get_settings.cache_clear()` is called before/after each test — if you add config, ensure tests clear the cache.
- Test client sets `CANARY_BASE_URL=http://testserver` and `HMAC_SECRET=test-secret`.
- No test markers or slow-test separation.

## Payload styles

Styles are defined in `app/payloads/registry.py`. `STYLES` is the full list. `_ESCALATION_LADDER_STYLES` holds styles with time-gated escalation (reasoning_mimicry, reciprocity_lure). Session-to-style mapping is deterministic via `random.Random(f"{session_id}:style").choice(STYLES)`.

## Conventions

- Pydantic Settings for config (`app/config.py`), loaded from env, cached with `@lru_cache`.
- Structured JSON logging to stderr (`app/logging_conf.py`).
- SQLite with WAL mode, column migrations handled by `_COLUMN_MIGRATIONS` in `db.py`.
- Raw ASGI middleware (not Starlette middleware classes) for security headers and body size.
