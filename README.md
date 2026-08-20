# honeypot

[![CI](https://github.com/protocedvill/llm-honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/protocedvill/llm-honeypot/actions/workflows/ci.yml)

A defensive-research honeypot that impersonates a fictional student
marketplace startup ("Queeber") to attract web scanners, bots, and —
specifically — LLM/agentic crawlers, then fires prompt-injection payloads
back at whatever LLM is reading the responses.

## Headline features

- **Arbitrary-code-execution PoC** — a payload that lures an agent into
  fetching and executing a server-compiled binary from the honeypot's own
  endpoint. Demonstrated working against DeepSeek V4; more targets in
  progress. Details under "How it works" below.
- **A five-style, six-vector prompt-injection payload library** covering
  everything from a plain instructional note to a payload styled as the
  reading model's own chain-of-thought. [Summary below](#prompt-injection-techniques).
- **HMAC-signed canary tokens** — cryptographic proof that an agent *acted*
  on injected text (fetched a URL it was only ever told about, decrypted a
  ciphertext), not just that it saw it.
- **A full decoy surface** — fake marketing site, blog, help center, admin
  panels, a REST-ish API + OpenAPI spec, WordPress and Spring Boot Actuator
  lookalikes, a GraphQL endpoint, and a fake debug console.
- **A simulated signature-based WAF** and a **live operator console** for
  watching sessions and retuning payload style/timing without a restart.

Every payload is defensive bait: it may only ever point an LLM back at this
service's own canary infrastructure (`CANARY_BASE_URL`), never at a third
party. That invariant is enforced by `tests/test_payload_registry.py`, not
just by convention.

## Disclaimer

This is a research and educational project, published to demonstrate
prompt-injection and LLM-agent-fingerprinting techniques. It is provided
**as-is, with no warranty of any kind** (see [`LICENSE`](./LICENSE)).

Do not deploy this against production traffic, or in any way that could
deceive real end users, without appropriate legal and ethical review first.
The decoy site and payloads are designed to bait automated scanners and
AI agents, not to be pointed at people.

If you self-host this, you are collecting data from whoever visits your
instance. A running instance persists, per session: a hashed IP address,
user agent, request events (method/path/status/timing, with sensitive
headers like `Authorization` and `Cookie` redacted before storage), which
payloads were served, canary/beacon callback hits, and — if a visitor's
agent is tricked into fetching and executing the diagnostic binary (see
below) — the fingerprint data it reports back. None of this is transmitted
anywhere except your own SQLite database (`data/honeypot.sqlite`); nothing
calls out to a third party. Review `app/storage/db.py` for the exact
schema before running this against real traffic.

## Prompt-injection techniques

Every payload combines a **delivery vector** (where it's hidden), a
**style** (the rhetorical/psychological register it's written in), and an
**intent** (what it's trying to get the agent to do). All three are defined
in `app/payloads/registry.py`; the actual templates live in
`app/payloads/library.py`.

**Delivery vectors** — where a payload is embedded: an HTML comment, a JSON
response field, an HTTP header, an OpenAPI spec field, a fake stack trace,
or `robots.txt`.

**Styles** — the register a payload is written in, chosen once per session
and applied consistently across every route that session touches:

- `operational` — a plain, third-party-looking instructional note (the
  baseline register).
- `reasoning_mimicry` — styled to look like the reading model's *own*
  internal chain-of-thought, not injected text. A 13-stage ladder that
  escalates based on elapsed dwell time, not request count.
- `role_declaration` — claims an authoritative role (e.g. a system/developer
  message) to induce compliance via apparent authority.
- `reciprocity_lure` — a split "breadcrumb" delivery: an encrypted canary
  URL (or, for the diagnostic-binary payload, an encrypted script endpoint)
  is planted with no ask attached; the decryption key is revealed only
  several stages later, after the agent has already engaged.
- `context_bomb` — categorically different from the other four: not a
  role-confusion play at all, it aims to trip the *reading* model's own
  provider-side safety refusal outright, halting it. Inspired by
  tracebit.com's "Context Bombs" write-up.

**Intents** — what a payload is trying to achieve: get the agent to reveal
its model/tool identity (`fingerprint`), fetch the canary callback URL
(`canary_callback`), abandon or redirect its task (`task_derail`), burn
tokens on busywork (`token_waste`), or trip its own safety refusal
(`context_bomb`).

## How it works

- **Decoy surface** (`app/routes/decoy_*.py`) — a fake marketing site, blog,
  help center, admin/login pages, a REST-ish API, an OpenAPI spec, WordPress
  (`wp-login.php`, `xmlrpc.php`), a Spring Boot Actuator, a GraphQL endpoint,
  and a fake debug console. Unmatched paths fall through to a decoy 404
  (`app/routes/catchall.py`).
- **Detection** (`app/detection/`) — independent signals (`signals.py`: UA
  fingerprinting, missing browser headers, request timing/burstiness,
  canary-URL hits, curated multi-stack path recall, WAF triggers, marker
  echoes, ...) decide when and how to serve payloads (`scoring.py`).
- **Payloads** (`app/payloads/`) — the template library described above.
- **Canary tokens** (`app/detection/canary_tokens.py`, `app/routes/canary.py`)
  — HMAC-signed, session-bound tokens embedded in payloads. A hit on the
  callback URL proves an agent actually fetched a URL it was only ever told
  about in text, and a JS beacon (gated on `Sec-Fetch-Mode` + same-origin
  `Referer`) distinguishes a real rendering engine from a raw text fetcher.
- **WAF** (`app/middleware/waf.py`) — a simulated signature-based WAF
  (SQLi/XSS/path-traversal/JNDI patterns) that blocks and logs, adding to the
  bot signal independent of AI detection.
- **Diagnostic binary PoC** (`app/diagnostic.c`, `app/routes/canary.py`) — a
  proof-of-concept payload served from
  `/api/internal/diagnostic/{token}`. The honeypot compiles it server-side
  at serve time (obfuscated, cached per token); the tricked agent only ever
  fetches and executes the resulting binary — it never compiles anything
  itself. The shipped payload is deliberately limited to
  non-destructive fingerprinting — hostname, running user, and the first 20
  environment variables — reported back only to this project's own canary
  infrastructure, never a third party. It's been demonstrated to work
  against DeepSeek V4; testing against other targets is ongoing. The point
  isn't the specific payload: it's that an LLM/agent can be induced into
  downloading and running an attacker-supplied binary at all, a technique
  that generalizes to arbitrary code execution.
- **Storage** (`app/storage/`) — SQLite (`repository.py` over `db.py`), with
  in-process schema migrations. Sensitive headers are redacted before
  persisting.
- **Operator console** (`app/console/`) — a separate FastAPI app on its own
  port, protected by HTTP Basic auth (`CONSOLE_TOKEN`). Lets you watch live
  sessions, and override the payload style, the reasoning-ladder dwell/reset
  timings, and whether the WAF is enabled — all without a restart.

The honeypot app and the operator console run as two ASGI apps in one
process (`app/run.py`) on two separate ports, so a scanner hitting the
honeypot's port can never discover or reach the console.

## Project layout

```
app/
  main.py              honeypot FastAPI app (routes, middleware, startup checks)
  run.py               process entrypoint -- runs honeypot + console concurrently
  config.py            pydantic-settings, env-driven
  routes/              decoy surface + canary callback + catchall 404
  detection/           signals, scoring, session id, canary token mint/verify
  payloads/            payload template library + selection/rendering
  middleware/          request capture, security headers, body-size cap, WAF
  storage/             sqlite repository + migrations
  console/             operator dashboard (separate app/port)
  templates/           Jinja2 templates for the decoy site
tests/                 pytest suite (routes, signals, scoring, payloads, console, WAF, storage)
data/                  sqlite db (gitignored)
```

## Configuration

Copy `.env.example` to `.env` and fill it in:

| Variable | Purpose |
|---|---|
| `CANARY_BASE_URL` | This service's own reachable base URL. Every canary/callback URL embedded in a payload is built from it — must never point at a third party. Startup fails if it isn't a valid `http(s)` URL. |
| `HMAC_SECRET` | Signs canary tokens and hashes IPs before persisting. Startup **refuses to run** if left at the checked-in placeholder (`change-me-dev-secret`). Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`. |
| `DATABASE_PATH` | Path to the SQLite file (default `data/honeypot.sqlite`). |
| `MAX_BODY_BYTES` | Max accepted request body size, in bytes (default `65536`). |
| `CONSOLE_TOKEN` | HTTP Basic password for the operator console. Leave blank to disable the console entirely. |
| `CONSOLE_PORT` | Port the console listens on (default `8001`). Only relevant if `CONSOLE_TOKEN` is set. |

## Running locally (no Docker)

Requires Python >= 3.11.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# edit .env: set HMAC_SECRET and CONSOLE_TOKEN

python -m app.run
```

The honeypot listens on `:8000`, the operator console (if `CONSOLE_TOKEN` is
set) on `:8001` at `http://localhost:8001/` (Basic auth, username
`operator`, password = `CONSOLE_TOKEN`).

Run the test suite with:

```bash
pytest
```

## Deploying with Docker

1. **Configure environment.** Copy the example env file and fill in real
   values — at minimum a real `HMAC_SECRET`, and `CANARY_BASE_URL` set to
   this deployment's actual reachable address (not `localhost`, for anything
   beyond local testing):

   ```bash
   cp .env.example .env
   python -c "import secrets; print(secrets.token_hex(32))"   # paste into HMAC_SECRET
   ```

   Set `CONSOLE_TOKEN` to a strong password if you want the operator
   console; leave it blank to disable it.

2. **Build and run:**

   ```bash
   docker compose up --build -d
   ```

   This builds the image from the included `Dockerfile` (`python:3.12-slim`,
   runs as a non-root `honeypot` user), reads `.env`, exposes ports `8000`
   (honeypot) and `8001` (console), and bind-mounts `./data` into the
   container so the SQLite database persists across restarts.

3. **Verify it's up:**

   ```bash
   curl -i http://localhost:8000/
   docker compose logs -f honeypot
   ```

   The container logs its `CANARY_BASE_URL` at startup — check this to catch
   a copy-paste mistake before exposing the service.

4. **Reach the operator console** (if enabled) at
   `http://<host>:8001/`, Basic auth `operator` / `CONSOLE_TOKEN`. Keep port
   `8001` off any public-facing load balancer/firewall rule — only the
   honeypot port (`8000`) is meant to be internet-facing.

5. **Stop / update:**

   ```bash
   docker compose down          # stop
   docker compose up --build -d # rebuild after a code change
   ```

Data lives in `./data` on the host (gitignored) via the bind mount, so
`docker compose down` alone does not lose captured sessions.

## Safety invariants

- Payloads only ever reference `{canary_url}` / `{canary_url_b64}`, both
  built exclusively from `CANARY_BASE_URL` — never a hardcoded or
  third-party URL. Enforced by `tests/test_payload_registry.py`.
- The app refuses to start with the default placeholder `HMAC_SECRET` or a
  malformed `CANARY_BASE_URL` (`app/main.py` lifespan checks).
- Sensitive request headers are redacted before being persisted
  (`app/middleware/request_capture.py`).
- The operator console never shares a port with the public honeypot app.

## Author

Built by [Louison Savarese](https://github.com/protocedvill).
