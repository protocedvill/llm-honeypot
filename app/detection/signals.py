"""Individual detection signals.

Each signal is a pure function: SignalContext -> ScoreDelta. Add a new
heuristic by writing a function and decorating it with @register_signal --
scoring.py picks up everything registered here automatically.
"""

import re
import statistics
from dataclasses import dataclass, field

_BOT_UA_PATTERN = re.compile(
    r"(python-requests|curl|wget|scrapy|go-http-client|okhttp|libwww-perl|"
    r"headlesschrome|phantomjs|puppeteer|playwright)",
    re.IGNORECASE,
)
_AI_UA_PATTERN = re.compile(
    r"(langchain|autogen|gptbot|openai|anthropic|crewai|browser-use|"
    r"llama-?index|agent-?gpt)",
    re.IGNORECASE,
)

# Buckets of well-known "sensitive path" markers spanning unrelated tech
# stacks. A dumb brute-force scanner's wordlist is large, generic, and
# typically saturates one stack at a time; an LLM recalling "plausible
# sensitive paths from training" tends to touch a small, curated set that
# spans several unrelated stacks in the same short burst -- observed
# directly in session_transcripts/1.txt (Apache + PHP + .NET + git + API
# docs markers all probed within the same few seconds).
_SENSITIVE_PATH_CATEGORIES: dict[str, tuple[str, ...]] = {
    "apache": (".htaccess", "server-status", "server-info"),
    "php": ("phpinfo", "wp-login", "wp-config", ".php"),
    "dotnet": ("web.config", "global.asax", ".aspx"),
    "git": (".git/",),
    "backup": ("backup.sql", ".bak", "dump.sql", ".sql"),
    "secrets": (".env", "credentials", ".aws/"),
    "api_docs": ("swagger", "openapi", "/docs"),
    "admin_panel": ("phpmyadmin", "adminer", "/admin"),
}


def _categorize_path(path: str) -> str | None:
    lowered = path.lower()
    for category, markers in _SENSITIVE_PATH_CATEGORIES.items():
        if any(marker in lowered for marker in markers):
            return category
    return None


@dataclass
class SignalContext:
    headers: dict[str, str]  # lower-cased header names
    method: str
    path: str
    ip: str
    session_id: str
    ts: float
    prior_event_timestamps: list[float] = field(default_factory=list)
    prior_event_paths: list[str] = field(default_factory=list)
    is_canary_hit: bool = False
    is_comprehension_hit: bool = False
    is_marker_referenced: bool = False
    js_beacon_fired: bool = False
    used_fallback_identity: bool = False


@dataclass
class ScoreDelta:
    bot: float = 0.0
    ai: float = 0.0
    human: float = 0.0
    reason: str = ""


_SIGNALS: list = []


def register_signal(fn):
    _SIGNALS.append(fn)
    return fn


def all_signals() -> list:
    return list(_SIGNALS)


@register_signal
def header_fingerprint(ctx: SignalContext) -> ScoreDelta:
    ua = ctx.headers.get("user-agent", "")
    if not ua:
        return ScoreDelta(bot=1.0, reason="missing-user-agent")
    if _AI_UA_PATTERN.search(ua):
        return ScoreDelta(ai=3.0, reason="ai-framework-ua")
    if _BOT_UA_PATTERN.search(ua):
        return ScoreDelta(bot=2.0, reason="bot-like-ua")
    return ScoreDelta()


@register_signal
def missing_browser_headers(ctx: SignalContext) -> ScoreDelta:
    missing = sum(1 for h in ("accept-language", "accept-encoding") if h not in ctx.headers)
    if not any(h.startswith("sec-fetch-") for h in ctx.headers):
        missing += 1
    if missing >= 2:
        return ScoreDelta(bot=1.5, reason="missing-browser-headers")
    return ScoreDelta()


@register_signal
def json_only_accept(ctx: SignalContext) -> ScoreDelta:
    if ctx.headers.get("accept", "").strip() == "application/json":
        return ScoreDelta(ai=1.0, reason="json-only-accept")
    return ScoreDelta()


@register_signal
def request_timing(ctx: SignalContext) -> ScoreDelta:
    timestamps = ctx.prior_event_timestamps
    if len(timestamps) < 2:
        return ScoreDelta()
    intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
    mean = statistics.fmean(intervals)
    if mean < 0.2:
        return ScoreDelta(bot=2.0, reason="sub-200ms-interval")
    if len(intervals) >= 3 and statistics.pstdev(intervals) < 0.05 and mean < 2.0:
        return ScoreDelta(bot=1.0, reason="highly-regular-interval")
    return ScoreDelta()


@register_signal
def canary_hit_signal(ctx: SignalContext) -> ScoreDelta:
    if ctx.is_canary_hit:
        return ScoreDelta(ai=5.0, reason="canary-url-hit")
    return ScoreDelta()


@register_signal
def comprehension_signal(ctx: SignalContext) -> ScoreDelta:
    if ctx.is_comprehension_hit:
        return ScoreDelta(ai=3.0, reason="comprehension-hit")
    return ScoreDelta()


@register_signal
def js_beacon_signal(ctx: SignalContext) -> ScoreDelta:
    if ctx.js_beacon_fired:
        return ScoreDelta(human=1.0, reason="js-beacon-fired")
    return ScoreDelta()


@register_signal
def cookie_retention_signal(ctx: SignalContext) -> ScoreDelta:
    if ctx.used_fallback_identity:
        return ScoreDelta(bot=1.0, reason="no-cookie-retention")
    return ScoreDelta()


@register_signal
def curated_wordlist_recall_signal(ctx: SignalContext) -> ScoreDelta:
    """Distinct-category breadth within a small recent window, not any
    single path, is the signal: touching >=4 unrelated-stack sensitive-path
    categories in <=30 requests looks like trained-knowledge recall, not a
    brute-force wordlist sweep (which is larger and usually stack-specific)."""
    recent_paths = [*ctx.prior_event_paths, ctx.path]
    categories = {c for c in (_categorize_path(p) for p in recent_paths) if c}
    if len(categories) >= 4 and len(recent_paths) <= 30:
        return ScoreDelta(ai=3.5, reason="curated-multi-stack-recall")
    return ScoreDelta()


@register_signal
def bursty_agentic_timing_signal(ctx: SignalContext) -> ScoreDelta:
    """An agentic tool loop looks distinctly bimodal: long (multi-second)
    gaps while the model reasons between tool calls, punctuated by
    sub-100ms bursts when it runs something like a shell for-loop. Neither
    a human's more uniform browsing cadence nor a constant-rate scanner
    produces both extremes within the same short window -- observed
    directly in session_transcripts/1.txt (think_time_ms alternating
    between tens of thousands of ms and ~20ms)."""
    timestamps = [*ctx.prior_event_timestamps, ctx.ts]
    if len(timestamps) < 4:
        return ScoreDelta()
    intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
    has_burst = any(i < 0.1 for i in intervals)
    has_gap = any(i > 2.0 for i in intervals)
    if has_burst and has_gap:
        return ScoreDelta(ai=2.5, reason="bursty-agentic-timing")
    return ScoreDelta()


@register_signal
def marker_reference_signal(ctx: SignalContext) -> ScoreDelta:
    """A payload can ask an agent to echo a distinctive marker (e.g. a
    header name) without the agent ever complying with the instruction's
    intent -- but testing the marker at all, with any value, still proves
    it read and reasoned about that specific response's text. This doesn't
    require compliance the way the FINGERPRINT intent originally assumed
    (see app/payloads/library.py's module docstring)."""
    if ctx.is_marker_referenced:
        return ScoreDelta(ai=3.0, reason="marker-referenced")
    return ScoreDelta()
