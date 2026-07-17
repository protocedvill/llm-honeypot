import re
import time
from urllib.parse import unquote_plus

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.config import get_settings
from app.payloads.registry import DeliveryVector
from app.routes._shared import inject_payload, templates
from app.storage import repository

# Real regex syntax, not substrings (unlike _SENSITIVE_PATH_CATEGORIES in
# app/detection/signals.py) -- these need to catch attack SYNTAX, not just
# keywords a legitimate decoy path/query might innocently contain. Small,
# high-confidence starting set: broad enough to catch the dominant
# real-world case (scanner/exploit-tool query-string probes) without
# false-positiving on normal decoy traffic.
_ATTACK_PATTERNS: dict[str, tuple[re.Pattern, ...]] = {
    "sqli": (
        re.compile(r"(?i)\bunion\s+select\b"),
        re.compile(r"(?i)'\s*or\s*'?\d*'?\s*=\s*'?\d*"),
        re.compile(r"(?i)\bor\s+1\s*=\s*1\b"),
        re.compile(r"(?i)\bsleep\(\s*\d+\s*\)"),
        re.compile(r"(?i)\bbenchmark\(\s*\d+"),
        re.compile(r"(?i)\bxp_cmdshell\b"),
        re.compile(r";\s*--"),
    ),
    "xss": (
        re.compile(r"(?i)<script[\s>/]"),
        re.compile(r"(?i)on(error|load)\s*="),
        re.compile(r"(?i)javascript:"),
    ),
    "traversal": (
        re.compile(r"\.\./"),
        re.compile(r"(?i)%2e%2e%2f"),
        re.compile(r"(?i)/etc/passwd"),
        re.compile(r"(?i)\\windows\\system32"),
    ),
    "command_injection": (
        re.compile(r"(?i)[;&|]\s*(cat|whoami|wget|curl|nc|bash|sh)\b"),
        re.compile(r"\$\([^)]+\)"),
        re.compile(r"`[^`]+`"),
    ),
    # Checked before "ssti" below: `${jndi:...}` is syntactically a subset
    # of the generic `${...}` ssti pattern, so without its own category and
    # dict-order priority it would get miscategorized as plain ssti instead
    # of labeled as the Log4Shell-style attempt it actually is.
    "log4shell": (
        re.compile(r"(?i)\$\{jndi:"),
    ),
    "ssti": (
        re.compile(r"\{\{.*\}\}"),
        re.compile(r"\$\{.*\}"),
    ),
}

# Never inspect the canary/beacon callback endpoints (app/routes/canary.py) --
# these are the actual detection endpoints, and their HMAC tokens are opaque
# hex/base64 that could coincidentally brush a pattern. Blocking them would
# silently break canary/beacon confirmation.
_EXEMPT_PREFIX = "/api/internal/"


def _categorize_attack(path: str, query: str) -> str | None:
    # request.url.query is the raw, still percent-encoded query string --
    # decode it first, or every pattern above silently never matches
    # (e.g. "../" arrives as "..%2F", "'" as "%27").
    decoded_query = unquote_plus(query)
    haystack = f"{path}?{decoded_query}" if decoded_query else path
    for category, patterns in _ATTACK_PATTERNS.items():
        if any(p.search(haystack) for p in patterns):
            return category
    return None


def _waf_enabled() -> bool:
    override = repository.get_config("waf_enabled")
    if override is None:
        return get_settings().waf_enabled
    return override == "on"


class WafMiddleware(BaseHTTPMiddleware):
    """Simulated signature-based WAF: inspects path + query string (never the
    body -- see app/middleware/security_headers.py's BodySizeLimitMiddleware
    docstring for why a BaseHTTPMiddleware reading the request body is
    unsafe) against a small set of SQLi/XSS/traversal/command-injection/SSTI
    patterns, and short-circuits with a fake vendor block page on a match.

    Must be added to the app BEFORE RequestCaptureMiddleware (see
    app/main.py) so a block response still flows back out through it --
    otherwise a block would never get logged or scored."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path.startswith(_EXEMPT_PREFIX) or not _waf_enabled():
            request.state.waf_triggered = False
            return await call_next(request)

        category = _categorize_attack(request.url.path, request.url.query)
        if category is None:
            request.state.waf_triggered = False
            return await call_next(request)

        request.state.waf_triggered = True
        payload_text = inject_payload(
            DeliveryVector.HTML_COMMENT, "html", request, request.url.path
        )
        return templates.TemplateResponse(
            request,
            "waf_block.html",
            {
                "payload_text": payload_text,
                "block_id": f"waf-{category}-{int(time.time() * 1000)}",
            },
            status_code=403,
        )
