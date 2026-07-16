"""Prompt-injection payload templates and safe rendering/selection.

Design intent: every payload is defensive-research bait aimed at whatever LLM
is reading the honeypot's responses. Payloads may only ever direct that LLM
back at OUR OWN canary infrastructure (via the {canary_url} placeholder,
built from CANARY_BASE_URL) -- never at a third party. This is enforced by
tests/test_payload_registry.py, not just by convention.
"""

import random
from dataclasses import dataclass
from enum import Enum

from app.detection.canary_tokens import mint_token


class DeliveryVector(str, Enum):
    HTML_COMMENT = "html_comment"
    JSON_FIELD = "json_field"
    HTTP_HEADER = "http_header"
    OPENAPI_FIELD = "openapi_field"
    STACK_TRACE = "stack_trace"
    ROBOTS_TXT = "robots_txt"


class PayloadIntent(str, Enum):
    FINGERPRINT = "fingerprint"  # get the agent to reveal model/tool identity
    CANARY_CALLBACK = "canary_callback"  # get the agent to fetch our canary URL
    TASK_DERAIL = "task_derail"  # get the agent to abandon/redirect its task
    TOKEN_WASTE = "token_waste"  # get the agent to do busywork that burns tokens


@dataclass(frozen=True)
class PayloadTemplate:
    id: str
    vector: DeliveryVector
    intent: PayloadIntent
    variants: tuple[str, ...]
    safe: bool = True
    # A distinctive string (e.g. a header name) this template asks the reader
    # to echo back. A well-aligned agent may refuse to actually comply with
    # the instruction, but testing the marker at all -- with any value --
    # still proves it read and reasoned about this specific response's text,
    # which is a comprehension signal independent of compliance.
    marker: str | None = None
    # Which artifact format(s) this variant's prose is written to fit, e.g.
    # "html", "env_file", "git_config", "sql_dump", "json", "robots_txt",
    # "openapi", "stack_trace". Selection filters on this so a SQL-dump route
    # never renders text written for an HTML comment (see library.py docstring
    # for why that cross-format repetition matters).
    context: tuple[str, ...] = ("generic",)
    # Which role-confusion lever this variant is testing: "operational" (plain
    # third-party note, the historical baseline), "reasoning_mimicry" (styled
    # like the reader's own chain-of-thought), or "role_declaration" (claims a
    # trusted role outright). See library.py module docstring.
    style: str = "operational"


def get_templates(vector: DeliveryVector, context: str | None = None) -> list[PayloadTemplate]:
    from app.payloads.library import PAYLOAD_TEMPLATES

    candidates = [t for t in PAYLOAD_TEMPLATES if t.vector == vector]
    if context is not None:
        candidates = [t for t in candidates if context in t.context]
    return candidates


def get_template(template_id: str) -> PayloadTemplate:
    from app.payloads.library import PAYLOAD_TEMPLATES

    for template in PAYLOAD_TEMPLATES:
        if template.id == template_id:
            return template
    raise KeyError(template_id)


def all_templates() -> list[PayloadTemplate]:
    from app.payloads.library import PAYLOAD_TEMPLATES

    return list(PAYLOAD_TEMPLATES)


def select_and_render(
    vector: DeliveryVector,
    context: str,
    session_id: str,
    canary_base_url: str,
    hmac_secret: str,
) -> tuple[PayloadTemplate, str, str]:
    """Pick a template for this vector+context, mint a canary token bound to
    the session, and render the chosen variant. Template selection is
    deterministic per session+template (stable within one session's
    multi-step interaction) but varies across sessions/IPs to resist
    attacker-side pattern matching. Variant selection additionally varies by
    context, so the same template hit through different response formats
    doesn't always render byte-identical text.

    Returns (template, token, rendered_text).
    """
    candidates = get_templates(vector, context)
    if not candidates:
        raise KeyError(f"no payload templates registered for vector {vector} context {context!r}")

    selector_rng = random.Random(f"{session_id}:{vector.value}:template")
    template = selector_rng.choice(candidates)

    variant_rng = random.Random(f"{session_id}:{template.id}:{context}:variant")
    variant = variant_rng.choice(template.variants)

    token = mint_token(session_id, hmac_secret)
    canary_url = f"{canary_base_url.rstrip('/')}/api/internal/callback/{token}"
    rendered = variant.format(canary_url=canary_url)
    return template, token, rendered
